// Package projectconfig reads the framework-independent portless.json format
// and resolves stable route names from explicit project context.
package projectconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/euforicio/portless/internal/client"
	"golang.org/x/sys/unix"
)

const (
	FileName       = "portless.json"
	maxConfigBytes = 1 << 20
	maxArguments   = 256
	maxEnvironment = 256
	maxValueBytes  = 32 << 10
)

// Config is a validated, direct-execution project configuration. Command is
// an argv vector; it is never parsed or executed as a shell string.
type Config struct {
	Name        string
	Command     []string
	AppPort     uint16
	Proxy       bool
	Environment map[string]string
}

type rawConfig struct {
	Name        string            `json:"name"`
	Command     []string          `json:"command"`
	AppPort     uint16            `json:"appPort"`
	Proxy       *bool             `json:"proxy"`
	Environment map[string]string `json:"env,omitempty"`
}

// Load reads and strictly validates one portless.json file. Proxy defaults to
// true when omitted; appPort zero asks the runner to allocate a free port.
func Load(path string) (Config, error) {
	if !filepath.IsAbs(path) {
		return Config{}, errors.New("project config path must be absolute")
	}
	file, err := openConfig(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read project config: %w", err)
	}
	if len(data) > maxConfigBytes {
		return Config{}, errors.New("project config exceeds size limit")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return Config{}, fmt.Errorf("decode project config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var raw rawConfig
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("decode project config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("project config contains trailing data")
	}

	proxy := true
	if raw.Proxy != nil {
		proxy = *raw.Proxy
	}
	config := Config{
		Command:     append([]string(nil), raw.Command...),
		AppPort:     raw.AppPort,
		Proxy:       proxy,
		Environment: cloneEnvironment(raw.Environment),
	}
	if raw.Name != "" {
		config.Name, err = client.NormalizeName(raw.Name)
		if err != nil {
			return Config{}, fmt.Errorf("invalid project name: %w", err)
		}
	}
	if err := Validate(config); err != nil {
		return Config{}, err
	}
	return config, nil
}

// Validate validates a Config assembled without Load.
func Validate(config Config) error {
	if len(config.Command) == 0 {
		return errors.New("project command must contain an executable")
	}
	if len(config.Command) > maxArguments {
		return fmt.Errorf("project command exceeds %d arguments", maxArguments)
	}
	for index, argument := range config.Command {
		if strings.IndexByte(argument, 0) >= 0 || len(argument) > maxValueBytes {
			return fmt.Errorf("project command argument %d is invalid", index)
		}
		if index == 0 && argument == "" {
			return errors.New("project command executable must not be empty")
		}
	}
	if !config.Proxy && config.AppPort != 0 {
		return errors.New("appPort requires proxy to be enabled")
	}
	if len(config.Environment) > maxEnvironment {
		return fmt.Errorf("project environment exceeds %d entries", maxEnvironment)
	}
	for key, value := range config.Environment {
		if err := ValidateEnvironmentKey(key); err != nil {
			return err
		}
		if strings.IndexByte(value, 0) >= 0 || len(value) > maxValueBytes {
			return fmt.Errorf("environment value for %q is invalid", key)
		}
	}
	return nil
}

// ValidateEnvironmentKey accepts portable process-environment identifiers.
func ValidateEnvironmentKey(key string) error {
	if len(key) == 0 || len(key) > 255 {
		return errors.New("environment key must be between 1 and 255 characters")
	}
	for index, character := range key {
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || character == '_' || (index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return fmt.Errorf("invalid environment key %q", key)
	}
	return nil
}

// Find searches start and its parents for a real portless.json file. Symlinks
// are rejected rather than followed.
func Find(start string) (string, bool, error) {
	directory, err := realDirectory(start)
	if err != nil {
		return "", false, err
	}
	for {
		candidate := filepath.Join(directory, FileName)
		info, statErr := os.Lstat(candidate)
		switch {
		case statErr == nil:
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return "", false, errors.New("portless.json must be a regular file, not a symlink")
			}
			return candidate, true, nil
		case !errors.Is(statErr, os.ErrNotExist):
			return "", false, statErr
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", false, nil
		}
		directory = parent
	}
}

// ResolveName applies the only supported name precedence: explicit flag,
// config, git worktree/root directory, then current directory.
func ResolveName(explicit, configured, workingDirectory string) (string, error) {
	if explicit != "" {
		name, err := client.NormalizeName(explicit)
		if err != nil {
			return "", fmt.Errorf("invalid explicit name: %w", err)
		}
		return name, nil
	}
	if configured != "" {
		name, err := client.NormalizeName(configured)
		if err != nil {
			return "", fmt.Errorf("invalid configured name: %w", err)
		}
		return name, nil
	}
	directory, err := realDirectory(workingDirectory)
	if err != nil {
		return "", err
	}
	if root, ok := gitRoot(directory); ok {
		return inferredDirectoryName(root)
	}
	return inferredDirectoryName(directory)
}

func inferredDirectoryName(directory string) (string, error) {
	base := strings.ToLower(filepath.Base(directory))
	var name strings.Builder
	lastHyphen := false
	for _, character := range base {
		valid := (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')
		if valid {
			name.WriteRune(character)
			lastHyphen = false
			continue
		}
		if name.Len() > 0 && !lastHyphen {
			name.WriteByte('-')
			lastHyphen = true
		}
	}
	value := strings.Trim(name.String(), "-")
	if value == "" {
		return "", fmt.Errorf("cannot infer a route name from directory %q", directory)
	}
	if len(value) > 63 {
		return "", fmt.Errorf("directory name %q is too long; supply an explicit Portless name", filepath.Base(directory))
	}
	return client.NormalizeName(value)
}

func openConfig(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errors.New("project config must be a regular file, not a symlink")
		}
		return nil, fmt.Errorf("open project config: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("project config must be a regular file, not a symlink")
	}
	return file, nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	allowedRootKeys := map[string]bool{"name": true, "command": true, "appPort": true, "proxy": true, "env": true}
	var readValue func(int) error
	readValue = func(depth int) error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("object key must be a string")
				}
				if seen[key] {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				if depth == 0 && !allowedRootKeys[key] {
					return fmt.Errorf("unknown project config field %q", key)
				}
				seen[key] = true
				if err := readValue(depth + 1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := readValue(depth + 1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	return readValue(0)
}

func gitRoot(directory string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "git", "-C", directory, "rev-parse", "--show-toplevel")
	output, err := command.Output()
	if err != nil || len(output) > 16<<10 {
		return "", false
	}
	root := strings.TrimSpace(string(output))
	if !filepath.IsAbs(root) {
		return "", false
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", false
	}
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	info, err := os.Stat(root)
	return root, err == nil && info.IsDir()
}

func realDirectory(path string) (string, error) {
	if path == "" {
		var err error
		path, err = os.Getwd()
		if err != nil {
			return "", err
		}
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve working directory: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("working directory must be a directory")
	}
	return resolved, nil
}

func cloneEnvironment(environment map[string]string) map[string]string {
	if environment == nil {
		return nil
	}
	clone := make(map[string]string, len(environment))
	for key, value := range environment {
		clone[key] = value
	}
	return clone
}
