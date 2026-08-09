package service

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

const DefaultLabel = "com.euforicio.portless"

// Config defines the root LaunchDaemon and all paths it is allowed to use.
type Config struct {
	Label               string
	Executable          string
	PlistPath           string
	StateDir            string
	RuntimeDir          string
	ManagementSocket    string
	ManagementGroup     string
	ManagementGID       int
	ContainerExecutable string
	StdoutPath          string
	StderrPath          string
	HTTPListeners       []string
	HTTPSListeners      []string
	UID                 int
	GID                 int
}

// DefaultConfig returns the fixed production layout. The management group is
// explicit so installers can choose a dedicated local group when desired.
func DefaultConfig(managementGroup string) (Config, error) {
	group, err := user.LookupGroup(managementGroup)
	if err != nil {
		return Config{}, fmt.Errorf("look up management group %q: %w", managementGroup, err)
	}
	managementGID, err := strconv.Atoi(group.Gid)
	if err != nil || managementGID < 0 {
		return Config{}, fmt.Errorf("management group %q has invalid GID %q", managementGroup, group.Gid)
	}
	return Config{
		Label:               DefaultLabel,
		Executable:          "/usr/local/libexec/portless",
		PlistPath:           "/Library/LaunchDaemons/" + DefaultLabel + ".plist",
		StateDir:            "/Library/Application Support/Portless",
		RuntimeDir:          "/var/run/portless",
		ManagementSocket:    "/var/run/portless/management.sock",
		ManagementGroup:     managementGroup,
		ManagementGID:       managementGID,
		ContainerExecutable: defaultContainerExecutable(),
		StdoutPath:          "/Library/Logs/Portless/portless.log",
		StderrPath:          "/Library/Logs/Portless/portless.error.log",
		HTTPListeners:       []string{"127.0.0.1:80", "[::1]:80"},
		HTTPSListeners:      []string{"127.0.0.1:443", "[::1]:443"},
		UID:                 0,
		GID:                 0,
	}, nil
}

func (c Config) validate() error {
	if c.Label == "" || strings.ContainsAny(c.Label, "/\x00") {
		return errors.New("invalid launchd label")
	}
	for name, path := range map[string]string{
		"executable": c.Executable, "plist": c.PlistPath, "state directory": c.StateDir,
		"runtime directory": c.RuntimeDir, "management socket": c.ManagementSocket,
		"stdout": c.StdoutPath, "stderr": c.StderrPath,
		"container executable": c.ContainerExecutable,
	} {
		if !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
			return fmt.Errorf("%s path must be absolute", name)
		}
	}
	if filepath.Dir(c.ManagementSocket) != filepath.Clean(c.RuntimeDir) {
		return errors.New("management socket must be directly inside the runtime directory")
	}
	if c.ManagementGroup == "" || strings.ContainsAny(c.ManagementGroup, "/:\x00") {
		return errors.New("management group is required")
	}
	group, err := user.LookupGroup(c.ManagementGroup)
	if err != nil {
		return fmt.Errorf("look up management group %q: %w", c.ManagementGroup, err)
	}
	groupGID, err := strconv.Atoi(group.Gid)
	if err != nil || groupGID != c.ManagementGID {
		return fmt.Errorf("management group %q does not match GID %d", c.ManagementGroup, c.ManagementGID)
	}
	if c.UID < 0 || c.GID < 0 || c.ManagementGID < 0 {
		return errors.New("UID and GID must be non-negative")
	}
	if len(c.HTTPListeners) == 0 || len(c.HTTPSListeners) == 0 {
		return errors.New("HTTP and HTTPS loopback listeners are required")
	}
	for _, listener := range c.HTTPListeners {
		if !isLoopbackListener(listener, 80) {
			return fmt.Errorf("HTTP listener %q is not explicit loopback port 80", listener)
		}
	}
	for _, listener := range c.HTTPSListeners {
		if !isLoopbackListener(listener, 443) {
			return fmt.Errorf("HTTPS listener %q is not explicit loopback port 443", listener)
		}
	}
	return nil
}

// Plist renders a deterministic root LaunchDaemon property list.
func (c Config) Plist() ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	arguments := []string{
		c.Executable, "daemon",
		"--state-dir", c.StateDir,
		"--management-socket", c.ManagementSocket,
		"--management-group", c.ManagementGroup,
		"--container-cli", c.ContainerExecutable,
	}
	for _, address := range c.HTTPListeners {
		arguments = append(arguments, "--http-listen", address)
	}
	for _, address := range c.HTTPSListeners {
		arguments = append(arguments, "--https-listen", address)
	}

	var out bytes.Buffer
	out.WriteString(xml.Header)
	out.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	out.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	writeString(&out, "Label", c.Label)
	writeString(&out, "Program", c.Executable)
	writeArray(&out, "ProgramArguments", arguments)
	writeString(&out, "UserName", "root")
	writeString(&out, "GroupName", "wheel")
	writeString(&out, "WorkingDirectory", c.StateDir)
	writeString(&out, "StandardOutPath", c.StdoutPath)
	writeString(&out, "StandardErrorPath", c.StderrPath)
	writeString(&out, "Umask", "0077")
	writeBool(&out, "KeepAlive", true)
	writeString(&out, "ProcessType", "Interactive")
	writeInteger(&out, "ThrottleInterval", 5)
	writeInteger(&out, "ExitTimeOut", 30)
	out.WriteString("</dict>\n</plist>\n")
	return out.Bytes(), nil
}

func defaultContainerExecutable() string {
	for _, candidate := range []string{"/opt/homebrew/bin/container", "/usr/local/bin/container", "/usr/bin/container"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate
		}
	}
	return "/usr/local/bin/container"
}

func isLoopbackListener(address string, wantedPort uint64) bool {
	colon := strings.LastIndexByte(address, ':')
	if colon <= 0 {
		return false
	}
	host, port := address[:colon], address[colon+1:]
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort != wantedPort {
		return false
	}
	return host == "127.0.0.1" || host == "[::1]"
}

func writeKey(out *bytes.Buffer, key string) {
	out.WriteString("  <key>")
	xml.EscapeText(out, []byte(key))
	out.WriteString("</key>\n")
}

func writeString(out *bytes.Buffer, key, value string) {
	writeKey(out, key)
	out.WriteString("  <string>")
	xml.EscapeText(out, []byte(value))
	out.WriteString("</string>\n")
}

func writeBool(out *bytes.Buffer, key string, value bool) {
	writeKey(out, key)
	if value {
		out.WriteString("  <true/>\n")
	} else {
		out.WriteString("  <false/>\n")
	}
}

func writeInteger(out *bytes.Buffer, key string, value int) {
	writeKey(out, key)
	fmt.Fprintf(out, "  <integer>%d</integer>\n", value)
}

func writeArray(out *bytes.Buffer, key string, values []string) {
	writeKey(out, key)
	out.WriteString("  <array>\n")
	for _, value := range values {
		out.WriteString("    <string>")
		xml.EscapeText(out, []byte(value))
		out.WriteString("</string>\n")
	}
	out.WriteString("  </array>\n")
}
