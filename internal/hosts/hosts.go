// Package hosts manages an isolated Portless block in a hosts file.
//
// The package never invokes sudo. DefaultConfig describes the privileged
// system paths, while callers choose when and under which identity to apply a
// previously inspected Plan.
package hosts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

const (
	BeginMarker = "# BEGIN PORTLESS MANAGED HOSTS"
	EndMarker   = "# END PORTLESS MANAGED HOSTS"

	defaultHostsPath = "/etc/hosts"
	defaultLockPath  = "/var/run/portless/hosts.lock"
	maxHostsBytes    = 1 << 20
	maxNames         = 4096
)

var (
	ErrInvalidName       = errors.New("invalid local host name")
	ErrMalformedBlock    = errors.New("malformed Portless hosts block")
	ErrPrivilegeRequired = errors.New("hosts mutation requires the configured owner or root")
	ErrStalePlan         = errors.New("hosts file changed after the plan was created")
)

// Action identifies the requested hosts-file mutation.
type Action string

const (
	ActionSynchronize Action = "synchronize"
	ActionClean       Action = "clean"
)

// Config describes the exact file metadata and lock used for a mutation.
// Production callers should use DefaultConfig. Tests and controlled tools may
// select other absolute paths and ownership without touching /etc/hosts.
type Config struct {
	Path     string
	LockPath string
	UID      int
	GID      int
	Mode     fs.FileMode
}

// DefaultConfig returns the macOS system hosts-file configuration. Applying it
// requires an already-privileged caller; no API in this package invokes sudo.
func DefaultConfig() Config {
	return Config{
		Path:     defaultHostsPath,
		LockPath: defaultLockPath,
		UID:      0,
		GID:      0,
		Mode:     0o644,
	}
}

// FileState is read-only metadata returned by Preflight.
type FileState struct {
	Path   string
	Exists bool
	Mode   fs.FileMode
	UID    int
	GID    int
	Size   int64
}

// Preflight reports whether the configured artifacts are structurally safe.
// A missing lock file is valid because Apply creates it with mode 0600.
type Preflight struct {
	Hosts          FileState
	Lock           FileState
	NeedsPrivilege bool
}

// Plan is an auditable, read-only description of one exact mutation. Apply
// rejects the plan if the source file has changed since planning.
type Plan struct {
	Action       Action
	Path         string
	LockPath     string
	Names        []string
	BeforeSHA256 string
	AfterSHA256  string
	BeforeBytes  int
	AfterBytes   int
	UID          int
	GID          int
	Mode         fs.FileMode
	Changed      bool

	config  Config
	desired []byte
}

// DesiredContent returns a copy of the exact content represented by the plan.
func (p Plan) DesiredContent() []byte {
	return bytes.Clone(p.desired)
}

// Result reports an applied or no-op mutation.
type Result struct {
	Plan    Plan
	Changed bool
}

// Check performs a read-only security preflight. It never creates the lock or
// writes the hosts file.
func (c Config) Check() (Preflight, error) {
	if err := c.validate(); err != nil {
		return Preflight{}, err
	}
	if err := c.checkParents(); err != nil {
		return Preflight{}, err
	}
	hostsState, _, err := inspectRegular(c.Path, c.Mode, c.UID, c.GID, false)
	if err != nil {
		return Preflight{}, err
	}
	lockState, _, err := inspectRegular(c.LockPath, 0o600, c.UID, c.GID, true)
	if err != nil {
		return Preflight{}, err
	}
	return Preflight{
		Hosts:          hostsState,
		Lock:           lockState,
		NeedsPrivilege: os.Geteuid() != 0 && os.Geteuid() != c.UID,
	}, nil
}

// SynchronizePlan reads and validates the hosts file, then returns a plan that
// replaces the managed block with the supplied registered names.
func (c Config) SynchronizePlan(names []string) (Plan, error) {
	return c.plan(ActionSynchronize, names)
}

// CleanPlan reads and validates the hosts file, then returns a plan that
// removes only the managed block.
func (c Config) CleanPlan() (Plan, error) {
	return c.plan(ActionClean, nil)
}

// Apply applies a previously inspected plan under the configured exclusive
// lock. It fails closed if the file changed after the plan was created.
func (c Config) Apply(plan Plan) (Result, error) {
	if err := c.validate(); err != nil {
		return Result{}, err
	}
	if err := c.checkParents(); err != nil {
		return Result{}, err
	}
	if err := validatePlan(c, plan); err != nil {
		return Result{}, err
	}
	if err := c.requirePrivilege(); err != nil {
		return Result{}, err
	}
	lock, err := c.lock()
	if err != nil {
		return Result{}, err
	}
	defer lock.Close()

	current, identity, err := readSecure(c)
	if err != nil {
		return Result{}, err
	}
	if len(current) != plan.BeforeBytes || digest(current) != plan.BeforeSHA256 {
		return Result{}, ErrStalePlan
	}
	if err := verifyPlanContent(plan, current); err != nil {
		return Result{}, err
	}
	if !plan.Changed {
		return Result{Plan: clonePlan(plan)}, nil
	}
	if err := writeAtomic(c, plan.desired, identity, plan.BeforeSHA256); err != nil {
		return Result{}, err
	}
	return Result{Plan: clonePlan(plan), Changed: true}, nil
}

// Synchronize atomically reconciles the managed block under an exclusive lock.
func (c Config) Synchronize(names []string) (Result, error) {
	return c.mutate(ActionSynchronize, names)
}

// Clean atomically removes only the managed block under an exclusive lock.
func (c Config) Clean() (Result, error) {
	return c.mutate(ActionClean, nil)
}

// Render returns content with exactly one deterministic managed block. Names
// are normalized, deduplicated, sorted, and limited to exact .localhost names.
func Render(current []byte, names []string) ([]byte, error) {
	normalized, err := normalizeNames(names)
	if err != nil {
		return nil, err
	}
	return renderNormalized(current, normalized)
}

// CleanContent removes only the Portless managed block.
func CleanContent(current []byte) ([]byte, error) {
	return renderNormalized(current, nil)
}

// NormalizeName validates and canonicalizes one exact .localhost name.
func NormalizeName(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, " \t\r\n/?#@\\:") {
		return "", ErrInvalidName
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if len(name) > 253 || !strings.HasSuffix(name, ".localhost") || name == "localhost" {
		return "", ErrInvalidName
	}
	for label := range strings.SplitSeq(name, ".") {
		if !validLabel(label) {
			return "", ErrInvalidName
		}
	}
	return name, nil
}

func (c Config) plan(action Action, names []string) (Plan, error) {
	if err := c.validate(); err != nil {
		return Plan{}, err
	}
	if err := c.checkParents(); err != nil {
		return Plan{}, err
	}
	current, _, err := readSecure(c)
	if err != nil {
		return Plan{}, err
	}
	return makePlan(c, action, current, names)
}

func (c Config) mutate(action Action, names []string) (Result, error) {
	if err := c.validate(); err != nil {
		return Result{}, err
	}
	if err := c.checkParents(); err != nil {
		return Result{}, err
	}
	if err := c.requirePrivilege(); err != nil {
		return Result{}, err
	}
	lock, err := c.lock()
	if err != nil {
		return Result{}, err
	}
	defer lock.Close()

	current, identity, err := readSecure(c)
	if err != nil {
		return Result{}, err
	}
	plan, err := makePlan(c, action, current, names)
	if err != nil {
		return Result{}, err
	}
	if !plan.Changed {
		return Result{Plan: clonePlan(plan)}, nil
	}
	if err := writeAtomic(c, plan.desired, identity, plan.BeforeSHA256); err != nil {
		return Result{}, err
	}
	return Result{Plan: clonePlan(plan), Changed: true}, nil
}

func makePlan(c Config, action Action, current []byte, names []string) (Plan, error) {
	var (
		desired    []byte
		normalized []string
		err        error
	)
	switch action {
	case ActionSynchronize:
		normalized, err = normalizeNames(names)
		if err == nil {
			desired, err = renderNormalized(current, normalized)
		}
	case ActionClean:
		desired, err = renderNormalized(current, nil)
	default:
		return Plan{}, fmt.Errorf("unknown hosts action %q", action)
	}
	if err != nil {
		return Plan{}, err
	}
	return Plan{
		Action:       action,
		Path:         c.Path,
		LockPath:     c.LockPath,
		Names:        slices.Clone(normalized),
		BeforeSHA256: digest(current),
		AfterSHA256:  digest(desired),
		BeforeBytes:  len(current),
		AfterBytes:   len(desired),
		UID:          c.UID,
		GID:          c.GID,
		Mode:         c.Mode,
		Changed:      !bytes.Equal(current, desired),
		config:       c,
		desired:      bytes.Clone(desired),
	}, nil
}

func validatePlan(c Config, plan Plan) error {
	if plan.config != c || plan.Path != c.Path || plan.LockPath != c.LockPath ||
		plan.UID != c.UID || plan.GID != c.GID || plan.Mode != c.Mode {
		return errors.New("hosts plan does not match configuration")
	}
	if plan.Action != ActionSynchronize && plan.Action != ActionClean {
		return errors.New("hosts plan has an invalid action")
	}
	if plan.BeforeBytes < 0 || digest(plan.desired) != plan.AfterSHA256 || len(plan.desired) != plan.AfterBytes ||
		plan.Changed != (plan.BeforeSHA256 != plan.AfterSHA256) {
		return errors.New("hosts plan content is invalid")
	}
	return nil
}

func verifyPlanContent(plan Plan, current []byte) error {
	var (
		expected []byte
		names    []string
		err      error
	)
	if plan.Action == ActionSynchronize {
		names, err = normalizeNames(plan.Names)
		if err == nil && !slices.Equal(names, plan.Names) {
			err = errors.New("hosts plan names are not canonical")
		}
		if err == nil {
			expected, err = renderNormalized(current, names)
		}
	} else {
		if len(plan.Names) != 0 {
			err = errors.New("clean plan contains host names")
		} else {
			expected, err = renderNormalized(current, nil)
		}
	}
	if err != nil || !bytes.Equal(expected, plan.desired) {
		return errors.New("hosts plan content does not match its action")
	}
	return nil
}

func clonePlan(plan Plan) Plan {
	plan.Names = slices.Clone(plan.Names)
	plan.desired = bytes.Clone(plan.desired)
	return plan
}

func renderNormalized(current []byte, names []string) ([]byte, error) {
	if len(current) > maxHostsBytes || bytes.IndexByte(current, 0) >= 0 {
		return nil, errors.New("hosts file is invalid or exceeds the size limit")
	}
	start, end, found, err := managedSpan(current)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		if !found {
			return bytes.Clone(current), nil
		}
		result := make([]byte, 0, len(current)-(end-start))
		result = append(result, current[:start]...)
		result = append(result, current[end:]...)
		return result, nil
	}

	block := renderBlock(names)
	if found {
		result := make([]byte, 0, len(current)-(end-start)+len(block))
		result = append(result, current[:start]...)
		result = append(result, block...)
		result = append(result, current[end:]...)
		if len(result) > maxHostsBytes {
			return nil, errors.New("rendered hosts file exceeds the size limit")
		}
		return result, nil
	}
	result := bytes.Clone(current)
	if len(result) != 0 && result[len(result)-1] != '\n' {
		result = append(result, '\n')
	}
	result = append(result, block...)
	if len(result) > maxHostsBytes {
		return nil, errors.New("rendered hosts file exceeds the size limit")
	}
	return result, nil
}

func managedSpan(content []byte) (start, end int, found bool, err error) {
	inBlock := false
	for offset := 0; offset < len(content); {
		lineEnd := bytes.IndexByte(content[offset:], '\n')
		next := len(content)
		if lineEnd >= 0 {
			lineEnd += offset
			next = lineEnd + 1
		} else {
			lineEnd = len(content)
		}
		lineBytes := content[offset:lineEnd]
		if len(lineBytes) != 0 && lineBytes[len(lineBytes)-1] == '\r' {
			lineBytes = lineBytes[:len(lineBytes)-1]
		}
		line := string(lineBytes)
		switch line {
		case BeginMarker:
			if inBlock || found {
				return 0, 0, false, ErrMalformedBlock
			}
			inBlock = true
			found = true
			start = offset
		case EndMarker:
			if !inBlock {
				return 0, 0, false, ErrMalformedBlock
			}
			inBlock = false
			end = next
		}
		offset = next
	}
	if inBlock {
		return 0, 0, false, ErrMalformedBlock
	}
	return start, end, found, nil
}

func renderBlock(names []string) []byte {
	var block strings.Builder
	block.WriteString(BeginMarker)
	block.WriteByte('\n')
	block.WriteString("# Generated by portless; use the portless hosts operation to change this block.\n")
	for _, name := range names {
		fmt.Fprintf(&block, "127.0.0.1\t%s\n", name)
		fmt.Fprintf(&block, "::1\t%s\n", name)
	}
	block.WriteString(EndMarker)
	block.WriteByte('\n')
	return []byte(block.String())
}

func normalizeNames(names []string) ([]string, error) {
	if len(names) > maxNames {
		return nil, fmt.Errorf("too many local host names: maximum is %d", maxNames)
	}
	unique := make(map[string]struct{}, len(names))
	for _, name := range names {
		normalized, err := NormalizeName(name)
		if err != nil {
			return nil, fmt.Errorf("%w: %q", ErrInvalidName, name)
		}
		unique[normalized] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for name := range unique {
		result = append(result, name)
	}
	slices.Sort(result)
	return result, nil
}

func validLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, character := range label {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func (c Config) validate() error {
	if !validAbsolutePath(c.Path) || !validAbsolutePath(c.LockPath) {
		return errors.New("hosts and lock paths must be clean absolute paths")
	}
	if c.Path == c.LockPath {
		return errors.New("hosts and lock paths must differ")
	}
	if c.UID < 0 || c.GID < 0 {
		return errors.New("hosts ownership must be non-negative")
	}
	if c.Mode != c.Mode.Perm() || c.Mode&0o022 != 0 || c.Mode&0o400 == 0 {
		return fmt.Errorf("unsafe hosts mode %04o", c.Mode)
	}
	return nil
}

func validAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func (c Config) requirePrivilege() error {
	if effectiveUID := os.Geteuid(); effectiveUID != 0 && effectiveUID != c.UID {
		return ErrPrivilegeRequired
	}
	return nil
}

func (c Config) checkParents() error {
	if err := inspectSafeParent(c.Path, c.UID); err != nil {
		return err
	}
	return inspectSafeParent(c.LockPath, c.UID)
}

func inspectSafeParent(path string, uid int) error {
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return fmt.Errorf("inspect parent of %s: %w", path, err)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("parent of %s is not a real directory", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("parent of %s is group or world writable", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect ownership of parent for %s", path)
	}
	if int(stat.Uid) != uid {
		return fmt.Errorf("parent of %s is owned by UID %d; want %d", path, stat.Uid, uid)
	}
	return nil
}

type fileIdentity struct {
	device uint64
	inode  uint64
}

func inspectRegular(path string, mode fs.FileMode, uid, gid int, missingOK bool) (FileState, fileIdentity, error) {
	state := FileState{Path: path}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && missingOK {
		return state, fileIdentity{}, nil
	}
	if err != nil {
		return state, fileIdentity{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return state, fileIdentity{}, fmt.Errorf("%s is not a real regular file", path)
	}
	if info.Mode().Perm() != mode {
		return state, fileIdentity{}, fmt.Errorf("%s has unsafe mode %04o; want %04o", path, info.Mode().Perm(), mode)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return state, fileIdentity{}, fmt.Errorf("cannot inspect ownership of %s", path)
	}
	if int(stat.Uid) != uid || int(stat.Gid) != gid {
		return state, fileIdentity{}, fmt.Errorf("%s is owned by %d:%d; want %d:%d", path, stat.Uid, stat.Gid, uid, gid)
	}
	state.Exists = true
	state.Mode = info.Mode().Perm()
	state.UID = int(stat.Uid)
	state.GID = int(stat.Gid)
	state.Size = info.Size()
	return state, fileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func readSecure(c Config) ([]byte, fileIdentity, error) {
	_, before, err := inspectRegular(c.Path, c.Mode, c.UID, c.GID, false)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	fd, err := syscall.Open(c.Path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	file := os.NewFile(uintptr(fd), c.Path)
	defer file.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return nil, fileIdentity{}, err
	}
	after := fileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}
	if before != after || stat.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		fs.FileMode(stat.Mode).Perm() != c.Mode || int(stat.Uid) != c.UID || int(stat.Gid) != c.GID {
		return nil, fileIdentity{}, errors.New("hosts file changed during secure open")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxHostsBytes+1))
	if err != nil {
		return nil, fileIdentity{}, err
	}
	if len(data) > maxHostsBytes {
		return nil, fileIdentity{}, errors.New("hosts file exceeds the size limit")
	}
	return data, after, nil
}

func (c Config) lock() (*os.File, error) {
	var (
		state    FileState
		expected fileIdentity
		fd       int
		err      error
	)
	fd = -1
	for attempt := 0; attempt < 4; attempt++ {
		state, expected, err = inspectRegular(c.LockPath, 0o600, c.UID, c.GID, true)
		if err != nil {
			return nil, err
		}
		flags := syscall.O_RDWR | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
		if !state.Exists {
			flags |= syscall.O_CREAT | syscall.O_EXCL
		}
		fd, err = syscall.Open(c.LockPath, flags, 0o600)
		if err == syscall.EEXIST && !state.Exists {
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
	if fd < 0 {
		return nil, errors.New("hosts lock changed repeatedly during secure open")
	}
	file := os.NewFile(uintptr(fd), c.LockPath)
	closeOnError := func(err error) (*os.File, error) {
		file.Close()
		return nil, err
	}
	if !state.Exists {
		if err := syscall.Fchown(fd, c.UID, c.GID); err != nil {
			return closeOnError(err)
		}
		if err := syscall.Fchmod(fd, 0o600); err != nil {
			return closeOnError(err)
		}
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return closeOnError(err)
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || fs.FileMode(stat.Mode).Perm() != 0o600 ||
		int(stat.Uid) != c.UID || int(stat.Gid) != c.GID {
		return closeOnError(errors.New("hosts lock has unsafe metadata"))
	}
	opened := fileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}
	if state.Exists && opened != expected {
		return closeOnError(errors.New("hosts lock changed during secure open"))
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return closeOnError(err)
	}
	info, err := os.Lstat(c.LockPath)
	if err != nil {
		return closeOnError(err)
	}
	lstat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(lstat.Dev) != opened.device || uint64(lstat.Ino) != opened.inode {
		return closeOnError(errors.New("hosts lock changed during secure open"))
	}
	return file, nil
}

func writeAtomic(c Config, desired []byte, expected fileIdentity, expectedDigest string) error {
	_, currentIdentity, err := inspectRegular(c.Path, c.Mode, c.UID, c.GID, false)
	if err != nil {
		return err
	}
	if currentIdentity != expected {
		return ErrStalePlan
	}
	temporary, err := os.CreateTemp(filepath.Dir(c.Path), ".portless-hosts-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	fail := func(err error) error {
		temporary.Close()
		return err
	}
	if err := temporary.Chown(c.UID, c.GID); err != nil {
		return fail(err)
	}
	if err := temporary.Chmod(c.Mode); err != nil {
		return fail(err)
	}
	if _, err := temporary.Write(desired); err != nil {
		return fail(err)
	}
	if err := temporary.Sync(); err != nil {
		return fail(err)
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	latest, finalIdentity, err := readSecure(c)
	if err != nil {
		return err
	}
	if finalIdentity != expected || digest(latest) != expectedDigest {
		return ErrStalePlan
	}
	if err := os.Rename(temporaryPath, c.Path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(c.Path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
