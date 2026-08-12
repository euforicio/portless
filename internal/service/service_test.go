package service

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/euforicio/portless/internal/profile"
)

func TestLaunchDaemonPlistPassesNativeValidation(t *testing.T) {
	config := temporaryConfig(t)
	plist, err := config.Plist()
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"<string>root</string>",
		"<string>wheel</string>",
		"<string>0077</string>",
		"<string>127.0.0.1:80</string>",
		"<string>[::1]:443</string>",
	} {
		if !bytes.Contains(plist, []byte(required)) {
			t.Errorf("plist is missing %q", required)
		}
	}
	containerFlag := []byte("<string>--container-cli</string>")
	if config.ContainerExecutable == "" {
		if bytes.Contains(plist, containerFlag) {
			t.Fatal("plist configures an unavailable optional container executable")
		}
	} else {
		for _, required := range []string{string(containerFlag), "<string>" + config.ContainerExecutable + "</string>"} {
			if !bytes.Contains(plist, []byte(required)) {
				t.Errorf("plist is missing %q", required)
			}
		}
	}
	if bytes.Contains(plist, []byte("RunAtLoad")) {
		t.Fatal("RunAtLoad is redundant with KeepAlive")
	}

	if runtime.GOOS != "darwin" {
		t.Skip("plutil validation requires macOS")
	}
	path := filepath.Join(t.TempDir(), "portless.plist")
	if err := os.WriteFile(path, plist, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/bin/plutil", "-lint", "--", path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("plutil -lint: %v: %s", err, output)
	}
	command = exec.Command("/usr/bin/plutil", "-extract", "Label", "raw", "-expect", "string", "-o", "-", "--", path)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("plutil label extraction: %v: %s", err, output)
	}
	if strings.TrimSpace(string(output)) != config.Label {
		t.Fatalf("plist label = %q", output)
	}
}

func TestLaunchDaemonRejectsRelativeContainerExecutable(t *testing.T) {
	config := temporaryConfig(t)
	config.ContainerExecutable = "container"
	if _, err := config.Plist(); err == nil {
		t.Fatal("relative container executable was accepted")
	}
}

func TestLaunchDaemonPersistsCustomProfileWithoutLegacyTLSListeners(t *testing.T) {
	config := temporaryConfig(t)
	config.ContainerExecutable = ""
	config.Profile = &profile.Config{
		Scheme: profile.HTTP, ListenAddress: "127.0.0.1:8080", TLD: ".test",
	}
	plist, err := config.Plist()
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"--scheme", "http", "--listen", "127.0.0.1:8080", "--tld", ".test", "--reconcile-profile"} {
		if !bytes.Contains(plist, []byte("<string>"+required+"</string>")) {
			t.Fatalf("custom profile plist is missing %q", required)
		}
	}
	for _, omitted := range []string{"--container-cli", "--https-listen", "--http-listen"} {
		if bytes.Contains(plist, []byte("<string>"+omitted+"</string>")) {
			t.Fatalf("custom HTTP profile unexpectedly contains %q", omitted)
		}
	}
}

func TestLaunchDaemonRejectsNonLoopbackListeners(t *testing.T) {
	config := temporaryConfig(t)
	for _, address := range []string{":443", "0.0.0.0:443", "192.168.1.5:443", "localhost:443", "127.0.0.1:notaport", "127.0.0.1:8443"} {
		config.HTTPSListeners = []string{address}
		if _, err := config.Plist(); err == nil {
			t.Errorf("listener %q was accepted", address)
		}
	}
}

func TestLaunchDaemonRejectsManagementGroupMismatch(t *testing.T) {
	config := temporaryConfig(t)
	config.ManagementGID++
	if _, err := config.Plist(); err == nil {
		t.Fatal("management group name and GID mismatch was accepted")
	}
}

func TestLifecycleCommandsAreAuditable(t *testing.T) {
	config := temporaryConfig(t)
	install, err := config.Commands(ActionInstall)
	if err != nil {
		t.Fatal(err)
	}
	if len(install) != 4 || install[0].Args[0] != "bootout" || install[1].Args[0] != "bootstrap" || install[3].Args[0] != "kickstart" {
		t.Fatalf("unexpected install commands: %+v", install)
	}
	status, err := config.Commands(ActionStatus)
	if err != nil || len(status) != 1 || status[0].Args[0] != "print" {
		t.Fatalf("status commands: %+v, %v", status, err)
	}
	uninstall, err := config.Commands(ActionUninstall)
	if err != nil || len(uninstall) != 1 || uninstall[0].Args[0] != "bootout" {
		t.Fatalf("uninstall commands: %+v, %v", uninstall, err)
	}
	if !strings.Contains(install[1].String(), config.PlistPath) {
		t.Fatalf("command is not auditable: %s", install[1].String())
	}
}

func TestLifecycleExecutorRejectsNonLaunchctlCommands(t *testing.T) {
	err := ApplyCommands(t.Context(), []Command{{Path: "/usr/bin/true", Args: []string{"unexpected"}}})
	if err == nil || !strings.Contains(err.Error(), "non-launchctl") {
		t.Fatalf("ApplyCommands error = %v", err)
	}
}

func TestInstallerIsIdempotentAndInstalledBinaryRuns(t *testing.T) {
	config := temporaryConfig(t)
	installer := Installer{Config: config}
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	first, err := installer.Install(source)
	if err != nil {
		t.Fatal(err)
	}
	if !first.HasChanges() {
		t.Fatal("initial install reported no changes")
	}
	assertFileMode(t, config.Executable, 0o755)
	assertFileMode(t, config.PlistPath, 0o644)
	assertFileMode(t, config.StateDir, 0o700)
	assertFileMode(t, config.RuntimeDir, 0o750)

	process := exec.Command(config.Executable, "-test.list=TestInstallerIsIdempotentAndInstalledBinaryRuns")
	output, err := process.CombinedOutput()
	if err != nil {
		t.Fatalf("installed process failed: %v: %s", err, output)
	}
	if !bytes.Contains(output, []byte("TestInstallerIsIdempotentAndInstalledBinaryRuns")) {
		t.Fatalf("installed process returned unexpected output: %s", output)
	}

	second, err := installer.Install(source)
	if err != nil {
		t.Fatal(err)
	}
	if second.HasChanges() {
		t.Fatalf("identical install changed %v", second.Changed)
	}

	upgrade, err := installer.Upgrade("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(upgrade.Changed, []string{config.Executable}) {
		t.Fatalf("upgrade changed %v", upgrade.Changed)
	}
	if output, err := exec.Command(config.Executable).CombinedOutput(); err != nil {
		t.Fatalf("upgraded process failed: %v: %s", err, output)
	}

	removed, err := installer.Uninstall()
	if err != nil {
		t.Fatal(err)
	}
	if !removed.HasChanges() {
		t.Fatal("uninstall removed nothing")
	}
	if _, err := os.Stat(config.StateDir); err != nil {
		t.Fatalf("recoverable state was removed: %v", err)
	}
	again, err := installer.Uninstall()
	if err != nil {
		t.Fatal(err)
	}
	if again.HasChanges() {
		t.Fatalf("second uninstall changed %v", again.Changed)
	}
	purged, err := installer.PurgeData()
	if err != nil {
		t.Fatal(err)
	}
	if len(purged) != 2 {
		t.Fatalf("purged paths = %v", purged)
	}
}

func TestInstallerRefusesSymlinkedArtifact(t *testing.T) {
	config := temporaryConfig(t)
	if err := os.MkdirAll(filepath.Dir(config.Executable), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("owned by somebody else"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, config.Executable); err != nil {
		t.Fatal(err)
	}
	if _, err := (Installer{Config: config}).Install("/usr/bin/true"); err == nil {
		t.Fatal("installer replaced a symlink")
	}
}

func TestManagementSocketUsesRealPermissionsAndPeerCredentials(t *testing.T) {
	config := SocketConfig{
		Path: filepath.Join(shortTempDir(t), "run", "management.sock"),
		UID:  os.Geteuid(),
		GID:  os.Getegid(),
	}
	listener, err := ListenManagement(config)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	assertFileMode(t, filepath.Dir(config.Path), 0o750)
	assertFileMode(t, config.Path, 0o660)

	type accepted struct {
		credential PeerCredentials
		err        error
	}
	result := make(chan accepted, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			result <- accepted{err: err}
			return
		}
		defer connection.Close()
		credential, err := Credentials(connection)
		result <- accepted{credential: credential, err: err}
	}()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: config.Path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	select {
	case accepted := <-result:
		if accepted.err != nil {
			t.Fatal(accepted.err)
		}
		if accepted.credential.UID != uint32(os.Geteuid()) {
			t.Fatalf("peer UID = %d, want %d", accepted.credential.UID, os.Geteuid())
		}
		if !accepted.credential.Allowed(uint32(os.Geteuid()), uint32(os.Getegid())) {
			t.Fatal("kernel-authenticated owner was rejected")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Unix peer credentials")
	}

	if _, err := ListenManagement(config); err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatalf("active socket was not preserved: %v", err)
	}
	if mode := fileMode(t, filepath.Dir(config.Path)); mode != 0o750 {
		t.Fatalf("active socket directory mode changed to %04o", mode)
	}
}

func TestManagementSocketReclaimsOnlyOwnedStaleSocket(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "run", "management.sock")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Dir(path), os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := os.Chown(path, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := ListenManagement(SocketConfig{Path: path, UID: os.Geteuid(), GID: os.Getegid()})
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()

	regular := filepath.Join(shortTempDir(t), "run", "management.sock")
	if err := os.MkdirAll(filepath.Dir(regular), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Dir(regular), os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(regular, []byte("do not remove"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenManagement(SocketConfig{Path: regular, UID: os.Geteuid(), GID: os.Getegid()}); err == nil {
		t.Fatal("regular file was replaced by a socket")
	}
	contents, err := os.ReadFile(regular)
	if err != nil || string(contents) != "do not remove" {
		t.Fatalf("regular file was altered: %q, %v", contents, err)
	}
}

func TestManagementSocketRejectsOverlongDarwinPath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin sockaddr_un path limit")
	}
	path := "/tmp/" + strings.Repeat("x", 104)
	if _, err := ListenManagement(SocketConfig{Path: path, UID: os.Geteuid(), GID: os.Getegid()}); err == nil {
		t.Fatal("overlong Unix socket path was accepted")
	}
}

func TestPeerAuthorizationRejectsUnrelatedIdentity(t *testing.T) {
	peer := PeerCredentials{UID: 501, Groups: []uint32{20}}
	if peer.Allowed(502, 80) {
		t.Fatal("unrelated peer was authorized")
	}
}

func TestInstalledStatusUsesRealFiles(t *testing.T) {
	config := temporaryConfig(t)
	installer := Installer{Config: config}
	states, err := installer.Status()
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range states {
		if state.Exists {
			t.Fatalf("unexpected artifact: %+v", state)
		}
	}
	if _, err := installer.Install("/usr/bin/true"); err != nil {
		t.Fatal(err)
	}
	states, err = installer.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 || !states[0].Exists || !states[1].Exists || !states[1].Match {
		t.Fatalf("status = %+v", states)
	}
}

func temporaryConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	group, err := user.LookupGroupId(strconv.Itoa(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	config, err := DefaultConfig(group.Name)
	if err != nil {
		t.Fatal(err)
	}
	config.Executable = filepath.Join(root, "libexec", "portless")
	config.PlistPath = filepath.Join(root, "LaunchDaemons", config.Label+".plist")
	config.StateDir = filepath.Join(root, "state")
	config.RuntimeDir = filepath.Join(root, "run")
	config.ManagementSocket = filepath.Join(config.RuntimeDir, "management.sock")
	config.StdoutPath = filepath.Join(root, "log", "portless.log")
	config.StderrPath = filepath.Join(root, "log", "portless.error.log")
	config.UID = os.Geteuid()
	config.GID = os.Getegid()
	return config
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "portless-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if got := fileMode(t, path); got != want {
		t.Fatalf("%s mode = %04o, want %04o", path, got, want)
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}
