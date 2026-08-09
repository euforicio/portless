package pki

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	SecurityTool   = "/usr/bin/security"
	SystemKeychain = "/Library/Keychains/System.keychain"
)

// TrustAction is an explicit privileged change to the macOS admin trust store.
type TrustAction string

const (
	TrustInstall TrustAction = "install"
	TrustRemove  TrustAction = "remove"
)

// Command is an auditable external command. IgnoreNotFound is limited to the
// removal step that makes installation and uninstallation idempotent.
type Command struct {
	Path string
	Args []string
}

func (c Command) String() string {
	quoted := make([]string, 0, len(c.Args)+1)
	quoted = append(quoted, c.Path)
	for _, arg := range c.Args {
		quoted = append(quoted, fmt.Sprintf("%q", arg))
	}
	return strings.Join(quoted, " ")
}

// TrustCommands returns a deterministic mutation command without changing the
// live trust store. ApplyTrust first inspects the exact DER certificate so an
// already-present or already-absent action is a no-op.
func TrustCommands(action TrustAction, caPath string) ([]Command, error) {
	if !filepath.IsAbs(caPath) {
		return nil, errors.New("CA certificate path must be absolute")
	}
	remove := Command{Path: SecurityTool, Args: []string{"remove-trusted-cert", "-d", caPath}}
	switch action {
	case TrustInstall:
		return []Command{{Path: SecurityTool, Args: []string{"add-trusted-cert", "-d", "-r", "trustRoot", "-p", "ssl", "-k", SystemKeychain, caPath}}}, nil
	case TrustRemove:
		return []Command{remove}, nil
	default:
		return nil, fmt.Errorf("unknown trust action %q", action)
	}
}

// SystemTrusted compares exact certificate DER against the system keychain.
// It is read-only and does not rely on a mutable common name.
func SystemTrusted(ctx context.Context, caPath string) (bool, error) {
	wanted, err := readCertificate(caPath)
	if err != nil {
		return false, err
	}
	output, err := exec.CommandContext(ctx, SecurityTool, "find-certificate", "-a", "-p", SystemKeychain).Output()
	if err != nil {
		return false, fmt.Errorf("inspect system keychain: %w", err)
	}
	for len(output) != 0 {
		block, rest := pem.Decode(output)
		if block == nil {
			break
		}
		output = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr == nil && bytes.Equal(certificate.Raw, wanted.Raw) {
			return true, nil
		}
	}
	return false, nil
}

// ApplyTrust executes a previously auditable trust action. It deliberately
// requires root and never invokes sudo itself.
func ApplyTrust(ctx context.Context, action TrustAction, caPath string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("macOS trust operations are only supported on darwin")
	}
	if os.Geteuid() != 0 {
		return errors.New("changing the system trust store requires root")
	}
	commands, err := TrustCommands(action, caPath)
	if err != nil {
		return err
	}
	present, err := SystemTrusted(ctx, caPath)
	if err != nil {
		return err
	}
	if (action == TrustInstall && present) || (action == TrustRemove && !present) {
		return nil
	}
	for _, command := range commands {
		output, runErr := exec.CommandContext(ctx, command.Path, command.Args...).CombinedOutput()
		if runErr == nil {
			continue
		}
		return fmt.Errorf("%s: %w: %s", command.String(), runErr, strings.TrimSpace(string(output)))
	}
	return nil
}

func readCertificate(path string) (*x509.Certificate, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("CA certificate path must be absolute")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, trailing := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(trailing))) != 0 {
		return nil, errors.New("CA file must contain exactly one PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if !certificate.IsCA {
		return nil, errors.New("certificate is not a CA")
	}
	return certificate, nil
}
