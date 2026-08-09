package service

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const Launchctl = "/bin/launchctl"

// Action names a privileged launchd lifecycle operation.
type Action string

const (
	ActionInstall   Action = "install"
	ActionUpgrade   Action = "upgrade"
	ActionStatus    Action = "status"
	ActionUninstall Action = "uninstall"
)

// Command is an auditable launchd command.
type Command struct {
	Path       string
	Args       []string
	WhenLoaded bool
}

// Loaded reports launchd's current job state using only the documented print
// exit status. Human-oriented output is deliberately discarded.
func (c Config) Loaded(ctx context.Context) (bool, error) {
	if err := c.validate(); err != nil {
		return false, err
	}
	err := exec.CommandContext(ctx, Launchctl, "print", "system/"+c.Label).Run()
	if err == nil {
		return true, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return false, nil
	}
	return false, err
}

// ApplyCommands executes a fixed, prevalidated launchctl plan. It never uses
// sudo and skips WhenLoaded commands when the exact launchd job is absent.
func ApplyCommands(ctx context.Context, commands []Command) error {
	for _, command := range commands {
		if command.Path != Launchctl || len(command.Args) == 0 {
			return errors.New("refusing non-launchctl lifecycle command")
		}
		if command.WhenLoaded {
			if len(command.Args) != 2 || command.Args[0] != "bootout" || !strings.HasPrefix(command.Args[1], "system/") {
				return errors.New("invalid conditional lifecycle command")
			}
			loaded := exec.CommandContext(ctx, Launchctl, "print", command.Args[1]).Run()
			if loaded != nil {
				var exitError *exec.ExitError
				if errors.As(loaded, &exitError) {
					continue
				}
				return loaded
			}
		}
		output, err := exec.CommandContext(ctx, command.Path, command.Args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %w: %s", command.String(), err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func (c Command) String() string {
	parts := []string{c.Path}
	for _, arg := range c.Args {
		parts = append(parts, fmt.Sprintf("%q", arg))
	}
	return strings.Join(parts, " ")
}

// Commands returns the launchctl plan. The caller performs it only after the
// artifact report shows a change; this keeps identical installs no-op.
func (c Config) Commands(action Action) ([]Command, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	target := "system/" + c.Label
	bootout := Command{Path: Launchctl, Args: []string{"bootout", target}, WhenLoaded: true}
	switch action {
	case ActionInstall, ActionUpgrade:
		return []Command{
			bootout,
			{Path: Launchctl, Args: []string{"bootstrap", "system", c.PlistPath}},
			{Path: Launchctl, Args: []string{"enable", target}},
			{Path: Launchctl, Args: []string{"kickstart", "-k", target}},
		}, nil
	case ActionStatus:
		return []Command{{Path: Launchctl, Args: []string{"print", target}}}, nil
	case ActionUninstall:
		return []Command{bootout}, nil
	default:
		return nil, errors.New("unknown service action")
	}
}
