package service

import (
	"errors"
	"fmt"
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
