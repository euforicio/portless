package projectconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadValidGenericConfig(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, FileName)
	contents := `{
  "name": "Fieldnotes",
  "command": ["go", "run", "./cmd/server"],
  "appPort": 4317,
  "proxy": true,
  "env": {"LOG_LEVEL": "debug", "EMPTY": ""}
}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Name != "fieldnotes.localhost" || !config.Proxy || config.AppPort != 4317 {
		t.Fatalf("config = %#v", config)
	}
	if strings.Join(config.Command, "|") != "go|run|./cmd/server" || config.Environment["LOG_LEVEL"] != "debug" {
		t.Fatalf("config contents = %#v", config)
	}
}

func TestLoadDefaultsProxyAndRejectsInvalidInput(t *testing.T) {
	directory := t.TempDir()
	validPath := filepath.Join(directory, FileName)
	if err := os.WriteFile(validPath, []byte(`{"command":["/usr/bin/true"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(validPath)
	if err != nil {
		t.Fatal(err)
	}
	if !config.Proxy || config.Name != "" || config.AppPort != 0 {
		t.Fatalf("defaults = %#v", config)
	}

	tests := map[string]string{
		"unknown field":     `{"command":["true"],"unknown":1}`,
		"trailing document": `{"command":["true"]} {}`,
		"empty command":     `{"command":[]}`,
		"shell string":      `{"command":"go run ."}`,
		"invalid name":      `{"name":"bad/name","command":["true"]}`,
		"invalid env key":   `{"command":["true"],"env":{"BAD-KEY":"x"}}`,
		"port no proxy":     `{"command":["true"],"appPort":3000,"proxy":false}`,
		"port overflow":     `{"command":["true"],"appPort":65536}`,
		"duplicate field":   `{"command":["true"],"command":["false"]}`,
		"duplicate env":     `{"command":["true"],"env":{"KEY":"one","KEY":"two"}}`,
	}
	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, strings.ReplaceAll(name, " ", "-")+".json")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load accepted invalid config")
			}
		})
	}

	symlink := filepath.Join(directory, "symlink.json")
	if err := os.Symlink(validPath, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(symlink); err == nil {
		t.Fatal("Load followed a symlink")
	}
	if _, err := Load(filepath.Base(validPath)); err == nil {
		t.Fatal("Load accepted a relative path")
	}
}

func TestFindAndResolveNamePrecedence(t *testing.T) {
	root := filepath.Join(t.TempDir(), "My_Project")
	nested := filepath.Join(root, "nested", "service")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "-C", root, "init").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	configPath := filepath.Join(root, FileName)
	if err := os.WriteFile(configPath, []byte(`{"command":["true"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	resolvedConfigPath, err := filepath.EvalSymlinks(configPath)
	if err != nil {
		t.Fatal(err)
	}
	found, ok, err := Find(nested)
	if err != nil || !ok || found != resolvedConfigPath {
		t.Fatalf("Find = %q, %t, %v", found, ok, err)
	}

	tests := []struct {
		explicit   string
		configured string
		want       string
	}{
		{explicit: "flag", configured: "config", want: "flag.localhost"},
		{configured: "config", want: "config.localhost"},
		{want: "my-project.localhost"},
	}
	for _, test := range tests {
		got, err := ResolveName(test.explicit, test.configured, nested)
		if err != nil || got != test.want {
			t.Fatalf("ResolveName(%q, %q) = %q, %v; want %q", test.explicit, test.configured, got, err, test.want)
		}
	}
}

func TestResolveNameFallsBackToCurrentDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "API Server")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	name, err := ResolveName("", "", directory)
	if err != nil || name != "api-server.localhost" {
		t.Fatalf("ResolveName = %q, %v", name, err)
	}
}
