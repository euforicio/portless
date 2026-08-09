package client

import (
	"net/netip"
	"testing"
)

func TestNormalizeName(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "Fieldnotes", want: "fieldnotes.localhost"},
		{input: "fieldnotes.localhost", want: "fieldnotes.localhost"},
		{input: "fieldnotes.localhost.", want: "fieldnotes.localhost"},
	} {
		got, err := NormalizeName(test.input)
		if err != nil {
			t.Fatalf("NormalizeName(%q): %v", test.input, err)
		}
		if got != test.want {
			t.Fatalf("NormalizeName(%q) = %q, want %q", test.input, got, test.want)
		}
	}

	for _, input := range []string{"", "-bad", "bad-", "two.labels", "bad_name", "☃"} {
		if _, err := NormalizeName(input); err == nil {
			t.Errorf("NormalizeName(%q) succeeded, want error", input)
		}
	}
}

func TestRouteValidationKeepsOwnersDistinct(t *testing.T) {
	t.Parallel()

	static := Route{
		Name: "app.localhost", Scheme: "http", Host: "127.0.0.1", Port: 3000,
		Owner: Owner{Kind: OwnerStatic, Refresh: RefreshNever},
	}
	if err := static.Validate(); err != nil {
		t.Fatalf("validate static route: %v", err)
	}

	process := static
	process.Owner = Owner{Kind: OwnerProcess, PID: 42, Refresh: RefreshNever}
	if err := process.Validate(); err != nil {
		t.Fatalf("validate process route: %v", err)
	}

	container := Route{
		Name: "app.localhost", Scheme: "http", Host: "192.168.64.2", Port: 80,
		Owner: Owner{Kind: OwnerContainer, Container: "app", Network: "default", Refresh: RefreshContainerAddress},
	}
	if err := container.Validate(); err != nil {
		t.Fatalf("validate container route: %v", err)
	}

	container.Owner.Refresh = RefreshNever
	if err := container.Validate(); err == nil {
		t.Fatal("container route with static refresh policy succeeded")
	}
	container.Owner.Refresh = RefreshContainerAddress
	container.Host = "8.8.8.8"
	if err := container.Validate(); err == nil {
		t.Fatal("container route with a public upstream succeeded")
	}
	static.Host = netip.MustParseAddr("192.168.64.2").String()
	if err := static.Validate(); err == nil {
		t.Fatal("static route with non-loopback host succeeded")
	}
}
