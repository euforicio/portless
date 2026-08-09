package routes_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/euforicio/portless/internal/routes"
)

func TestNormalizeAuthority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		authority string
		want      string
		valid     bool
	}{
		{name: "host", authority: "fieldnotes.localhost", want: "fieldnotes.localhost", valid: true},
		{name: "case port and trailing dot", authority: "FieldNotes.LOCALHOST.:443", want: "fieldnotes.localhost", valid: true},
		{name: "nested labels", authority: "api.dev.localhost:8443", want: "api.dev.localhost", valid: true},
		{name: "bare localhost", authority: "localhost", valid: false},
		{name: "suffix confusion", authority: "fieldnotes.localhost.example", valid: false},
		{name: "userinfo", authority: "user@fieldnotes.localhost", valid: false},
		{name: "path", authority: "fieldnotes.localhost/path", valid: false},
		{name: "missing port", authority: "fieldnotes.localhost:", valid: false},
		{name: "zero port", authority: "fieldnotes.localhost:0", valid: false},
		{name: "invalid port", authority: "fieldnotes.localhost:65536", valid: false},
		{name: "empty label", authority: "fieldnotes..localhost", valid: false},
		{name: "leading hyphen", authority: "-fieldnotes.localhost", valid: false},
		{name: "unicode", authority: "fíeldnotes.localhost", valid: false},
		{name: "ip literal", authority: "127.0.0.1:443", valid: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := routes.NormalizeAuthority(test.authority)
			if test.valid {
				if err != nil {
					t.Fatalf("NormalizeAuthority() error = %v", err)
				}
				if got != test.want {
					t.Fatalf("NormalizeAuthority() = %q, want %q", got, test.want)
				}
				return
			}
			if !errors.Is(err, routes.ErrInvalidHost) {
				t.Fatalf("NormalizeAuthority() error = %v, want ErrInvalidHost", err)
			}
		})
	}
}

func TestNewRouteValidatesUpstream(t *testing.T) {
	t.Parallel()

	valid := []string{
		"http://127.0.0.1:8080",
		"https://[::1]:8443/",
		"http://10.0.0.2:80",
		"http://[fd00::2]:3000",
	}
	for _, upstream := range valid {
		t.Run("valid "+upstream, func(t *testing.T) {
			t.Parallel()
			route, err := routes.NewRoute("app.localhost", upstream)
			if err != nil {
				t.Fatalf("NewRoute() error = %v", err)
			}
			if route.Host() != "app.localhost" || route.Upstream() == "" {
				t.Fatalf("unexpected route: host=%q upstream=%q", route.Host(), route.Upstream())
			}
		})
	}

	invalid := []string{
		"",
		"127.0.0.1:8080",
		"ftp://127.0.0.1:21",
		"http://localhost:8080",
		"http://0.0.0.0:8080",
		"http://224.0.0.1:8080",
		"http://169.254.1.2:3000",
		"http://8.8.8.8:8080",
		"http://127.0.0.1",
		"http://127.0.0.1:8080/base",
		"http://127.0.0.1:8080?query=yes",
		"http://user:password@127.0.0.1:8080",
	}
	for _, upstream := range invalid {
		t.Run("invalid "+upstream, func(t *testing.T) {
			t.Parallel()
			_, err := routes.NewRoute("app.localhost", upstream)
			if !errors.Is(err, routes.ErrInvalidUpstream) {
				t.Fatalf("NewRoute() error = %v, want ErrInvalidUpstream", err)
			}
		})
	}
}

func TestTableOperations(t *testing.T) {
	t.Parallel()

	table := routes.NewTable()
	first, err := table.Set("B.localhost", "http://127.0.0.1:8002")
	if err != nil {
		t.Fatal(err)
	}
	second, err := table.Set("a.localhost", "http://127.0.0.1:8001")
	if err != nil {
		t.Fatal(err)
	}

	got, ok := table.Lookup("A.LOCALHOST:443")
	if !ok || got.Upstream() != second.Upstream() {
		t.Fatalf("Lookup() = (%q, %v), want %q", got.Upstream(), ok, second.Upstream())
	}
	if _, ok := table.Lookup("missing.localhost"); ok {
		t.Fatal("Lookup() found an unregistered host")
	}

	listed := table.List()
	if len(listed) != 2 || listed[0].Host() != "a.localhost" || listed[1].Host() != "b.localhost" {
		t.Fatalf("List() = %#v, want host-sorted snapshot", listed)
	}

	if !table.Delete("b.localhost:443") || table.Delete("b.localhost") {
		t.Fatal("Delete() did not report route presence accurately")
	}
	if _, ok := table.Lookup(first.Host()); ok {
		t.Fatal("deleted route remains visible")
	}
}

func TestTableZeroValueCanSetRoute(t *testing.T) {
	t.Parallel()

	var table routes.Table
	if _, err := table.Set("app.localhost", "http://127.0.0.1:080"); err != nil {
		t.Fatal(err)
	}
	route, ok := table.Lookup("app.localhost")
	if !ok || route.Upstream() != "http://127.0.0.1:80" {
		t.Fatalf("Lookup() = (%q, %v), want canonical port", route.Upstream(), ok)
	}
}

func TestTableReplaceIsAtomic(t *testing.T) {
	t.Parallel()

	table := routes.NewTable()
	oldRoute, err := table.Set("old.localhost", "http://127.0.0.1:8000")
	if err != nil {
		t.Fatal(err)
	}
	newRoute, err := routes.NewRoute("new.localhost", "http://127.0.0.1:9000")
	if err != nil {
		t.Fatal(err)
	}

	if err := table.Replace([]routes.Route{newRoute, newRoute}); err == nil {
		t.Fatal("Replace() accepted duplicate hosts")
	}
	if _, ok := table.Lookup(oldRoute.Host()); !ok {
		t.Fatal("failed Replace() changed the active snapshot")
	}

	if err := table.Replace([]routes.Route{newRoute}); err != nil {
		t.Fatal(err)
	}
	if _, ok := table.Lookup(oldRoute.Host()); ok {
		t.Fatal("old snapshot remains after Replace()")
	}
	if _, ok := table.Lookup(newRoute.Host()); !ok {
		t.Fatal("new snapshot is not visible after Replace()")
	}
}

func TestTableConcurrentAccess(t *testing.T) {
	t.Parallel()

	table := routes.NewTable()
	const workers = 16
	const iterations = 100

	var group sync.WaitGroup
	for worker := range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			host := fmt.Sprintf("app-%d.localhost", worker)
			for range iterations {
				if _, err := table.Set(host, "http://127.0.0.1:8080"); err != nil {
					t.Errorf("Set() error = %v", err)
					return
				}
				table.Lookup(host)
				table.List()
				table.Delete(host)
			}
		}()
	}
	group.Wait()
}

func TestCustomTLDAndWildcardFallback(t *testing.T) {
	t.Parallel()

	table, err := routes.NewTableWithOptions(routes.Options{TLD: "DEV", WildcardFallback: true})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := table.Set("app.dev", "http://127.0.0.1:8000")
	if err != nil {
		t.Fatal(err)
	}
	nearer, err := table.Set("api.app.dev", "http://127.0.0.1:8001")
	if err != nil {
		t.Fatal(err)
	}
	exact, err := table.Set("v1.api.app.dev", "http://127.0.0.1:8002")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		authority string
		want      routes.Route
		found     bool
	}{
		{authority: "v1.api.app.dev:8443", want: exact, found: true},
		{authority: "child.api.app.dev", want: nearer, found: true},
		{authority: "deep.child.app.dev", want: parent, found: true},
		{authority: "missing.dev", found: false},
		{authority: "app.developer", found: false},
		{authority: "app.dev.example", found: false},
		{authority: "dev", found: false},
		{authority: "child.localhost", found: false},
	}
	for _, test := range tests {
		got, found := table.Resolve(test.authority)
		if found != test.found || (found && got.Upstream() != test.want.Upstream()) {
			t.Errorf("Resolve(%q) = (%q, %v), want (%q, %v)", test.authority, got.Upstream(), found, test.want.Upstream(), test.found)
		}
	}
	if _, found := table.Lookup("child.api.app.dev"); found {
		t.Fatal("Lookup performed wildcard fallback")
	}
}

func TestWildcardFallbackIsOptIn(t *testing.T) {
	t.Parallel()

	table, err := routes.NewTableWithOptions(routes.Options{TLD: ".test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := table.Set("app.test", "http://127.0.0.1:8000"); err != nil {
		t.Fatal(err)
	}
	if _, found := table.Resolve("child.app.test"); found {
		t.Fatal("exact-only table resolved an unregistered child")
	}
}

func TestCustomTLDValidationAndReplacementBoundary(t *testing.T) {
	t.Parallel()

	for _, invalid := range []string{".", "..test", "dev.local", "-test", "123", "tést", "test:443"} {
		if _, err := routes.NewTableWithOptions(routes.Options{TLD: invalid}); !errors.Is(err, routes.ErrInvalidTLD) {
			t.Errorf("NewTableWithOptions(TLD=%q) error = %v, want ErrInvalidTLD", invalid, err)
		}
	}

	table, err := routes.NewTableWithOptions(routes.Options{TLD: "test"})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := routes.NewRoute("app.localhost", "http://127.0.0.1:8000")
	if err != nil {
		t.Fatal(err)
	}
	if err := table.Replace([]routes.Route{foreign}); !errors.Is(err, routes.ErrInvalidHost) {
		t.Fatalf("Replace(foreign route) error = %v, want ErrInvalidHost", err)
	}
}
