package daemon

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/euforicio/portless/internal/client"
	"github.com/euforicio/portless/internal/routes"
)

func BenchmarkRegistryCommit(b *testing.B) {
	for _, routeCount := range []int{1, 100, 1024} {
		b.Run(fmt.Sprintf("routes_%d", routeCount), func(b *testing.B) {
			stateDir := b.TempDir()
			table := routes.NewTable()
			registry := &registry{
				path:    filepath.Join(stateDir, stateFileName),
				table:   table,
				records: make(map[string]client.Route),
				active:  make(map[string]bool),
			}
			records, active := benchmarkRegistrations(routeCount)
			if err := registry.commitLocked(records, active); err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := registry.commitLocked(records, active); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkRegistrations(count int) (map[string]client.Route, map[string]bool) {
	records := make(map[string]client.Route, count)
	active := make(map[string]bool, count)
	for index := range count {
		name := fmt.Sprintf("app-%04d.localhost", index)
		records[name] = client.Route{
			Name:   name,
			Scheme: "http",
			Host:   "127.0.0.1",
			Port:   uint16(10000 + index),
			Owner:  client.Owner{Kind: client.OwnerStatic, Refresh: client.RefreshNever},
		}
		active[name] = true
	}
	return records, active
}
