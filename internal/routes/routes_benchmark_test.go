package routes_test

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/euforicio/portless/internal/routes"
)

func BenchmarkTableResolveConcurrentReplace(b *testing.B) {
	const routeCount = 100

	first := benchmarkRoutes(b, routeCount, 8000)
	second := benchmarkRoutes(b, routeCount, 9000)
	table := routes.NewTable()
	if err := table.Replace(first); err != nil {
		b.Fatal(err)
	}

	var operations atomic.Uint64
	var replacements atomic.Uint64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			operation := operations.Add(1)
			if operation%1024 == 0 {
				replacement := first
				if replacements.Add(1)%2 == 1 {
					replacement = second
				}
				if err := table.Replace(replacement); err != nil {
					b.Error(err)
					return
				}
				continue
			}
			if _, ok := table.Resolve("app-050.localhost:443"); !ok {
				b.Error("registered route was not resolved")
				return
			}
		}
	})
	b.ReportMetric(float64(replacements.Load())/float64(b.N), "replaces/op")
}

func benchmarkRoutes(b *testing.B, count, basePort int) []routes.Route {
	b.Helper()
	result := make([]routes.Route, count)
	for index := range count {
		route, err := routes.NewRoute(
			fmt.Sprintf("app-%03d.localhost", index),
			fmt.Sprintf("http://127.0.0.1:%d", basePort+index),
		)
		if err != nil {
			b.Fatal(err)
		}
		result[index] = route
	}
	return result
}
