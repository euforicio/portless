package pki

import (
	"fmt"
	"path/filepath"
	"testing"
)

func BenchmarkAuthorityCertificate(b *testing.B) {
	b.Run("cached", func(b *testing.B) {
		authority, err := Open(filepath.Join(b.TempDir(), "pki"), Options{})
		if err != nil {
			b.Fatal(err)
		}
		if _, err := authority.Certificate("cached.localhost"); err != nil {
			b.Fatal(err)
		}

		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if _, err := authority.Certificate("cached.localhost"); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("uncached", func(b *testing.B) {
		authority, err := Open(filepath.Join(b.TempDir(), "pki"), Options{})
		if err != nil {
			b.Fatal(err)
		}

		b.ReportAllocs()
		b.ResetTimer()
		for index := 0; b.Loop(); index++ {
			if _, err := authority.Certificate(fmt.Sprintf("uncached-%d.localhost", index)); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("bounded_eviction", func(b *testing.B) {
		authority, err := Open(filepath.Join(b.TempDir(), "pki"), Options{MaxLeafCertificates: 16})
		if err != nil {
			b.Fatal(err)
		}
		for index := range 16 {
			if _, err := authority.Certificate(fmt.Sprintf("seed-%d.localhost", index)); err != nil {
				b.Fatal(err)
			}
		}

		b.ReportAllocs()
		b.ResetTimer()
		for index := 0; b.Loop(); index++ {
			if _, err := authority.Certificate(fmt.Sprintf("evict-%d.localhost", index)); err != nil {
				b.Fatal(err)
			}
		}
	})
}
