# Performance benchmarks

Portless keeps focused microbenchmarks for the request and persistence paths
where regressions would affect normal operation. They use real loopback TCP and
TLS listeners, real proxy requests, real certificate generation, and real
temporary-file writes, renames, file synchronization, and directory
synchronization. They do not use mocks or stubs.

Run the complete benchmark set with allocation reporting and repeated samples:

```sh
go test -run '^$' -bench '^Benchmark' -benchmem -count=5 \
  ./internal/proxy ./internal/routes ./internal/daemon ./internal/pki
```

The benchmarks cover:

- HTTP/1.1 and HTTP/2 requests through the reverse proxy to a loopback backend.
- concurrent route resolution with one atomic route-table replacement per 1,024
  measured operations;
- durable daemon registry commits containing 1, 100, and 1,024 active routes;
- cached and uncached exact-host certificate issuance, plus issuance that
  evicts from a 16-certificate bounded cache.

Use the same machine, filesystem, Go version, power mode, and package selection
when comparing results. Report the five samples rather than only the fastest
run; filesystem synchronization and cryptographic randomness introduce real
run-to-run variation. `go test` prints `ns/op`, `B/op`, and `allocs/op`; the
route concurrency benchmark also prints its measured replacement rate.
