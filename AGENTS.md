# Repository instructions

## Product boundary

Build a small, production-friendly Go port of Portless. The routing core is
runtime-agnostic: local processes and containers from Docker, Podman, Apple
Container, Lima, or any other runtime are ordinary validated host/port
upstreams. Runtime discovery adapters are optional conveniences, never core
requirements. The user-facing contract is stable HTTPS names such as
`https://fieldnotes.localhost`; internal ports and container addresses remain
implementation details.

## Engineering constraints

- Use Go 1.26.5 or newer within the Go 1.26 line and use current Go 1.26 APIs.
- Prefer the standard library. Add a third-party module only for a demonstrated
  gap, especially WebSocket or HTTP/2 extended-CONNECT behavior.
- Before adding a module, verify its latest stable release, maintenance state,
  license, and Go 1.26 compatibility. Pin the current stable version.
- Use `httputil.ReverseProxy.Rewrite`; do not introduce the deprecated
  `Director` hook.
- Never mock or stub. Tests must exercise real listeners, sockets, child
  processes, certificates, files, and Apple-container CLI behavior where that
  integration is in scope.
- Default listeners are loopback-only. LAN, tailnet, or public exposure must be
  explicit and separately tested.
- Privilege is limited to one-time service installation, ports 80/443, and CA
  trust. Routine route and container operations must not invoke `sudo`.
- Treat route registrations and container metadata as untrusted input. Validate
  hostnames, ports, upstream addresses, paths, and ownership at every boundary.
- Keep APIs small and behavior explicit. Avoid frameworks and unnecessary
  abstraction.

## Validation

Run at minimum:

```sh
go fmt ./...
go vet ./...
go test ./...
go test -race ./...
```

Integration behavior must be verified with real HTTP, HTTPS, HTTP/2, WebSocket,
Unix-socket, launchd-plist, and Apple-container execution paths as applicable.

## Delivery workflow

Use [README.md](README.md#agent-delivery-and-ci-policy) for isolated worktrees,
independent review, exact-tree acceptance and serialized integration. Direct-main
is a proposed gated workflow; preserve current protections and publication authorization.
