# Architecture

## Process model

```text
Browser -> https://<name>.localhost:443
        -> root LaunchDaemon (TLS and reverse proxy)
        -> validated upstream
           - loopback application port, or
           - current Apple-container VM address and declared port

Unprivileged CLI -> permissioned Unix socket -> LaunchDaemon route manager
```

The daemon is the only privileged process. It owns ports 80 and 443, private CA
material, the durable route registry, and the management socket. The CLI never
writes root-owned configuration directly.

## Component boundaries

### Proxy and routes

- Match normalized HTTP Host or HTTP/2 authority against an exact route.
- Use `httputil.ReverseProxy` with `Rewrite` and controlled forwarding headers.
- Stream request and response bodies without buffering the complete payload.
- Preserve ordinary WebSocket upgrades and test HMR-shaped traffic.
- Determine whether RFC 8441 needs a maintained third-party WebSocket package;
  use the latest stable compatible release only when real tests prove the gap.
- Reject unknown hosts, proxy loops, invalid upstreams, and non-loopback
  management access.

### PKI and macOS service

- Generate an EC local CA with `crypto/x509`; do not shell out to OpenSSL.
- Generate and cache exact-host leaf certificates through SNI.
- Install or remove trust through explicit one-time macOS commands.
- Install a root LaunchDaemon with loopback-only listeners and a permissioned
  Unix management socket.
- Make install, upgrade, status, and uninstall idempotent and recoverable.

### Apple-container and CLI integration

- Resolve the configured container with Apple's `container` CLI.
- Accept only running containers with a declared TCP port and reachable address.
- Refresh routes after container restart or address change.
- Expose `install`, `add`, `remove`, `list`, `status`, `doctor`, and `uninstall`
  through a small command surface.
- Keep static aliases and process-owned development routes distinguishable.

## Security invariants

- Default network exposure is only `127.0.0.1` and `::1`.
- `.localhost` is the default and requires no hosts-file mutation.
- Route names are normalized DNS labels and exact-match by default.
- The management socket verifies local ownership and accepts a narrow schema.
- The daemon validates all upstreams; clients cannot request arbitrary files,
  commands, listener addresses, or daemon flags.
- CA private keys are readable only by root.

## Release gates

- Real HTTP/1.1 and HTTP/2 requests route to distinct live backends.
- Real WebSocket echo, close, fragmentation, and abrupt-disconnect paths pass.
- HTTPS is trusted after install and fails closed for unregistered hostnames.
- Concurrent route changes are atomic and survive daemon restart.
- A real Apple container remains reachable after stop/start and IP reassignment.
- Routine commands succeed without privilege after the one-time installation.
- `go vet`, unit/integration tests, race tests, and credential scans pass.
