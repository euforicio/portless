# Architecture

## Process model

```text
Browser -> https://<name>.localhost:443
        -> root LaunchDaemon (TLS and reverse proxy)
        -> validated upstream
           - loopback application or runtime-published host port, or
           - private-unicast container/VM address and declared port

Unprivileged CLI -> permissioned Unix socket -> LaunchDaemon route manager
```

The daemon is the only privileged process. It owns ports 80 and 443, private CA
material, the durable route registry, and the management socket. The CLI never
writes root-owned configuration directly.

An explicitly requested per-run LAN exposure is a separate unprivileged
host-level proxy owned by the runner CLI. It binds one assigned LAN address on
an OS-selected port and forwards to the same validated upstream as the local
route. It does not alter the daemon profile, so `.localhost` remains
loopback-only and available simultaneously. No runtime adapter participates.

`internal/daemon` is the composition root. Startup validates the persisted
active profile before interpreting `routes.json`, revalidates dynamic owners,
opens the configured certificate source, binds every configured listener, and
only then starts serving. Any partial bind is rolled back. Shutdown stops management
acceptance first, cancels refresh work, drains HTTP servers, closes idle proxy
connections, and force-closes remaining hijacked or blocked connections.

## Component boundaries

### Proxy and routes

- Match normalized HTTP Host or HTTP/2 authority against an exact route.
- Use `httputil.ReverseProxy` with `Rewrite` and controlled forwarding headers.
- Stream request and response bodies without buffering the complete payload.
- Preserve ordinary WebSocket upgrades and test HMR-shaped traffic.
- Determine whether RFC 8441 needs a maintained third-party WebSocket package;
  use the latest stable compatible release only when real tests prove the gap.
- The implemented protocol and dependency decision is recorded in
  [proxy-routes.md](proxy-routes.md).
- Reject unknown hosts, proxy loops, invalid upstreams, and non-loopback
  management access.

### PKI and macOS service

- Generate an EC local CA with `crypto/x509`; do not shell out to OpenSSL.
- Generate and cache exact-host leaf certificates through SNI.
- Install or remove trust through explicit one-time macOS commands.
- Install a root LaunchDaemon with loopback-only listeners and a permissioned
  Unix management socket.
- Make install, upgrade, status, and uninstall idempotent and recoverable.

### Generic runner and optional runtime discovery

- Execute arbitrary application argv directly through `internal/runner`.
- Treat all validated IP-and-port aliases identically in the routing core.
- Resolve a configured container with Apple's `container` CLI only on the
  explicit optional adapter path.
- Accept only running containers with a declared TCP port and reachable address.
- Refresh routes after container restart or address change.
- Expose `install`, `upgrade`, `add`, `remove`, `list`, `status`, `doctor`,
  `refresh`, and `uninstall` through a small command surface.
- Keep static aliases and process-owned development routes distinguishable.
- Re-inspect container owners at startup, every five seconds, and on explicit
  `refresh`. An unverifiable owner remains registered but has no active proxy
  route until inspection succeeds again.
- Persist the kernel-authenticated operator UID for container ownership. The
  system daemon uses trusted `/bin/launchctl asuser` to enter that login
  bootstrap, drops to the resolved UID/GID and supplementary groups, supplies a
  minimal environment, and only then executes the configured absolute CLI.

### Durable route state

The daemon stores its active profile in strict `profile.json` and canonical
protocol route records, including ownership, in `<state-dir>/routes.json`.
The files are strict versioned JSON, `0600`, owned by
the daemon UID, size- and count-bounded, and never followed through a symlink.
Mutations validate the complete next proxy snapshot, write a same-directory
temporary file, sync it, rename it, sync the directory, and then publish the
new route table. Security-driven deactivation removes a stale endpoint from the
live table before attempting a durable metadata update.

## Security invariants

- Default network exposure is only `127.0.0.1` and `::1`.
- LAN requires the literal `--lan` run flag, binds one eligible address rather
  than a wildcard, and persists only exact owned cleanup metadata.
- `.localhost` is the default and requires no hosts-file mutation.
- Route names are normalized DNS labels and exact-match by default.
- The management socket verifies local ownership and accepts a narrow schema.
- Process-owned routes are tied to the peer UID and a kernel process-start
  identity rather than a reusable PID alone.
- Protocol v2 requires absent, exact-owner, or explicit-any match conditions;
  owner comparison and mutation are atomic under the registry lock.
- Container inspector UIDs are daemon-derived and non-root. Request JSON cannot
  select an identity, and the mutable user CLI is never executed as root.
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
- Real HTTP LAN, exact-host HTTPS/HTTP2, HTTP/1.1 upgrade, mDNS readiness,
  address rebinding, and identity-safe cleanup paths pass on an eligible Mac.
- `go vet`, unit/integration tests, race tests, and credential scans pass.
