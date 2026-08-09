# portless

A native Go local-domain proxy and Apple-container router for macOS.

The intended experience is:

```sh
portless install
portless add fieldnotes --container fieldnotes --port 80
open https://fieldnotes.localhost
```

Applications and containers still use internal ports. One loopback-only proxy
owns ports 443 and 80, routes by hostname, and keeps those implementation
details out of user-facing URLs.

## Initial scope

- Go 1.26.5+ implementation with a single distributable binary.
- Dynamic `.localhost` routes without `/etc/hosts` changes.
- HTTPS, HTTP/2, streaming, ordinary WebSocket upgrades, and an explicit
  decision for RFC 8441 extended CONNECT.
- A locally generated CA with exact-host certificates and one-time macOS trust.
- Root LaunchDaemon for the listener plus an unprivileged management interface.
- Apple `container` discovery and route refresh when VM addresses change.
- Atomic persistent state, stale-owner cleanup, diagnostics, and safe removal.

See [docs/architecture.md](docs/architecture.md) for component boundaries and
acceptance criteria.
