# portless

Portless is a native Go local-domain proxy and Apple-container router for
macOS. It gives local applications stable HTTPS names such as
`https://fieldnotes.localhost` while keeping changing ports and container
addresses behind one loopback-only daemon.

## Install and operate

Build with Go 1.26.5 or a newer Go 1.26 release, then perform the one explicit
privileged bootstrap:

```sh
go build -o portless ./cmd/portless
sudo ./portless install --management-group admin \
  --container-cli /opt/homebrew/bin/container
```

`install` does not require an existing management socket. It atomically installs
the current executable and LaunchDaemon property list, creates the local CA,
adds that exact CA to the system trust store, starts the service through
`launchctl`, and waits for the management socket to answer. Repeating `install`
is safe. Use `sudo ./portless upgrade` to reconcile a newer executable.

After installation, route operations are unprivileged and never invoke `sudo`,
`launchctl`, or `security`:

```sh
portless add fieldnotes --port 3000
portless add api --port 8080 --pid "$PID"
portless add dashboard --container dashboard --port 80
portless list
portless status
portless doctor
portless refresh
portless remove fieldnotes
```

The management socket is `/var/run/portless/management.sock` and is accessible
only to root and the selected management group. `PORTLESS_SOCKET` selects an
alternate absolute socket for development and integration tests.

`sudo portless uninstall` stops launchd, removes the exact trusted CA, binary,
property list, and socket. It deliberately retains route state, certificates,
and logs for recovery. Destructive state removal is not exposed by the ordinary
CLI.

## Runtime behavior

- HTTP on loopback port 80 redirects only registered exact hosts to HTTPS with
  a method-preserving 308 response.
- HTTPS on loopback port 443 uses an exact-host SNI certificate and rejects an
  SNI/Host mismatch.
- The proxy supports streaming, HTTP/2 client access, HTTPS upstreams, safe
  redirect rewriting, and ordinary HTTP/1.1 WebSocket/HMR upgrades.
- Route registrations are strictly validated and atomically persisted at
  `/Library/Application Support/Portless/routes.json`.
- The daemon independently re-inspects every container registration. A stopped,
  missing, ambiguous, or unverifiable container is removed from the active
  proxy table while its registration is retained for later recovery.
- Container inspection is tied to the kernel-authenticated login UID that added
  the route. The root daemon enters that user's launchd bootstrap domain through
  `/bin/launchctl asuser` and drops UID/GID before executing the user's absolute
  Apple `container` CLI. Root cannot register a container-owned route.
- Process-owned routes include a Darwin process-start identity and are removed
  after the exact process exits, including across daemon restarts.

## Intentional constraints

Portless binds literal `127.0.0.1` and `::1` listeners only. It does not expose
LAN, tailnet, or public listeners and does not modify `/etc/hosts`. RFC 8441
HTTP/2 extended-CONNECT WebSockets remain intentionally unsupported because Go
1.26 does not expose a supported server configuration for them; ordinary
HTTP/1.1 WebSockets and HTTP/2 request/response traffic are supported.

See [docs/architecture.md](docs/architecture.md), [docs/cli.md](docs/cli.md),
[docs/pki-service.md](docs/pki-service.md), and
[docs/proxy-routes.md](docs/proxy-routes.md) for the security and protocol
contracts.
