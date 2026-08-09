# portless

Portless is a small macOS-native Go proxy for stable local application names.
It maps validated IP-and-port upstreams to origins such as
`https://fieldnotes.localhost`. Local processes and host ports published by
Docker, Podman, Apple Container, Lima, or another runtime use the same routing
core; no container runtime is required.

## Initialize once

Build with Go 1.26.5 or a newer Go 1.26 release, then run init as your ordinary
macOS user:

```sh
go build -o portless ./cmd/portless
./portless init
# or install a custom persisted profile
./portless init --scheme http --listen 127.0.0.1:8080 --tld .test
```

`init` performs read-only platform, management-group, daemon, port, and
privilege-helper checks. A healthy same-version rerun returns without invoking
`sudo`. When reconciliation is needed it invokes fixed `/usr/bin/sudo` once to
run the auditable installer, installs or upgrades the binary and LaunchDaemon,
creates and trusts the local CA, starts the service, waits for the management
socket, and runs doctor again from the original user process.

`install`, `upgrade`, and `uninstall` remain advanced root-only lifecycle
commands. The default management socket is
`/var/run/portless/management.sock`; `PORTLESS_SOCKET` selects an alternate
absolute test or foreground-development socket.

## Run any command

Portless executes an argv vector directly. It does not invoke a shell, inspect
package managers, read `package.json`, infer frameworks, or understand
workspaces or Turborepo.

```sh
portless run --name fieldnotes -- go run ./cmd/server
portless run --name api --app-port 8080 -- ./api-server
portless fieldnotes go run ./cmd/server
portless                         # uses the nearest validated portless.json
```

The child receives `PORT`, `HOST`, `PORTLESS_URL`, and, when the installed
public CA file is readable, `NODE_EXTRA_CA_CERTS`. The latter is compatibility
metadata only and does not imply Node.js behavior. Dynamic and fixed ports are
supported. Signals are forwarded to an identity-checked child process group,
the exact child exit status is returned, and the process-owned route is removed
only when its daemon-canonical owner still matches. `--force` can take over only
an exact live runner record and uses protocol compare-and-set replacement.

`--tailscale` and `--funnel` are explicit per-run exposure boundaries. They use
the official CLI's live capabilities, apply one root-mounted registration, and
remove only that exact registration when the run ends. They never use `sudo`.
`--lan` explicitly adds a host-level plain-HTTP listener on one eligible LAN
address and advertises the exact route as `.local`. It never depends on a
container runtime, wildcard-binds, or persists as a default. `--ip` pins one
eligible assigned address; otherwise Portless selects deterministically and
tracks interface/address changes. `--lan --https` enables exact-host TLS with a
bounded local-CA leaf cache. Other devices do not automatically trust the Mac's
CA; Portless prints the public CA path for explicit client trust.

```sh
portless run --name fieldnotes --lan -- go run ./cmd/server
portless run --name fieldnotes --lan --ip 192.168.1.20 -- go run ./cmd/server
portless run --name fieldnotes --lan --https -- go run ./cmd/server
```

LAN listeners use an OS-assigned unprivileged port, shown in the printed URL.
They expose the application to subnet peers without access control. The local
`.localhost` origin remains available simultaneously on the loopback daemon.

Example `portless.json`:

```json
{
  "name": "fieldnotes",
  "command": ["go", "run", "./cmd/server"],
  "appPort": 3000,
  "proxy": true,
  "env": {"LOG_LEVEL": "debug"}
}
```

## Routes and operation

```sh
portless alias dashboard --host 127.0.0.1 --port 3000
portless alias vm-api --host 192.168.64.8 --port 8080
portless alias dashboard --host 127.0.0.1 --port 4000 --force
portless list
portless remove dashboard
portless doctor
portless prune
portless hosts sync             # read-only plan
sudo portless hosts sync --apply
```

Static aliases accept literal loopback or private-unicast upstreams, making
runtime-published ports ordinary routes. `add --container ID` remains an
optional Apple Container discovery convenience and is never called by init,
run, alias, proxy, list, or sharing paths.

The default proxy preserves exact `.localhost` HTTPS routing on loopback ports
80/443, method-preserving redirects, HTTP/2 request/response traffic,
streaming, HTTPS upstreams, redirect rewriting, and HTTP/1.1 WebSockets.
Custom foreground profiles support one literal loopback listener, HTTP or
HTTPS, a custom single-label TLD, generated CA or secure certificate/key files,
and opt-in registered-parent fallback. Generated-CA wildcard fallback is
rejected because the leaf cache is not durably bounded. The active profile is
persisted and incompatible daemon restarts fail closed. `init` accepts the same
profile flags for the installed service; an intentional profile replacement is
allowed only after every route has been removed.

## Safety boundaries and intentional exclusions

- Default listeners are literal loopback addresses only.
- LAN activates only through the explicit per-run `--lan` flag; configuration
  files and environment variables cannot silently enable it.
- Routine run, alias, list, remove, refresh, prune, Serve, and Funnel operations
  never invoke `sudo`.
- Trust, LaunchDaemon, privileged ports, `/etc/hosts`, and destructive route
  cleanup remain explicit boundaries.
- There is no Linux/Windows behavior and no framework or package-manager
  integration.
- RFC 8441 HTTP/2 extended-CONNECT WebSockets are not advertised; Go 1.26 has
  no supported server configuration for them. HTTP/1.1 WebSockets are tested.
- Tailscale registrations are durably tied to the runner identity, cleaned
  exactly on normal and signaled shutdown, and reconciled after a hard crash by
  `portless prune` or the confirmed `portless clean --routes --yes` boundary.
- LAN advertisement identities are also tied to the runner identity. Cleanup
  stops only the exact owned `dns-sd` process; Portless never changes firewall
  or DNS configuration, `/etc/hosts`, or unrelated `dns-sd` processes.

See [CLI](docs/cli.md), [architecture](docs/architecture.md),
[profiles](docs/proxy-profiles.md), [runner](docs/runner.md),
[sharing](docs/sharing.md), and [PKI/service](docs/pki-service.md).
