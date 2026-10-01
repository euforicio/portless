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
[performance benchmarks](docs/benchmarks.md),
[profiles](docs/proxy-profiles.md), [runner](docs/runner.md),
[sharing](docs/sharing.md), and [PKI/service](docs/pki-service.md).

## Apple Container integration

The optional real-runtime integration requires Apple silicon macOS with the
Apple `container` CLI installed. It creates a uniquely named nginx container,
exports `PORTLESS_TEST_CONTAINER` and `PORTLESS_TEST_CONTAINER_PORT` for the
real resolver test, verifies the resolved TCP endpoint, and deletes only that
exact container on success, failure, or interruption:

```sh
./scripts/test-apple-container-integration
```

GitHub Actions exposes the same path only through the manually dispatched
`Apple Container integration` workflow. The job requires explicit confirmation
and a provisioned self-hosted runner carrying the standard `macOS` and `ARM64`
labels, so ordinary pull-request and push CI never attempts unsupported nested
virtualization on hosted runners.

## Agent delivery and CI policy

This is the intended local-first integration workflow. These instructions do not
implement a shipping service or authorize publication; current protections,
review requirements and release approvals still apply.

### Local acceptance

Iterate with the owning Go package test. Final acceptance preserves `go fmt ./...`, `go vet ./...`, `go test ./...` and `go test -race ./...` from
`AGENTS.md`. Exercise affected real sockets/listeners; privileged
installation/CA, Apple Container and Tailscale mutation lanes require their
existing explicit opt-ins and qualified macOS host.

### Serialized integration

1. Use one isolated branch/worktree per change. Preserve dirty user checkouts;
   give parallel work its own ports, databases and output paths. Inspect current
   source and run targeted tests while editing.
2. Obtain independent review of the diff and evidence before integration.
   Auth, payments, permissions, migrations, runtime isolation and release/CI
   changes require the designated owner's review and existing stronger gates.
3. One coordinator owns integration for each repository. Under a shared lock or
   queue, fetch current `main`, rebase one candidate onto it, resolve conflicts
   and validate the exact final tree with the repository's full acceptance gate.
   Record base SHA, candidate SHA/tree, commands, toolchain/platform, results and
   reviewer disposition. Unavailable required checks block landing.
4. Any edit, conflict resolution, rebase or integration changes the candidate and
   invalidates its earlier validation. Repeat applicable/full acceptance and
   refresh review for the final diff. Recheck main before landing; if it moved,
   rebase and validate again. No stale green result or force push.
5. Only with publication authorization and compatible protections, land by a
   normal fast-forward-only update. Otherwise use the required PR/merge-queue
   path and validate its final integration tree. Never bypass hooks, required
   reviews, environments or branch rules. Watch checks for the landed main SHA;
   freeze integration on failure and prepare a reviewed revert/recovery.

### CI and build lifecycle

`.github/workflows/ci.yml` is routine validation; the privileged macOS, Apple
Container and Tailscale workflows are distinct acceptance boundaries. Selective
CI must not quietly skip them for affected changes. Signed/versioned release
assets and rollback binaries are separate from temporary integration evidence.

Selective CI is a target: select changed components and their dependents, keep
an always-present truthful required summary, and retain full platform/security
freshness and every release gate. Reuse only immutable verified outputs whose
source SHA/tree, toolchain, lockfiles, build inputs and platform/variant match;
verify digest/provenance before promotion. A dependency cache hit is not proof
of acceptance, and rebuilding creates a new product requiring validation.

The routine main-build target is **two successful builds per platform/variant**
(OS, architecture and build flavor/channel), counted after trusted successful
qualification. Failed/cancelled runs do not displace a known-good build. Protect
active handoffs, pinned consumers, approved release candidates, diagnostic/audit
exceptions and rollback products until their needs end. Published releases and
registry/image assets have their own compatibility/rollback policy; do not prune
them with disposable CI artifacts. Time-based `retention-days` alone cannot
implement a two-build count. Cleanup must remain inactive/dry-run until separately
approved with the exact candidates and consumer exclusions.

Still to implement: a coordinator/queue shared across agent threads and hosts,
an exact-tree acceptance record with invalidation, protection-aware landing and
main-check monitoring, and consumer-aware retention/reuse where absent. Local
worktree isolation and deployment concurrency do not provide that shared lock.

Background: [The Amp Way](https://ampcode.com/docs/using-amp/how-we-work) and
[Shipping Changes](https://ampcode.com/docs/orbs/shipping). Their delivery model
informs this proposal; their commands/settings are not this repository's policy.
