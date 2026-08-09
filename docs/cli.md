# CLI and Apple container integration

The command surface is intentionally small:

```text
portless install
portless add NAME --port PORT [--pid PID] [--protocol http|https]
portless add NAME --container ID [--port PORT] [--protocol http|https]
portless remove NAME
portless list
portless status
portless doctor
portless refresh
portless uninstall
```

`NAME` is one DNS label. The CLI accepts either `fieldnotes` or
`fieldnotes.localhost` and sends the canonical `fieldnotes.localhost` name to
the daemon. Local routes default to `127.0.0.1`; `--host` can select another
loopback IP. A local route without `--pid` is static. `--pid` makes it
process-owned, which lets the daemon remove it when that process is no longer
alive.

For an Apple container route, the CLI executes `container inspect ID` directly,
requires a running container, selects a declared TCP container port, and
extracts reachable unicast addresses from the running network status. `--port`
is optional only when exactly one published TCP port is declared. An explicit
`--port` is treated as the operator's declaration for a direct listener because
Apple does not expose image `EXPOSE` metadata and direct listeners need not use
host port publishing. Stopped containers, missing or ambiguous ports, UDP-only
declarations, malformed identifiers, and missing addresses fail before a
management request is sent.

Container routes are sent with both the currently resolved address and owner
metadata:

```text
owner.kind      = container
owner.container = the stable Apple container ID
owner.network   = the first attached Apple network
owner.refresh   = container-address
```

The daemon adds an `inspector_uid` from the connection's kernel credentials;
the client cannot choose it. Container routes must be registered by the
unprivileged login user that owns the Apple container catalog. The daemon
re-resolves that UID on every inspection, enters its launchd bootstrap domain,
drops privileges, and executes the configured absolute CLI with a minimal
environment. This keeps same-named containers in different login sessions
unambiguous and never runs a Homebrew-owned executable as root.

The address is a cached implementation detail, not the identity of the route.
The daemon must re-inspect the named owner after a container restart and
atomically replace the upstream when its address changes. Static and
process-owned routes use `refresh=never`; they must never be reinterpreted as
container routes.

The daemon repeats the inspection on add instead of trusting the CLI-provided
address or network. If the two observations differ, add returns
`stale_metadata` and the operator retries. Periodic and explicit refreshes use
the stable container ID and declared port. Failed inspection disables the
active route without discarding the registration, so a later successful
inspection restores it without routing to the stale address.

Process-owned routes are similarly canonicalized by the daemon. A non-root
peer may register only a process owned by its kernel UID. The daemon records the
Darwin process start time and removes the registration when that exact process
identity disappears.

## Management protocol

The unprivileged CLI sends one newline-delimited JSON request on one connection
to the permissioned Unix socket and reads one JSON response. Protocol version 1
supports `add`, `remove`, `list`, `status`, `doctor`, and `refresh`. The reserved
`install` and `uninstall` operation values are rejected by the daemon with
`privilege_required`; lifecycle work is never delegated to the management
group. Each response repeats the valid request ID. Unknown versions,
operations, owners, refresh policies, fields, oversized frames, extra frames,
or mismatched request IDs fail closed. The server authenticates kernel peer
credentials before decoding and applies one total request deadline.

The default socket is `/var/run/portless/management.sock`. `PORTLESS_SOCKET` may point to
an alternate absolute socket for development and integration tests.
`PORTLESS_CONTAINER_CLI` may select an alternate `container` executable for
controlled integration environments. Neither setting changes daemon listener
or route policy.

Running these commands is the explicit mutation boundary. Merely building or
testing the repository never installs a service, changes CA trust, or mutates a
live container.

## Privileged lifecycle

`sudo portless install` and `sudo portless upgrade` are out-of-band bootstrap
commands that work before the socket exists. They reconcile the binary and
plist, create and trust the exact local CA, apply the fixed launchctl plan, and
wait for daemon readiness. `sudo portless uninstall` stops launchd, removes the
exact trusted CA and installed artifacts, and retains state for recovery. No
package invokes `sudo`; privilege is supplied explicitly by the operator.
