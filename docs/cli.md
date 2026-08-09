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

The address is a cached implementation detail, not the identity of the route.
The daemon must re-inspect the named owner after a container restart and
atomically replace the upstream when its address changes. Static and
process-owned routes use `refresh=never`; they must never be reinterpreted as
container routes.

## Management protocol

The unprivileged CLI sends one newline-delimited JSON request on one connection
to the permissioned Unix socket and reads one JSON response. Protocol version 1
supports only `install`, `add`, `remove`, `list`, `status`, `doctor`, and
`uninstall`. Each response repeats the request ID. Unknown versions, operations,
owners, refresh policies, fields, or mismatched request IDs fail closed.

The default socket is `/var/run/portless.sock`. `PORTLESS_SOCKET` may point to
an alternate absolute socket for development and integration tests.
`PORTLESS_CONTAINER_CLI` may select an alternate `container` executable for
controlled integration environments. Neither setting changes daemon listener
or route policy.

Running these commands is the explicit mutation boundary. Merely building or
testing the repository never installs a service, changes CA trust, or mutates a
live container.
