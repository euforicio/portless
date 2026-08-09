# Generic process runner

`internal/runner` and `internal/projectconfig` provide the framework-independent
foundation for running a local command behind a stable Portless HTTPS name.
They do not inspect package managers, JavaScript metadata, workspaces,
frameworks, or containers. A container-published host port is an ordinary
host/port alias outside the process runner.

## Project configuration

The optional `portless.json` format is a strict JSON object:

```json
{
  "name": "fieldnotes",
  "command": ["go", "run", "./cmd/server"],
  "appPort": 3000,
  "proxy": true,
  "env": {
    "LOG_LEVEL": "debug"
  }
}
```

- `command` is required and must be a non-empty argv array. Portless executes
  the executable directly and never parses or executes a shell string.
- `name` is optional. It accepts one Portless DNS label, with an optional
  `.localhost` suffix.
- `proxy` defaults to `true`. When false, `appPort` must be omitted or zero and
  no route endpoint environment is injected.
- `appPort` is an optional fixed TCP port. Zero or omission asks the runner to
  allocate a free IPv4 loopback port.
- `env` is an optional string map. Keys must be portable environment names.

The reader rejects relative paths, symlinks, non-regular files, oversized
input, unknown or duplicate fields, duplicate environment keys, trailing JSON,
invalid names, invalid ports, NUL bytes, and excessive argv or environment
data. It has no `package.json` fallback.

Name resolution has a fixed precedence: explicit flag, configuration, the
verified Git worktree/root directory, then the current directory. Git discovery
uses a direct `git -C <directory> rev-parse --show-toplevel` argv invocation,
not a shell. Directory names are lowercased and punctuation runs become `-`.
Names longer than one DNS label fail and require an explicit name; they are not
silently truncated.

## Execution and environment

`runner.Open` creates or validates a caller-selected absolute state directory.
`Manager.Start` launches one direct argv command in its own process group and
returns a `Process` after recording its kernel identity. `Manager.Run` adds
signal forwarding and waits. Callers can use `Process.Identity` to register the
same PID/start identity as a process-owned daemon route and `Process.Endpoint`
to obtain its loopback target.

For a proxied run, the runner reserves `127.0.0.1:<port>` with a real TCP
listener, releases it immediately before `exec`, and injects:

| Variable | Value |
| --- | --- |
| `PORT` | allocated or fixed application port |
| `HOST` | `127.0.0.1` |
| `PORTLESS_URL` | `https://<name>.localhost` |

These keys and `NODE_EXTRA_CA_CERTS` are runner-managed and cannot be supplied
through the per-run environment map. Because an arbitrary application cannot
inherit and bind the same reserved listener, a small close-before-exec race is
unavoidable. The reservation prevents runner-to-runner conflicts within one
state registry and detects a busy fixed port, but the child remains responsible
for reporting a bind failure if another process claims the port during that
handoff.

`NODE_EXTRA_CA_CERTS` is compatibility metadata, not a Node.js requirement or
runtime inference. It is injected only for a proxied run when the caller
explicitly supplies an absolute, real CA certificate file. The runner never
examines argv to guess a runtime.

## Supervision and identity safety

Every child has `PGID == PID`. Darwin process inspection records PID, process
start time, UID, and process group from one `kern.proc.pid` snapshot. Before
each forwarded `SIGTERM`, `SIGKILL`, or caller-provided Unix signal, the runner
repeats that inspection and fails closed if any value changed. Darwin does not
offer an atomic kill-by-start-time primitive, so the final kernel snapshot is
kept immediately adjacent to the group signal.

Context cancellation sends `SIGTERM` to the verified group, waits the configured
grace period (five seconds by default), revalidates, and then sends `SIGKILL`.
`Wait` always reaps the child and removes only a state record with the same
name and exact identity. A normal non-zero exit returns both `Result` and the
underlying `*exec.ExitError`. A signal exit has `ExitCode == -1`, `Signaled ==
true`, and the exact signal; a CLI can map that to the conventional
`128 + signal` status if desired.

If starting the child succeeds but durable registration fails, the runner
kills and reaps that exact child before returning the error. It never leaves a
successfully started but untracked process behind.

## Durable discovery, pruning, and takeover

Runner state is versioned, count- and size-bounded JSON in `runner.json` with a
cross-process `runner.lock`. The directory must be `0700`; both files are
`0600`, owned by the current effective UID, opened without following symlinks,
and state replacement is write/sync/rename/directory-sync atomic.

Records contain both child and supervisor PID/start/UID identity. `Discover`
classifies them as:

- `active`: the exact child and supervisor both exist;
- `orphaned`: the exact child exists but its original supervisor does not;
- `stale`: the child PID/start/UID/process-group identity no longer exists.

Unknown kernel inspection errors fail closed. `Prune` removes only definitely
stale records and never signals a process. A live orphan remains discoverable
for an explicit, identity-checked takeover.

`ForceTakeover` requires a complete, currently observed process-owned
`client.Route`. It verifies the canonical route name, endpoint host and port,
durable child PID/start identity, live UID, and dedicated process group before
signaling. Missing, static, endpoint-mismatched, stale, or identity-mismatched
routes cannot authorize a kill. Durable runner state alone is never sufficient,
so an unrelated process is not killed after PID reuse or state corruption.

Management protocol version 1 still replaces and removes daemon routes by name
without expected-owner compare-and-set semantics. The runner can therefore
make process signaling identity-safe, but a future CLI integration that wants
atomic route takeover or cleanup must first add expected-owner conditional
mutation to the management protocol. This package does not work around that
boundary with an unsafe unconditional route mutation.
