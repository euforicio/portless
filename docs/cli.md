# CLI contract

## Commands

```text
portless init [--management-group GROUP]
              [--scheme http|https] [--listen LOOPBACK:PORT] [--tld TLD]
              [--cert FILE --key FILE] [--wildcard]
portless run [--name NAME] [--app-port PORT] [--force]
             [--lan] [--tailscale|--funnel] -- COMMAND [ARGS...]
portless NAME COMMAND [ARGS...]
portless
portless alias|add NAME --host IP --port PORT [--protocol http|https] [--force]
portless add NAME --container ID [--port PORT] [--protocol http|https] [--force]
portless remove NAME [--force]
portless list
portless proxy start [--foreground] [daemon profile flags]
portless proxy stop|status
portless service install|status|uninstall
portless trust status|install|remove
portless hosts sync|clean [--apply]
portless prune
portless clean [--routes --yes]
portless doctor|refresh|version
```

Bare `portless` requires a validated `portless.json`. The shorthand treats the
first unknown command token as the route name and every remaining token as the
direct child argv. No form accepts a shell command string.

`run` starts a real child in a dedicated process group, registers its exact
PID/start identity through the daemon, and conditionally removes the route on
exit. Nonzero exits and signal exits retain their conventional status. A
fixed `--app-port` or config `appPort` is checked before exec; otherwise a real
IPv4 loopback port is reserved and handed off immediately before exec.

`--force` is intentionally narrower for a runner than for a static alias. A
runner takeover requires matching durable runner state, current daemon route,
endpoint, UID, PID, start identity, and process group. It terminates that exact
group and replaces the route with an owner compare-and-set. `alias --force` is
the explicit administrative unconditional replacement boundary.

## Generic routes

Static aliases accept literal loopback or RFC-private unicast addresses. Public,
unspecified, multicast, and link-local targets are rejected. A host port
published by any container or VM runtime is therefore just:

```sh
portless alias api --host 127.0.0.1 --port 8080
portless alias vm-api --host 192.168.64.8 --port 8080
```

Apple Container discovery is optional. Only the explicit `--container` path
executes an Apple `container inspect`; its daemon-side reinspection and
login-UID protections remain intact. The service manifest omits the adapter
entirely when no absolute executable was configured.

## Management protocol v2

One bounded newline-delimited JSON request and response use a kernel-authenticated
Unix connection. Protocol v2 requires every add/remove to declare one match:

- `absent`: safe create;
- `owner`: replace or remove only the exact daemon-canonical owner;
- `any`: an explicit administrative force boundary.

Process add responses return the daemon-filled start identity. Owner matching
and registry persistence happen under the same mutation lock, so concurrent
cleanup cannot remove a newer owner. Unknown protocol versions, operations,
fields, match modes, owners, extra frames, or mismatched request IDs fail
closed. Version 1 is not accepted.

## Privilege

`init` is invoked as the ordinary user. A healthy same-version daemon and
doctor result causes an immediate no-sudo return. Otherwise `init` uses only
fixed `/usr/bin/sudo` to run the root lifecycle command and performs the final
readiness and doctor calls itself.

Routine route, runner, refresh, prune, and Tailscale operations never invoke
sudo. `hosts` defaults to a read-only auditable plan; `--apply` requires an
already-privileged process. Trust install/remove and service uninstall are
similarly explicit.

## Profiles and sharing

The default profile remains exact HTTPS `.localhost` on loopback 443 with
loopback 80 redirects. Foreground daemon/profile flags are `--scheme`,
`--listen`, `--tld`, `--cert`, `--key`, and `--wildcard`. Custom settings are
persisted in `profile.json`; a later daemon with no explicit profile loads that
persisted non-legacy profile, while an explicitly incompatible profile fails.
The same flags on `init` persist an installed-service profile in its launchd
manifest. A deliberate replacement carries an auditable reconcile marker and
is accepted only when `routes.json` is empty, preventing namespace
reinterpretation. HTTP or certificate-file profiles remove unused generated-CA
trust and child metadata; generated-CA profiles install them.

Tailscale Serve/Funnel run flags perform live read-only preflight, exact apply,
verification, and exact cleanup. `--lan` fails closed until Portless can pair
the existing real `dns-sd` publisher with an eligible LAN listener and a
certificate valid for the advertised `.local` name.
