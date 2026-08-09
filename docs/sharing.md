# Host sharing foundations

Portless sharing is explicit and independent of route ownership. These packages
accept generic loopback routes; they do not import or depend on a container
runtime. Local-only `.localhost` routing remains the default. LAN, tailnet, and
public exposure happen only when a caller deliberately starts or applies the
corresponding plan.

## LAN names with mDNS

`internal/mdns` publishes one exact, single-label HTTPS name such as
`fieldnotes.local` through macOS `/usr/bin/dns-sd`. `Check` is read-only: it
normalizes the name, validates the port, and requires the selected private
unicast address to be assigned to an up, multicast-capable, non-point-to-point
interface. Loopback, link-local, public, multicast, unspecified, and VPN-style
point-to-point addresses fail closed.

The returned command plan uses DNS-SD proxy registration:

```text
/usr/bin/dns-sd -P fieldnotes _https._tcp local. 443 fieldnotes.local. 192.168.1.20 path=/
```

`Start` is the explicit exposure boundary. It waits for both the hostname
record and service registration to report active before returning. `Refresh`
revalidates the selected address against current interfaces and replaces the
child only when the address changed. `Close` sends `SIGTERM`, waits for DNS-SD
to deregister, bounds shutdown, and is idempotent.

This advertises a name and HTTPS service; the caller remains responsible for
ensuring the selected LAN address and port reach the intended generic route.

## Tailscale Serve and Funnel

`internal/tailscale` supports one application mounted at `/` on each external
HTTPS port. It accepts only explicit `http://127.0.0.1:<port>` backends, so the
Tailscale daemon cannot be directed to arbitrary network or filesystem targets.

`Client.Check` is read-only and runs bounded, noninteractive official CLI
queries. It requires:

- Tailscale 1.98.9 or newer, which contains the Serve/Funnel denial-of-service
  fix in security bulletin TS-2026-008.
- a running, online node with a stable Tailscale DNS name;
- MagicDNS, the node `https` capability, and a certificate domain matching the
  node name; and
- for Funnel, both the live `funnel` capability and a `funnel-ports` capability
  authorizing the selected port.

Missing capabilities fail before mutation. `--yes` is not treated as a consent
bypass: current Tailscale code uses it to suppress deletion prompts, while
missing HTTPS or Funnel authorization can otherwise enter a web-consent flow.

`BuildPlan` accounts for every existing TCP or web port plus caller-reserved
plans. Serve allocates 443, then the first available port from 8443 upward.
Funnel is constrained by the official service to 443, 8443, and 10000, so it
supports at most three root-mounted applications on one node and returns an
exhaustion error after those ports are occupied.

The auditable mutation plans are:

```text
tailscale serve  --bg --yes --https=443 --set-path=/ http://127.0.0.1:3000
tailscale funnel --bg --yes --https=443 --set-path=/ http://127.0.0.1:3000

tailscale serve  --yes --https=443 --set-path=/ off
tailscale funnel --yes --https=443 --set-path=/ off
```

`Apply` rechecks that the allocated port is still unused before registering,
then verifies the exact root target and private/public mode from status.
`Clean` first verifies that the port, path, target, and mode still match the
owned registration, removes only that path, and verifies its disappearance.
It never uses `serve reset` or `funnel reset`, because reset would remove
unrelated configuration. No API invokes `sudo`.

Tailscale's current macOS documentation is inconsistent about Funnel support
between its variant matrix and its dedicated Funnel pages. Portless therefore
does not guess from the application variant: it limits itself to port proxying
and trusts the installed CLI plus live capabilities. File and directory sharing
is not supported by this package.

### Volatile Tailscale sources

The CLI and capability behavior above was verified on 2026-08-08 against:

- [Serve CLI reference](https://tailscale.com/docs/reference/tailscale-cli/serve),
  last validated by Tailscale on 2026-01-26.
- [Funnel CLI reference](https://tailscale.com/docs/reference/tailscale-cli/funnel),
  last validated by Tailscale on 2026-01-26.
- [Funnel requirements and port limits](https://tailscale.com/docs/features/tailscale-funnel).
- [HTTPS enablement](https://tailscale.com/docs/how-to/set-up-https-certificates),
  last validated by Tailscale on 2025-12-10.
- [macOS variants](https://tailscale.com/docs/concepts/macos-variants), last
  validated by Tailscale on 2026-01-05.
- [Tailscale v1.102.2 Serve/Funnel CLI implementation](https://github.com/tailscale/tailscale/blob/v1.102.2/cmd/tailscale/cli/serve_v2.go)
  and [Serve configuration implementation](https://github.com/tailscale/tailscale/blob/v1.102.2/ipn/serve.go).
- [Tailscale security bulletins](https://tailscale.com/security-bulletins),
  including TS-2026-008, published 2026-07-13.

On the validation host, the installed official CLI reported v1.102.2 and
`osVariant=macsys`. Read-only Serve preflight succeeded. Funnel preflight
correctly failed because the node did not advertise Funnel capabilities; no
tailnet or public registration was mutated.

## Managed hosts block

`.localhost` normally needs no hosts-file entry. `internal/hosts` exists for
environments that explicitly require deterministic system resolver entries.
It owns only this block:

```text
# BEGIN PORTLESS MANAGED HOSTS
# Generated by portless; use the portless hosts operation to change this block.
127.0.0.1	fieldnotes.localhost
::1	fieldnotes.localhost
# END PORTLESS MANAGED HOSTS
```

`Render` and `CleanContent` are pure operations. Names are normalized,
deduplicated, sorted, bounded, and limited to exact `.localhost` DNS names.
Unrelated bytes stay in place, malformed or duplicate markers fail closed, and
repeated synchronization is a byte-for-byte no-op.

`DefaultConfig().Check`, `SynchronizePlan`, and `CleanPlan` are read-only.
Plans record the exact paths, ownership, modes, before/after byte counts and
SHA-256 digests, normalized names, and desired content. Applying a plan is an
explicit privileged action by the caller; the package never invokes `sudo`.

Before writing, the package requires clean absolute paths, safe root-owned
parents, regular non-symlink files, exact ownership and modes, and a secure
`0600` lock. It opens with `O_NOFOLLOW`, compares device/inode metadata across
the open, takes a real cross-process `flock`, rejects stale plans or content,
writes and syncs a same-directory temporary file, atomically renames it, and
syncs the parent directory. Tests use temporary hosts files and never mutate
live `/etc/hosts`.
