# Proxy profiles

A proxy profile is one validated public listener, one DNS namespace, one route
resolution policy, and, for HTTPS, one certificate source. The foundation is
runtime agnostic: Docker, Podman, Apple Container, Lima, and ordinary processes
all register the same validated `http` or `https` IP-and-port upstream route.
Runtime discovery and ownership checks stay outside `internal/profile`,
`internal/routes`, and `internal/proxy`.

## Settings and defaults

`profile.Config` explicitly selects:

- `Scheme`: `http` or `https`;
- `ListenAddress`: a literal IPv4 or IPv6 loopback address and a port from 1 to
  65535;
- `TLD`: one ASCII DNS label, normalized to a lowercase dot-prefixed suffix;
- `WildcardFallback`: disabled unless explicitly enabled;
- `Certificates`: either `local-ca` or `files` for HTTPS.

`profile.DefaultConfig()` records the current public default:
`https://<registered-name>.localhost` on `127.0.0.1:443`, exact routing, and a
generated local-CA certificate provider. A caller can create another profile
for `http://<name>.test:8080`, `https://<name>.internal:8443`, or another
loopback-only origin without changing the upstream route contract.

Profiles reject hostnames, unspecified, private, public, multicast, and zoned
IP addresses as listeners. Port zero and out-of-range or non-numeric ports are
invalid. `New` validates all settings and certificate material before `Listen`
can bind. `Serve` rechecks that it received the profile's loopback TCP listener
and uses `http.Server.ServeTLS`, preserving standard-library HTTP/2 negotiation
alongside HTTP/1.1 WebSocket/HMR upgrades.

The matching route table is created from `Profile.RouteOptions()`. Pass
`Profile.Port()` as `proxy.Options.PublicPort` so rewritten upstream redirects
and `X-Forwarded-Host` contain the configured non-default port. The default
zero proxy option retains the existing implicit ports.

## Certificate sources

HTTPS always requires the matching configured route table. `profile.New`
rejects a table whose TLD or fallback setting differs from the profile. TLS
selection normalizes SNI under that TLD and requires `routes.Table.Resolve` to
select a registered exact route or permitted parent before choosing a
certificate. The HTTPS handler also requires normalized HTTP authority and SNI
to match, returning 421 when they differ.

File mode requires distinct clean absolute paths. The final path components
must be regular files rather than symlinks, neither file may be writable by its
group or others, and the private key may not be readable or executable by its
group or others. Before a listener binds, the profile parses the pair, proves
the public and private keys match, and rejects CA, expired, not-yet-valid, or
non-server certificates. During selection it verifies that the certificate SAN
covers the requested registered hostname. File mode can use a certificate with
the exact and wildcard SANs required by a fallback policy.

Local-CA mode takes a generated certificate callback such as
`pki.Authority.GetCertificate`. The authority should use the profile suffix and
the same exact route table for its registered-host predicate. Generated
local-CA mode is currently restricted to exact routing: the existing authority
persists one exact leaf per SNI and does not yet impose a durable leaf-count
bound, so accepting arbitrary
descendants would permit unbounded certificate-file growth. Wildcard fallback
can be used with plain HTTP or a fixed custom certificate; lifting this
restriction requires a durable PKI cache bound.

## Registered-parent fallback

Fallback is a resolution policy, not a wildcard route entry. Given registered
routes for `app.test` and `api.app.test`:

| Request | Selected route |
| --- | --- |
| `api.app.test` | exact `api.app.test` |
| `v1.api.app.test` | longest parent `api.app.test` |
| `assets.app.test` | parent `app.test` |
| `missing.test` | none |
| `app.localhost` | invalid for the `.test` profile |
| `app.test.example` | invalid for the `.test` profile |

The requested child authority remains the public origin for forwarding headers,
redirect rewriting, and certificate hostname checks. Only the selected route's
validated upstream endpoint is inherited from its registered parent.

## Daemon integration and persistence

`internal/daemon` composes `Profile` for a custom listener, constructs the
matching route table, passes the public port to redirect rewriting, selects the
generated authority or validated certificate files, and serves through
`Profile.Listen` and `Profile.Serve`. Plain HTTP profiles use the same route
table without TLS configuration.

The normalized configuration is stored as strict owner-only `profile.json`.
An explicitly different scheme, listener, TLD, wildcard policy, or certificate
source fails before route state is reinterpreted. A non-legacy persisted profile
is loaded when the service starts without explicit profile flags. The legacy
default remains a deliberate compatibility composition for dual-stack 80/443.
