# Proxy and route core

The proxy resolves the normalized HTTP `Host` or HTTP/2 `:authority` value
against an exact route. Route names are lowercase ASCII DNS names below
`.localhost`; wildcards, suffix matching, IP literals, userinfo, malformed
ports, and non-DNS input are rejected.

Upstreams are absolute `http` or `https` URLs with an explicit IP address and
port. Only loopback and private unicast addresses are accepted.
Paths, queries, fragments, credentials, hostnames, unspecified addresses,
multicast addresses, and public addresses are rejected. Container ownership is
validated by the Apple-container integration before it registers a route; the
route package enforces the network and URL boundary but cannot establish
container identity by itself.

`routes.Table` supports concurrent exact lookup, add/replace, delete, sorted
snapshot listing, and whole-table replacement. Route values are immutable and
whole-table replacements validate before swapping the active map.

## Forwarding behavior

The proxy uses `httputil.ReverseProxy.Rewrite`. It sends the validated upstream
authority as the backend `Host`, preserves the request path, escaped path,
query, and streaming body, and recreates these trusted headers after discarding
client-supplied forwarding data:

- `X-Forwarded-For`: the immediate client IP
- `X-Forwarded-Host`: the canonical registered route name
- `X-Forwarded-Proto`: `http` or `https` from the frontend connection

`Forwarded`, every client-supplied `X-Forwarded-*` field, and `X-Real-IP` are
not trusted. The default transport ignores proxy environment variables, does
not transparently decompress upstream responses, and supports HTTP/1.1 plus
HTTP/2 over TLS. Streaming responses flush immediately. Backend `Alt-Svc` is
removed so an internal endpoint cannot advertise itself as the public local
origin. Absolute and network-path redirects that exactly identify the selected
upstream endpoint are rewritten to the public route; relative and external
redirects are preserved.

Unknown routes return 404, malformed authorities return 400, and `CONNECT`
returns 405. An outbound hop marker causes a recursive route to terminate with
508 on its first return through this proxy. Transport failures return a generic
502 without exposing dial details. Absolute-form, opaque, and userinfo-bearing
request targets are rejected before upstream rewriting.

Ordinary HTTP/1.1 WebSocket upgrades use the standard library's 101-response
hijack and bidirectional-copy path. Tests exercise HMR-shaped query and text
traffic, fragmented frames, close frames, and abrupt disconnects over real TCP
connections.

## RFC 8441 decision

No third-party dependency is justified for the current scope. RFC 8441 changes
the WebSocket handshake to an HTTP/2 extended `CONNECT` with a `:protocol`
pseudo-header and a 200 response; it is not the HTTP/1.1 `Upgrade`/101
handshake. See [RFC 8441 sections 3 and
5](https://www.rfc-editor.org/rfc/rfc8441.html#section-3).

Go 1.26.5 contains HTTP/2 framing for extended CONNECT, but its server keeps
`SETTINGS_ENABLE_CONNECT_PROTOCOL` disabled by default. The source explains
that advertising it makes browsers attempt HTTP/2 WebSockets even though
ordinary server WebSocket handlers do not support that handshake. The only
current enablement is the undocumented `GODEBUG=http2xconnect=1` switch; the
public API proposal remains open. Evidence:

- [Go 1.26.5 default-off extended CONNECT implementation](https://github.com/golang/go/blob/go1.26.5/src/net/http/h2_bundle.go#L3488-L3507)
- [Go compatibility analysis and default-disable decision](https://github.com/golang/go/issues/71128#issuecomment-2578287798)
- [Open public API proposal](https://github.com/golang/go/issues/53208)
- [`ReverseProxy` HTTP/1.1 upgrade implementation](https://github.com/golang/go/blob/go1.26.5/src/net/http/httputil/reverseproxy.go#L820-L879)

Portless therefore does not advertise extended CONNECT and rejects `CONNECT`.
Ordinary HTTP/2 request/response routing and ordinary HTTP/1.1 WebSocket/HMR
traffic are supported and tested. RFC 8441 should be reconsidered only if it
becomes a product acceptance criterion; that work would require a supported
HTTP/2 configuration API plus real browser, proxy, upstream, cancellation, and
flow-control tests, including translation to ordinary HTTP/1.1 WebSocket
backends.
