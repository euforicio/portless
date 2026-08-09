// Package proxy routes HTTP traffic to validated local upstreams.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/euforicio/portless/internal/routes"
)

const loopHeader = "X-Portless-Proxy-Hop"

var ErrNilRoutes = errors.New("proxy requires a route table")

// Options contains the small set of proxy integration hooks. A nil Transport
// uses a dedicated transport that does not honor proxy environment variables.
// ErrorLog may be nil.
type Options struct {
	Transport http.RoundTripper
	ErrorLog  *log.Logger
	// PublicPort is the configured frontend port used when rewriting absolute
	// upstream redirects. Zero preserves the standard port behavior.
	PublicPort uint16
}

// Handler is safe for concurrent use. Route changes take effect on the next
// request without rebuilding the handler.
type Handler struct {
	routes     *routes.Table
	proxy      *httputil.ReverseProxy
	publicPort uint16
}

type requestContextKey struct{}

type requestContext struct {
	route           routes.Route
	publicAuthority string
	publicScheme    string
}

// New constructs a streaming reverse proxy backed by table.
func New(table *routes.Table, options Options) (*Handler, error) {
	if table == nil {
		return nil, ErrNilRoutes
	}

	transport := options.Transport
	if transport == nil {
		transport = newTransport()
	}

	reverseProxy := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1 * time.Nanosecond,
		ErrorLog:      options.ErrorLog,
		Rewrite: func(request *httputil.ProxyRequest) {
			requestData := request.In.Context().Value(requestContextKey{}).(requestContext)
			target := requestData.route.Target()
			request.SetURL(&target)
			for name := range request.Out.Header {
				if strings.HasPrefix(strings.ToLower(name), "x-forwarded-") {
					request.Out.Header.Del(name)
				}
			}
			request.Out.Header.Del("X-Real-Ip")
			request.SetXForwarded()
			request.Out.Header.Set("X-Forwarded-Host", requestData.publicAuthority)
			request.Out.Header.Set(loopHeader, "1")
		},
		ModifyResponse: func(response *http.Response) error {
			// An internal service must not advertise protocols or endpoints to
			// the browser as though it were the public-facing local proxy.
			response.Header.Del("Alt-Svc")
			rewriteLocation(response)
			return nil
		},
		ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, err error) {
			if options.ErrorLog != nil {
				options.ErrorLog.Printf("proxy upstream error: %v", err)
			}
			http.Error(writer, "bad gateway", http.StatusBadGateway)
		},
	}

	return &Handler{routes: table, proxy: reverseProxy, publicPort: options.PublicPort}, nil
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodConnect {
		http.Error(writer, "CONNECT is not supported", http.StatusMethodNotAllowed)
		return
	}
	if request.Header.Get(loopHeader) == "1" {
		http.Error(writer, "proxy loop detected", http.StatusLoopDetected)
		return
	}
	if request.URL == nil || request.URL.IsAbs() || request.URL.Opaque != "" || request.URL.User != nil {
		http.Error(writer, "invalid request target", http.StatusBadRequest)
		return
	}

	authority, err := h.routes.NormalizeAuthority(request.Host)
	if err != nil {
		http.Error(writer, "invalid host", http.StatusBadRequest)
		return
	}
	route, ok := h.routes.Resolve(authority)
	if !ok {
		http.Error(writer, "unknown host", http.StatusNotFound)
		return
	}

	ctx := contextWithRoute(request, route, authority, h.publicPort)
	h.proxy.ServeHTTP(writer, request.WithContext(ctx))
}

// CloseIdleConnections closes idle connections held by the upstream transport.
func (h *Handler) CloseIdleConnections() {
	if closer, ok := h.proxy.Transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func newTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	transport.Protocols = protocols
	return transport
}

func contextWithRoute(request *http.Request, route routes.Route, publicHost string, publicPort uint16) context.Context {
	publicScheme := "http"
	if request.TLS != nil {
		publicScheme = "https"
	}
	publicAuthority := publicHost
	if publicPort != 0 && !isDefaultPort(publicScheme, publicPort) {
		publicAuthority = fmt.Sprintf("%s:%d", publicHost, publicPort)
	}
	value := requestContext{route: route, publicAuthority: publicAuthority, publicScheme: publicScheme}
	return context.WithValue(request.Context(), requestContextKey{}, value)
}

func isDefaultPort(scheme string, port uint16) bool {
	return (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}

func rewriteLocation(response *http.Response) {
	if response.Request == nil {
		return
	}
	requestData, ok := response.Request.Context().Value(requestContextKey{}).(requestContext)
	if !ok {
		return
	}
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil || location.Host == "" || location.User != nil {
		return
	}
	target := requestData.route.Target()
	if !sameEndpoint(location, &target) {
		return
	}
	location.Scheme = requestData.publicScheme
	location.Host = requestData.publicAuthority
	response.Header.Set("Location", location.String())
}

func sameEndpoint(candidate, target *url.URL) bool {
	candidateScheme := candidate.Scheme
	if candidateScheme == "" {
		candidateScheme = target.Scheme
	}
	if !strings.EqualFold(candidateScheme, target.Scheme) {
		return false
	}
	candidateAddr, candidateErr := netip.ParseAddr(candidate.Hostname())
	targetAddr, targetErr := netip.ParseAddr(target.Hostname())
	if candidateErr != nil || targetErr != nil || candidateAddr.Unmap() != targetAddr.Unmap() {
		return false
	}
	return effectivePort(candidate, candidateScheme) == effectivePort(target, target.Scheme)
}

func effectivePort(value *url.URL, scheme string) string {
	if port := value.Port(); port != "" {
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 {
			return ""
		}
		return strconv.FormatUint(number, 10)
	}
	if strings.EqualFold(scheme, "http") {
		return "80"
	}
	if strings.EqualFold(scheme, "https") {
		return "443"
	}
	return ""
}
