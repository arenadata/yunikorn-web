/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package webserver

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/apache/yunikorn-core/pkg/webservice"

	"github.com/go-krb5/x/identity"
)

//go:embed dist/*
var documentRoot embed.FS

const (
	// k8ShimUnixScheme marks a K8Shim.URL pointing at a unix socket file
	// instead of a TCP endpoint, e.g. unix:///var/run/yunikorn/k8shim.sock.
	k8ShimUnixScheme = "unix"
	// k8ShimUnixHost is the placeholder authority used for requests sent over
	// the unix socket: the dialer ignores the address, but the outbound
	// request still needs a syntactically valid host.
	k8ShimUnixHost = "localhost"
)

// NewWebServer builds the web UI server on top of the shared core webservice
// server: the /ws/ routes forward requests to the k8shim REST API, everything
// else is served from the embedded static UI.
func NewWebServer(conf *webservice.Config) (*webservice.WebServer, error) {
	staticRoute, err := staticUIRoute()
	if err != nil {
		return nil, err
	}

	proxy, err := newK8ShimProxy(conf)
	if err != nil {
		return nil, err
	}

	routes := append(proxyRoutes(proxy), staticRoute)
	return webservice.NewWebServer(conf, conf.ListenAddress, routes), nil
}

// staticUIRoute serves the embedded static UI for every path not taken by
// another route (the root catch-all pattern is the fallback route of the
// shared web server).
func staticUIRoute() (webservice.Route, error) {
	staticFS, err := fs.Sub(documentRoot, "dist")
	if err != nil {
		return webservice.Route{}, err
	}
	return webservice.Route{
		Name:        webservice.RouteNameStaticUI,
		Method:      http.MethodGet,
		Pattern:     "/*filepath",
		HandlerFunc: http.FileServer(http.FS(staticFS)).ServeHTTP,
	}, nil
}

// proxyRoutes mirrors the /ws/ routes of the scheduler REST API with the proxy
// as the handler, so the route names (and with them the role based
// authorization) stay identical on both sides.
func proxyRoutes(proxy http.Handler) []webservice.Route {
	var routes []webservice.Route
	for _, rt := range webservice.Routes() {
		if !strings.HasPrefix(rt.Pattern, "/ws/") {
			continue
		}
		routes = append(routes, webservice.Route{
			Name:        rt.Name,
			Method:      rt.Method,
			Pattern:     rt.Pattern,
			HandlerFunc: proxy.ServeHTTP,
		})
	}
	return routes
}

// newK8ShimProxy builds the reverse proxy towards the k8shim REST API.
func newK8ShimProxy(conf *webservice.Config) (*httputil.ReverseProxy, error) {
	origin, socketPath, err := parseK8ShimURL(conf.K8Shim.URL)
	if err != nil {
		return nil, err
	}
	if len(socketPath) > 0 && conf.K8Shim.TLS != nil {
		// the k8shim socket listener speaks plain HTTP: the socket file
		// permissions are the access control on that leg, so silently dropping
		// the configured client certificates would be a surprise
		return nil, fmt.Errorf("k8shim TLS is not supported with a unix socket URL %q", conf.K8Shim.URL)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(origin)
			pr.SetXForwarded()
			// The user's credentials never travel to k8shim: the web -> k8shim
			// leg authenticates itself with a token signed from the
			// authenticated request identity using the k8shim shared secret.
			pr.Out.Header.Del("Authorization")
			if len(conf.K8Shim.SharedSecret) > 0 {
				if id := identity.FromHTTPRequestContext(pr.In); id != nil {
					token := webservice.SignToken(conf.K8Shim.SharedSecret,
						id.UserName(), identityGroups(id), time.Now().Add(5*time.Minute))
					pr.Out.Header.Set("Authorization", "Token "+token)
				}
			}
		},
	}

	switch {
	case len(socketPath) > 0:
		// every connection goes to the socket file, whatever host the rewritten
		// request carries
		dialer := new(net.Dialer)
		proxy.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, k8ShimUnixScheme, socketPath)
			},
		}
	case conf.K8Shim.TLS != nil:
		tlsConfig, err := conf.K8Shim.TLS.TLSConfig()
		if err != nil {
			return nil, err
		}
		proxy.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}
	return proxy, nil
}

// parseK8ShimURL validates the configured k8shim address and splits it into
// the origin requests are rewritten to and, for unix URLs, the socket file to
// dial. The returned socket path is empty for the TCP schemes.
func parseK8ShimURL(raw string) (*url.URL, string, error) {
	origin, err := url.Parse(raw)
	if err != nil {
		return nil, "", fmt.Errorf("invalid k8shim URL %q: %w", raw, err)
	}

	switch origin.Scheme {
	case "http", "https":
		if origin.Host == "" {
			return nil, "", fmt.Errorf("invalid k8shim URL %q: missing host", raw)
		}
		return origin, "", nil
	case k8ShimUnixScheme:
		// unix:///run/k8shim.sock and unix:/run/k8shim.sock both name an
		// absolute socket path; an authority is the first segment of a
		// relative one (unix://k8shim.sock), as is an opaque part
		// (unix:k8shim.sock)
		socketPath := origin.Opaque
		if len(socketPath) == 0 {
			socketPath = origin.Host + origin.Path
		}
		if len(socketPath) == 0 {
			return nil, "", fmt.Errorf("invalid k8shim URL %q: missing socket path", raw)
		}
		return &url.URL{Scheme: "http", Host: k8ShimUnixHost}, socketPath, nil
	default:
		return nil, "", fmt.Errorf("unsupported k8shim URL scheme %q: want http, https or unix", origin.Scheme)
	}
}

// identityGroups extracts the groups attribute from a request identity.
func identityGroups(id identity.Identity) []string {
	attrs := id.Attributes()
	if attrs == nil {
		return nil
	}
	switch v := attrs["groups"].(type) {
	case []string:
		return v
	case []any:
		groups := make([]string, 0, len(v))
		for _, gi := range v {
			if s, ok := gi.(string); ok {
				groups = append(groups, s)
			}
		}
		return groups
	}
	return nil
}
