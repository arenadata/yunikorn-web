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
	"embed"
	"io/fs"
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
	origin, err := url.Parse(conf.K8Shim.URL)
	if err != nil {
		return nil, err
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(origin)
			pr.SetXForwarded()
			// The user's credentials never travel to k8shim: the web -> k8shim
			// leg authenticates itself with a token signed from the
			// authenticated request identity using the k8shim shared secret.
			pr.Out.Header.Del("Authorization")
			if conf.K8Shim.SharedSecret != "" {
				if id := identity.FromHTTPRequestContext(pr.In); id != nil {
					token := webservice.SignToken(conf.K8Shim.SharedSecret,
						id.UserName(), identityGroups(id), time.Now().Add(5*time.Minute))
					pr.Out.Header.Set("Authorization", "Token "+token)
				}
			}
		},
	}

	if conf.K8Shim.TLS != nil {
		tlsConfig, err := conf.K8Shim.TLS.TLSConfig()
		if err != nil {
			return nil, err
		}
		proxy.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}
	return proxy, nil
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
