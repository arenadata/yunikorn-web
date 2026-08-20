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

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apache/yunikorn-core/pkg/webservice"

	"github.com/go-krb5/x/identity"
	"gotest.tools/v3/assert"
)

// Route patterns of the scheduler REST API, one per authorization category.
const (
	clusterPath   = "/ws/v1/clusters"   // RouteNameCluster
	schedulerPath = "/ws/v1/partitions" // RouteNameScheduler
	metricsPath   = "/ws/v1/metrics"    // RouteNameMetrics
)

// loadConfig builds the webservice configuration the same way the deployed
// services do: from YUNIKORN_* environment variables. All pre-existing
// YUNIKORN_* variables are cleared first so servers within one test never
// inherit each other's settings.
func loadConfig(t *testing.T, env map[string]string) *webservice.Config {
	t.Helper()
	for _, kv := range os.Environ() {
		if k, _, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(k, "YUNIKORN_") {
			t.Setenv(k, "") // registers restoration of the original value
			_ = os.Unsetenv(k)
		}
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	cfg, err := webservice.LoadConfig()
	assert.NilError(t, err)
	return cfg
}

// startCoreServer starts the shared core webservice server (the same stack the
// k8shim runs on :9080) on a free localhost port and returns its base URL.
func startCoreServer(t *testing.T, env map[string]string, rts []webservice.Route) string {
	t.Helper()
	cfg := loadConfig(t, env)
	return startServer(t, cfg, rts)
}

// startMetricsServer mirrors the k8shim metrics-only listener: the core
// webservice server with a single /metrics route and the YUNIKORN_METRICS_AUTH_*
// override applied (see k8shim pkg/shim/metrics_server.go).
func startMetricsServer(t *testing.T, env map[string]string) string {
	t.Helper()
	cfg := loadConfig(t, env).MetricsConfig()
	metricsRoute := webservice.Route{
		Name:        webservice.RouteNameMetrics,
		Method:      http.MethodGet,
		Pattern:     "/metrics",
		HandlerFunc: identityEcho,
	}
	return startServer(t, cfg, []webservice.Route{metricsRoute})
}

func startServer(t *testing.T, cfg *webservice.Config, rts []webservice.Route) string {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	srv := webservice.NewWebServer(cfg, addr, rts)
	srv.Start()
	t.Cleanup(func() { _ = srv.Stop() })
	waitTCP(t, addr)

	scheme := "http"
	if tlsCfg, err := cfg.TLSConfig(); err == nil && tlsCfg != nil {
		scheme = "https"
	}
	return scheme + "://" + addr
}

// echoRoutes returns the real scheduler REST API route table (names, methods
// and patterns) with the handlers replaced by identityEcho, so tests can
// observe the authenticated identity that reached the handler.
func echoRoutes() []webservice.Route {
	rts := webservice.Routes()
	for i := range rts {
		rts[i].HandlerFunc = identityEcho
	}
	return rts
}

// echoResponse is what identityEcho reports back about the request it served:
// the authenticated identity and the request itself, so proxy tests can assert
// what actually arrived at the k8shim.
type echoResponse struct {
	User          string   `json:"user"`
	Groups        []string `json:"groups"`
	Authorization string   `json:"authorization"`
	Authenticated bool     `json:"authenticated"`

	Method         string `json:"method"`
	Path           string `json:"path"`
	RawQuery       string `json:"rawQuery"`
	Host           string `json:"host"`
	Body           string `json:"body"`
	ForwardedFor   string `json:"forwardedFor"`
	ForwardedHost  string `json:"forwardedHost"`
	ForwardedProto string `json:"forwardedProto"`
}

func identityEcho(w http.ResponseWriter, r *http.Request) {
	resp := echoResponse{
		Authorization:  r.Header.Get("Authorization"),
		Method:         r.Method,
		Path:           r.URL.Path,
		RawQuery:       r.URL.RawQuery,
		Host:           r.Host,
		ForwardedFor:   r.Header.Get("X-Forwarded-For"),
		ForwardedHost:  r.Header.Get("X-Forwarded-Host"),
		ForwardedProto: r.Header.Get("X-Forwarded-Proto"),
	}
	if body, err := io.ReadAll(r.Body); err == nil {
		resp.Body = string(body)
	}
	if id := identity.FromHTTPRequestContext(r); id != nil {
		resp.User = id.UserName()
		resp.Authenticated = id.Authenticated()
		if attrs := id.Attributes(); attrs != nil {
			switch g := attrs["groups"].(type) {
			case []string:
				resp.Groups = g
			case []any:
				for _, gi := range g {
					if s, ok := gi.(string); ok {
						resp.Groups = append(resp.Groups, s)
					}
				}
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NilError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func waitTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("server %s did not start listening", addr)
}

// signToken signs a webservice auth token; a negative ttl produces an expired
// token.
func signToken(secret, user string, groups []string, ttl time.Duration) string {
	return webservice.SignToken(secret, user, groups, time.Now().Add(ttl))
}

func withToken(token string) func(*http.Request) {
	return withHeader("Authorization", "Token "+token)
}

func withBasic(user, pass string) func(*http.Request) {
	return func(r *http.Request) { r.SetBasicAuth(user, pass) }
}

func withHeader(key, value string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set(key, value) }
}

func withCookie(c *http.Cookie) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(c) }
}

func doGet(t *testing.T, client *http.Client, url string, opts ...func(*http.Request)) *http.Response {
	t.Helper()
	resp, err := tryGet(client, url, opts...)
	assert.NilError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func doPost(t *testing.T, client *http.Client, url, contentType, body string, opts ...func(*http.Request)) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	assert.NilError(t, err)
	req.Header.Set("Content-Type", contentType)
	for _, o := range opts {
		o(req)
	}
	resp, err := client.Do(req)
	assert.NilError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func tryGet(client *http.Client, url string, opts ...func(*http.Request)) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for _, o := range opts {
		o(req)
	}
	return client.Do(req)
}

func decodeEcho(t *testing.T, resp *http.Response) echoResponse {
	t.Helper()
	var e echoResponse
	assert.NilError(t, json.NewDecoder(resp.Body).Decode(&e))
	return e
}

// stripRealm turns a Kerberos principal (user@REALM) into the bare user name.
func stripRealm(principal string) string {
	user, _, _ := strings.Cut(principal, "@")
	return user
}

func containsGroup(groups []string, want string) bool {
	for _, g := range groups {
		if strings.EqualFold(g, want) {
			return true
		}
	}
	return false
}

// testPKI is a throw-away certificate authority for TLS and mTLS tests.
type testPKI struct {
	CAFile string
	dir    string
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	serial int64
}

func newPKI(t *testing.T, name string) *testPKI {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	assert.NilError(t, err)
	caCert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)

	p := &testPKI{dir: dir, caCert: caCert, caKey: key, serial: 1}
	p.CAFile = filepath.Join(dir, "ca.pem")
	writePEM(t, p.CAFile, "CERTIFICATE", der)
	return p
}

// issue creates a leaf certificate for localhost/127.0.0.1 usable both as a
// server and as a client certificate, and returns the PEM file paths.
func (p *testPKI) issue(t *testing.T, cn string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err)
	p.serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(p.serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	assert.NilError(t, err)

	certFile = filepath.Join(p.dir, cn+".pem")
	keyFile = filepath.Join(p.dir, cn+".key")
	writePEM(t, certFile, "CERTIFICATE", der)
	keyDER, err := x509.MarshalECPrivateKey(key)
	assert.NilError(t, err)
	writePEM(t, keyFile, "EC PRIVATE KEY", keyDER)
	return certFile, keyFile
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	assert.NilError(t, err)
	assert.NilError(t, pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}))
	assert.NilError(t, f.Close())
}

// tlsClient builds an HTTP client trusting caFile; certFile/keyFile add a
// client certificate for mTLS.
func tlsClient(t *testing.T, caFile, certFile, keyFile string) *http.Client {
	t.Helper()
	cfg := &tls.Config{}
	if caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		assert.NilError(t, err)
		pool := x509.NewCertPool()
		assert.Assert(t, pool.AppendCertsFromPEM(pemBytes))
		cfg.RootCAs = pool
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		assert.NilError(t, err)
		cfg.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}
