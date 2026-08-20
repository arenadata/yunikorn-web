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

// End to end tests for the web -> k8shim leg over a unix socket
// (YUNIKORN_K8SHIM_URL=unix:///var/run/yunikorn/k8shim.sock). The web side is
// the real yunikorn-web server; the k8shim side is the socket listener the
// shim starts in exposeMetricsOnly mode (k8shim pkg/cmd/shim/main.go,
// localServer): the scheduler REST route table on a bare httprouter, served
// over a 0660 socket file with no authentication of its own - the file
// permissions are the access control on that leg.
package e2e

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apache/yunikorn-core/pkg/webservice"
	"github.com/apache/yunikorn-web/pkg/webserver"
	"github.com/julienschmidt/httprouter"
	"gotest.tools/v3/assert"
)

// Route patterns used by the socket tests on top of the ones in helpers_test.go.
const (
	healthPath    = "/ws/v1/scheduler/healthcheck" // RouteNameScheduler
	stateDumpPath = "/ws/v1/fullstatedump"         // RouteNameScheduler
	streamPath    = "/ws/v1/events/stream"         // RouteNameScheduler, server-sent events
	validatePath  = "/ws/v1/validate-conf"         // RouteNameCluster, POST
)

// shimSocket is the k8shim unix socket listener under test control: it owns
// the socket path and can be started and stopped independently of the web
// server, so tests can exercise the shim being down, restarted or unreachable.
type shimSocket struct {
	Path string
	srv  *http.Server
}

// newShimSocket reserves a socket path without listening on it yet.
func newShimSocket(t *testing.T) *shimSocket {
	t.Helper()
	// not t.TempDir(): it embeds the test name in the path, which easily blows
	// the ~104 byte sockaddr_un limit
	dir, err := os.MkdirTemp("", "yk-sock")
	assert.NilError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return &shimSocket{Path: filepath.Join(dir, "k8shim.sock")}
}

// URL is the socket in the form YUNIKORN_K8SHIM_URL takes in the deployment.
func (s *shimSocket) URL() string { return "unix://" + s.Path }

// start serves handler on the socket file, with the permissions and the
// timeouts of the shim listener.
func (s *shimSocket) start(t *testing.T, handler http.Handler) {
	t.Helper()
	assert.Assert(t, s.srv == nil, "socket already serving")
	_ = os.Remove(s.Path)
	listener, err := net.Listen("unix", s.Path)
	assert.NilError(t, err)
	assert.NilError(t, os.Chmod(s.Path, 0o660))

	s.srv = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	srv := s.srv
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { s.stop(t) })
}

// stop closes the listener and removes the socket file, like the shim does on
// SIGTERM.
func (s *shimSocket) stop(t *testing.T) {
	t.Helper()
	if s.srv == nil {
		return
	}
	assert.NilError(t, s.srv.Close())
	s.srv = nil
	_ = os.Remove(s.Path)
}

// startShimSocket starts a k8shim style socket listener for the given routes.
func startShimSocket(t *testing.T, rts []webservice.Route) *shimSocket {
	t.Helper()
	s := newShimSocket(t)
	s.start(t, shimRouter(rts))
	return s
}

// shimRouter is the handler the shim serves on the socket: the routes on a
// plain httprouter, without the authentication, authorization and compression
// middleware of the core web app.
func shimRouter(rts []webservice.Route) http.Handler {
	router := httprouter.New()
	for _, rt := range rts {
		router.Handler(rt.Method, rt.Pattern, rt.HandlerFunc)
	}
	return router
}

// coreSocketHandler is the fully wrapped core webservice handler (its
// authentication and authorization included), for the tests that check what a
// socket listener validating the proxy token makes of the forwarded request.
func coreSocketHandler(t *testing.T, env map[string]string, rts []webservice.Route) http.Handler {
	t.Helper()
	return webservice.NewWebServer(loadConfig(t, env), "", rts).Handler()
}

// overrideRoute replaces the handler of one route so the shim answers
// something distinctive on that endpoint.
func overrideRoute(t *testing.T, rts []webservice.Route, pattern string, h http.HandlerFunc) []webservice.Route {
	t.Helper()
	out := append([]webservice.Route(nil), rts...)
	found := false
	for i := range out {
		if out[i].Pattern == pattern {
			out[i].HandlerFunc = h
			found = true
		}
	}
	assert.Assert(t, found, "no route with pattern %s", pattern)
	return out
}

// shimToken is the payload the web -> k8shim leg signs into its tokens.
type shimToken struct {
	User   string   `json:"user"`
	Exp    int64    `json:"exp"`
	Groups []string `json:"groups"`
}

// parseShimToken verifies the "Authorization: Token ..." header the proxy
// attached against the k8shim shared secret and returns its payload.
func parseShimToken(t *testing.T, secret, header string) shimToken {
	t.Helper()
	raw, ok := strings.CutPrefix(header, "Token ")
	assert.Assert(t, ok, "not a token authorization header: %q", header)
	encoded, sig, ok := strings.Cut(raw, ".")
	assert.Assert(t, ok, "malformed token: %q", raw)
	payload, err := base64.StdEncoding.DecodeString(encoded)
	assert.NilError(t, err)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	assert.Equal(t, sig, hex.EncodeToString(mac.Sum(nil)),
		"token is not signed with the k8shim shared secret")

	var tok shimToken
	assert.NilError(t, json.Unmarshal(payload, &tok))
	return tok
}

// waitStatus polls url until it answers with want. The socket is dialed per
// request, but the transport can still hold an idle connection to a socket
// file the shim has just removed, so a status change may take one retry.
func waitStatus(t *testing.T, url string, want int) *http.Response {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := tryGet(http.DefaultClient, url)
		switch {
		case err == nil && resp.StatusCode == want:
			t.Cleanup(func() { _ = resp.Body.Close() })
			return resp
		case err == nil:
			_ = resp.Body.Close()
			if time.Now().After(deadline) {
				t.Fatalf("GET %s: got status %d, want %d", url, resp.StatusCode, want)
			}
		default:
			if time.Now().After(deadline) {
				t.Fatalf("GET %s: %v, want status %d", url, err, want)
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestWebProxiesToShimOverUnixSocket: with a unix:// k8shim URL the /ws/
// requests are served by the shim over the socket file - method, path, query,
// body, status and headers all survive the trip - while the static UI keeps
// being served by web itself.
func TestWebProxiesToShimOverUnixSocket(t *testing.T) {
	stateDump := strings.Repeat("yunikorn-state-dump ", 52429) // ~1 MiB
	rts := overrideRoute(t, echoRoutes(), healthPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Shim-Marker", "socket")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("brewing"))
	})
	rts = overrideRoute(t, rts, stateDumpPath, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, stateDump)
	})

	sock := startShimSocket(t, rts)
	web := startWebServer(t, map[string]string{
		"YUNIKORN_K8SHIM_URL": sock.URL(),
	})

	t.Run("the request reaches the shim over the socket", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, web+clusterPath)
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		echo := decodeEcho(t, resp)
		assert.Equal(t, echo.Method, http.MethodGet)
		assert.Equal(t, echo.Path, clusterPath)
		// the socket dialer ignores the address, so the forwarded request
		// carries the placeholder authority instead of a real host
		assert.Equal(t, echo.Host, "localhost")
		// and the original request is still described by the X-Forwarded-* set
		assert.Equal(t, echo.ForwardedHost, strings.TrimPrefix(web, "http://"))
		assert.Equal(t, echo.ForwardedProto, "http")
		assert.Equal(t, echo.ForwardedFor, "127.0.0.1")
	})

	t.Run("path parameters and query string are preserved", func(t *testing.T) {
		const path = "/ws/v1/partition/default/queue/root.default/applications"
		const query = "states=Running&user=user%20one"
		resp := doGet(t, http.DefaultClient, web+path+"?"+query)
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		echo := decodeEcho(t, resp)
		assert.Equal(t, echo.Path, path)
		assert.Equal(t, echo.RawQuery, query)
	})

	t.Run("method and request body are preserved", func(t *testing.T) {
		const body = "partitions:\n  - name: default\n"
		resp := doPost(t, http.DefaultClient, web+validatePath, "application/x-yaml", body)
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		echo := decodeEcho(t, resp)
		assert.Equal(t, echo.Method, http.MethodPost)
		assert.Equal(t, echo.Path, validatePath)
		assert.Equal(t, echo.Body, body)
	})

	t.Run("status code and response headers come from the shim", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, web+healthPath)
		assert.Equal(t, resp.StatusCode, http.StatusTeapot)
		assert.Equal(t, resp.Header.Get("X-Shim-Marker"), "socket")
		body, err := io.ReadAll(resp.Body)
		assert.NilError(t, err)
		assert.Equal(t, string(body), "brewing")
	})

	t.Run("large responses survive the socket and the gzip layer", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, web+stateDumpPath)
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		body, err := io.ReadAll(resp.Body)
		assert.NilError(t, err)
		assert.Equal(t, len(body), len(stateDump))
		assert.Equal(t, sha256.Sum256(body), sha256.Sum256([]byte(stateDump)))
	})

	t.Run("the static UI is not proxied", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, web+"/index.html")
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		body, err := io.ReadAll(resp.Body)
		assert.NilError(t, err)
		assert.Assert(t, strings.Contains(strings.ToLower(string(body)), "<html"))
	})
}

// TestWebSocketURLForms: both spellings of an absolute socket path reach the
// same listener.
func TestWebSocketURLForms(t *testing.T) {
	sock := startShimSocket(t, echoRoutes())

	for _, raw := range []string{"unix://" + sock.Path, "unix:" + sock.Path} {
		t.Run(raw, func(t *testing.T) {
			web := startWebServer(t, map[string]string{"YUNIKORN_K8SHIM_URL": raw})
			resp := doGet(t, http.DefaultClient, web+clusterPath)
			assert.Equal(t, resp.StatusCode, http.StatusOK)
			assert.Equal(t, decodeEcho(t, resp).Path, clusterPath)
		})
	}
}

// TestWebSocketStripsUserAuthorization: the socket listener serves whatever it
// is handed, so the browser credentials must not arrive there.
func TestWebSocketStripsUserAuthorization(t *testing.T) {
	sock := startShimSocket(t, echoRoutes())
	web := startWebServer(t, map[string]string{
		"YUNIKORN_K8SHIM_URL": sock.URL(),
	})

	resp := doGet(t, http.DefaultClient, web+clusterPath,
		withHeader("Authorization", "Bearer browser-credentials"))
	assert.Equal(t, resp.StatusCode, http.StatusOK)
	echo := decodeEcho(t, resp)
	assert.Equal(t, echo.Authorization, "", "user credentials must not reach the k8shim")
	assert.Equal(t, echo.Authenticated, false)
}

// TestWebForwardsSignedTokenToShimOverUnixSocket: the identity authenticated
// on the user leg is what the proxy signs into the k8shim token, and that
// token travels over the socket in place of the user's own credentials.
func TestWebForwardsSignedTokenToShimOverUnixSocket(t *testing.T) {
	const userSecret, shimSecret = "user-secret", "shim-secret"
	sock := startShimSocket(t, echoRoutes())
	web := startWebServer(t, map[string]string{
		"YUNIKORN_AUTH_SHARED_SECRET":        userSecret,
		"YUNIKORN_K8SHIM_URL":                sock.URL(),
		"YUNIKORN_K8SHIM_AUTH_SHARED_SECRET": shimSecret,
	})

	userToken := signToken(userSecret, "tester", []string{"dev", "ops"}, time.Hour)
	resp := doGet(t, http.DefaultClient, web+clusterPath, withToken(userToken))
	assert.Equal(t, resp.StatusCode, http.StatusOK)
	echo := decodeEcho(t, resp)

	assert.Assert(t, !strings.Contains(echo.Authorization, userToken),
		"the k8shim leg must use its own token, not the user's")
	tok := parseShimToken(t, shimSecret, echo.Authorization)
	assert.Equal(t, tok.User, "tester")
	assert.Assert(t, containsGroup(tok.Groups, "dev"), "groups=%v", tok.Groups)
	assert.Assert(t, containsGroup(tok.Groups, "ops"), "groups=%v", tok.Groups)
	assert.Assert(t, tok.Exp > time.Now().Unix(), "the k8shim token is already expired")

	// the user leg is still authenticated: an unsigned request never gets to
	// the socket
	resp = doGet(t, http.DefaultClient, web+clusterPath)
	assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
}

// TestWebSocketWithoutUserIdentityAttachesNoToken: with no authentication on
// the user leg there is no identity to sign, so the request arrives at the
// socket listener with no Authorization header at all.
func TestWebSocketWithoutUserIdentityAttachesNoToken(t *testing.T) {
	sock := startShimSocket(t, echoRoutes())
	web := startWebServer(t, map[string]string{
		"YUNIKORN_K8SHIM_URL":                sock.URL(),
		"YUNIKORN_K8SHIM_AUTH_SHARED_SECRET": "shim-secret",
	})

	resp := doGet(t, http.DefaultClient, web+clusterPath)
	assert.Equal(t, resp.StatusCode, http.StatusOK)
	assert.Equal(t, decodeEcho(t, resp).Authorization, "")
}

// TestWebToShimSharedSecretOverUnixSocket: the shim listener serves the socket
// unauthenticated, but the token the proxy attaches over that leg is a real
// one - a listener that does validate it (here the full core webservice stack
// on the socket) accepts the request and sees the browser identity, and
// rejects it when the secrets differ.
func TestWebToShimSharedSecretOverUnixSocket(t *testing.T) {
	const userSecret, shimSecret = "user-secret", "shim-secret"
	sock := newShimSocket(t)
	sock.start(t, coreSocketHandler(t, map[string]string{
		"YUNIKORN_AUTH_SHARED_SECRET": shimSecret,
	}, echoRoutes()))

	t.Run("matching secret", func(t *testing.T) {
		web := startWebServer(t, map[string]string{
			"YUNIKORN_AUTH_SHARED_SECRET":        userSecret,
			"YUNIKORN_K8SHIM_URL":                sock.URL(),
			"YUNIKORN_K8SHIM_AUTH_SHARED_SECRET": shimSecret,
		})
		resp := doGet(t, http.DefaultClient, web+clusterPath,
			withToken(signToken(userSecret, "tester", []string{"dev"}, time.Hour)))
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		echo := decodeEcho(t, resp)
		assert.Equal(t, echo.User, "tester")
		assert.Equal(t, echo.Authenticated, true)
		assert.Assert(t, containsGroup(echo.Groups, "dev"), "groups=%v", echo.Groups)
	})

	t.Run("secret mismatch", func(t *testing.T) {
		web := startWebServer(t, map[string]string{
			"YUNIKORN_AUTH_SHARED_SECRET":        userSecret,
			"YUNIKORN_K8SHIM_URL":                sock.URL(),
			"YUNIKORN_K8SHIM_AUTH_SHARED_SECRET": "another-secret",
		})
		resp := doGet(t, http.DefaultClient, web+clusterPath,
			withToken(signToken(userSecret, "tester", nil, time.Hour)))
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
	})
}

// TestWebSocketShimLifecycle: the socket is dialed per request, so web
// survives starting before the shim and the shim being restarted underneath
// it - no web restart is needed to pick the socket up again.
func TestWebSocketShimLifecycle(t *testing.T) {
	sock := newShimSocket(t)
	web := startWebServer(t, map[string]string{
		"YUNIKORN_K8SHIM_URL": sock.URL(),
	})

	// web is up before the shim has created its socket file
	resp := doGet(t, http.DefaultClient, web+clusterPath)
	assert.Equal(t, resp.StatusCode, http.StatusBadGateway)
	// the static UI does not depend on the k8shim being reachable
	assert.Equal(t, doGet(t, http.DefaultClient, web+"/index.html").StatusCode, http.StatusOK)

	// the shim comes up
	sock.start(t, shimRouter(echoRoutes()))
	resp = waitStatus(t, web+clusterPath, http.StatusOK)
	assert.Equal(t, decodeEcho(t, resp).Path, clusterPath)

	// and goes down again, removing its socket file
	sock.stop(t)
	waitStatus(t, web+clusterPath, http.StatusBadGateway)

	// restarted on the same path, it is reachable again
	sock.start(t, shimRouter(echoRoutes()))
	resp = waitStatus(t, web+clusterPath, http.StatusOK)
	assert.Equal(t, decodeEcho(t, resp).Path, clusterPath)
}

// TestWebSocketFilePermissions: the socket file permissions are the access
// control on the web -> k8shim leg; a socket web may not open is a 502, never
// a proxied response.
func TestWebSocketFilePermissions(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses socket file permissions")
	}
	sock := startShimSocket(t, echoRoutes())
	// no pooled connection exists yet: the first request has to open the file
	assert.NilError(t, os.Chmod(sock.Path, 0o000))

	web := startWebServer(t, map[string]string{
		"YUNIKORN_K8SHIM_URL": sock.URL(),
	})
	resp := doGet(t, http.DefaultClient, web+clusterPath)
	assert.Equal(t, resp.StatusCode, http.StatusBadGateway)

	// the shim listener grants access to its group, as the shim does on start
	assert.NilError(t, os.Chmod(sock.Path, 0o660))
	resp = doGet(t, http.DefaultClient, web+clusterPath)
	assert.Equal(t, resp.StatusCode, http.StatusOK)
}

// TestWebSocketConcurrentRequests: the socket transport serves parallel
// browsers, each connection dialed to the same socket file.
func TestWebSocketConcurrentRequests(t *testing.T) {
	sock := startShimSocket(t, echoRoutes())
	web := startWebServer(t, map[string]string{
		"YUNIKORN_K8SHIM_URL": sock.URL(),
	})

	const workers, perWorker = 16, 4
	errs := make(chan error, workers*perWorker)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			path := fmt.Sprintf("/ws/v1/partition/p%d/queue/root/applications", i)
			for range perWorker {
				resp, err := tryGet(http.DefaultClient, web+path)
				if err != nil {
					errs <- err
					return
				}
				var echo echoResponse
				err = json.NewDecoder(resp.Body).Decode(&echo)
				_ = resp.Body.Close()
				switch {
				case err != nil:
					errs <- err
				case resp.StatusCode != http.StatusOK:
					errs <- fmt.Errorf("GET %s: status %d", path, resp.StatusCode)
				case echo.Path != path:
					errs <- fmt.Errorf("GET %s: served %s", path, echo.Path)
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestWebStreamsEventsOverUnixSocket: the event stream is forwarded
// incrementally over the socket - the browser sees each event as the shim
// writes it, not only when the stream ends.
func TestWebStreamsEventsOverUnixSocket(t *testing.T) {
	const first, second = "event: first\n\n", "event: second\n\n"
	release := make(chan struct{})
	rts := overrideRoute(t, echoRoutes(), streamPath, func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flusher", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, first)
		flusher.Flush()
		select {
		case <-release:
		case <-time.After(5 * time.Second): // the proxy buffered the first event
		}
		_, _ = io.WriteString(w, second)
		flusher.Flush()
	})

	sock := startShimSocket(t, rts)
	web := startWebServer(t, map[string]string{
		"YUNIKORN_K8SHIM_URL": sock.URL(),
	})

	client := &http.Client{Timeout: 15 * time.Second}
	resp := doGet(t, client, web+streamPath)
	assert.Equal(t, resp.StatusCode, http.StatusOK)
	assert.Equal(t, resp.Header.Get("Content-Type"), "text/event-stream")

	buf := make([]byte, len(first))
	_, err := io.ReadFull(resp.Body, buf)
	assert.NilError(t, err, "the first event did not arrive before the stream ended")
	assert.Equal(t, string(buf), first)

	close(release)
	buf = make([]byte, len(second))
	_, err = io.ReadFull(resp.Body, buf)
	assert.NilError(t, err)
	assert.Equal(t, string(buf), second)
}

// TestWebSocketConfigValidation: a broken socket configuration keeps the web
// server from starting instead of being silently downgraded.
func TestWebSocketConfigValidation(t *testing.T) {
	sock := newShimSocket(t)
	pki := newPKI(t, "shim-ca")

	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{
			// the socket listener speaks plain HTTP: dropping the configured
			// client certificates would be a silent loss of authentication
			name: "TLS on the socket leg",
			env: map[string]string{
				"YUNIKORN_K8SHIM_URL":         sock.URL(),
				"YUNIKORN_K8SHIM_TLS_CA_FILE": pki.CAFile,
			},
			wantErr: "TLS is not supported with a unix socket URL",
		},
		{
			name:    "no socket path",
			env:     map[string]string{"YUNIKORN_K8SHIM_URL": "unix://"},
			wantErr: "missing socket path",
		},
		{
			name:    "unknown scheme",
			env:     map[string]string{"YUNIKORN_K8SHIM_URL": "socket://" + sock.Path},
			wantErr: "unsupported k8shim URL scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := webserver.NewWebServer(loadConfig(t, tt.env))
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// TestWebLDAPUserEndToEndOverUnixSocket: the deployment shape of the socket
// setup - authentication on the browser leg, the socket on the k8shim leg. The
// LDAP identity and its groups reach the shim in the signed token, and the
// role authorization still happens before anything is proxied.
func TestWebLDAPUserEndToEndOverUnixSocket(t *testing.T) {
	l := startLDAPContainer(t)
	sock := startShimSocket(t, echoRoutes())
	web := startWebServer(t, mergeEnv(ldapEnv(l), map[string]string{
		"YUNIKORN_AUTH_MODE":                 "ldap",
		"YUNIKORN_LDAP_COOKIE_SECRET":        "cookie-secret",
		"YUNIKORN_LDAP_ADMIN_GROUPS":         "yk-admins",
		"YUNIKORN_LDAP_VIEWER_GROUPS":        "yk-viewers",
		"YUNIKORN_K8SHIM_URL":                sock.URL(),
		"YUNIKORN_K8SHIM_AUTH_SHARED_SECRET": "shim-secret",
	}))

	t.Run("admin identity and groups reach the shim", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, web+clusterPath, withBasic("admin1", "admin1pw"))
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		echo := decodeEcho(t, resp)
		assert.Equal(t, echo.Path, clusterPath)
		tok := parseShimToken(t, "shim-secret", echo.Authorization)
		assert.Equal(t, tok.User, "admin1")
		assert.Assert(t, containsGroup(tok.Groups, "yk-admins"), "groups=%v", tok.Groups)
	})

	t.Run("an unauthorized user never reaches the socket", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, web+clusterPath, withBasic("viewer1", "viewer1pw"))
		assert.Equal(t, resp.StatusCode, http.StatusForbidden)
	})

	t.Run("an unauthenticated browser is challenged", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, web+clusterPath)
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
		assert.Assert(t, resp.Header.Get("WWW-Authenticate") != "")
	})
}
