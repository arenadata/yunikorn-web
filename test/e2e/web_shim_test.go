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

// End to end tests for the authentication variants between yunikorn-web and
// the yunikorn-k8shim REST API. The web side is the real yunikorn-web server
// (embedded UI plus the /ws/ reverse proxy); the k8shim side is the same core
// webservice server the shim starts on :9080, here with echo handlers so the
// tests can observe the identity and headers that actually reached the shim.
package e2e

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/apache/yunikorn-web/pkg/webserver"
	"gotest.tools/v3/assert"
)

// startWebServer starts the real yunikorn-web server configured from
// YUNIKORN_* environment variables and returns its base URL.
func startWebServer(t *testing.T, env map[string]string) string {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cfg := loadConfig(t, mergeEnv(env, map[string]string{
		"YUNIKORN_LISTEN_ADDRESS": addr,
	}))
	srv, err := webserver.NewWebServer(cfg)
	assert.NilError(t, err)
	srv.Start()
	t.Cleanup(func() { _ = srv.Stop() })
	waitTCP(t, addr)

	scheme := "http"
	if tlsCfg, err := cfg.TLSConfig(); err == nil && tlsCfg != nil {
		scheme = "https"
	}
	return scheme + "://" + addr
}

// TestWebProxyStripsUserAuthorization: whatever credentials the browser
// sends, the proxy never forwards them to the k8shim.
func TestWebProxyStripsUserAuthorization(t *testing.T) {
	shim := startCoreServer(t, nil, echoRoutes())
	web := startWebServer(t, map[string]string{
		"YUNIKORN_K8SHIM_URL": shim,
	})

	resp := doGet(t, http.DefaultClient, web+clusterPath,
		withHeader("Authorization", "Bearer browser-credentials"))
	assert.Equal(t, resp.StatusCode, http.StatusOK)
	echo := decodeEcho(t, resp)
	assert.Equal(t, echo.Authorization, "", "user credentials must not reach the k8shim")
	assert.Equal(t, echo.Authenticated, false)

	// the embedded static UI is served for non-/ws/ paths
	ui := doGet(t, http.DefaultClient, web+"/index.html")
	assert.Equal(t, ui.StatusCode, http.StatusOK)
	body, err := io.ReadAll(ui.Body)
	assert.NilError(t, err)
	assert.Assert(t, strings.Contains(strings.ToLower(string(body)), "<html"))
}

// TestWebForwardsSignedTokenToShim: the web -> k8shim leg authenticates with
// a token signed from the authenticated user identity using the k8shim shared
// secret; user and groups propagate, the user's own token does not.
func TestWebForwardsSignedTokenToShim(t *testing.T) {
	const userSecret, shimSecret = "user-secret", "shim-secret"
	shim := startCoreServer(t, map[string]string{
		"YUNIKORN_AUTH_SHARED_SECRET": shimSecret,
	}, echoRoutes())
	web := startWebServer(t, map[string]string{
		"YUNIKORN_AUTH_SHARED_SECRET":        userSecret,
		"YUNIKORN_K8SHIM_URL":                shim,
		"YUNIKORN_K8SHIM_AUTH_SHARED_SECRET": shimSecret,
	})

	userToken := signToken(userSecret, "tester", []string{"dev", "ops"}, time.Hour)
	resp := doGet(t, http.DefaultClient, web+clusterPath, withToken(userToken))
	assert.Equal(t, resp.StatusCode, http.StatusOK)
	echo := decodeEcho(t, resp)
	assert.Equal(t, echo.User, "tester")
	assert.Assert(t, containsGroup(echo.Groups, "dev"))
	assert.Assert(t, containsGroup(echo.Groups, "ops"))
	assert.Assert(t, strings.HasPrefix(echo.Authorization, "Token "))
	assert.Assert(t, strings.TrimPrefix(echo.Authorization, "Token ") != userToken,
		"the k8shim leg must use its own token, not the user's")

	// a token signed with the k8shim secret is not valid on the user leg
	resp = doGet(t, http.DefaultClient, web+clusterPath,
		withToken(signToken(shimSecret, "tester", nil, time.Hour)))
	assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
}

// TestWebShimSecretMismatch: a k8shim configured with a different secret
// rejects the proxied requests.
func TestWebShimSecretMismatch(t *testing.T) {
	shim := startCoreServer(t, map[string]string{
		"YUNIKORN_AUTH_SHARED_SECRET": "shim-secret",
	}, echoRoutes())
	web := startWebServer(t, map[string]string{
		"YUNIKORN_AUTH_SHARED_SECRET":        "user-secret",
		"YUNIKORN_K8SHIM_URL":                shim,
		"YUNIKORN_K8SHIM_AUTH_SHARED_SECRET": "another-secret",
	})

	resp := doGet(t, http.DefaultClient, web+clusterPath,
		withToken(signToken("user-secret", "tester", nil, time.Hour)))
	assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
}

// TestWebWithoutUserAuthCannotReachProtectedShim: with no authenticated user
// identity on the web side, the proxy attaches no token, so a protected
// k8shim rejects the request.
func TestWebWithoutUserAuthCannotReachProtectedShim(t *testing.T) {
	shim := startCoreServer(t, map[string]string{
		"YUNIKORN_AUTH_SHARED_SECRET": "shim-secret",
	}, echoRoutes())
	web := startWebServer(t, map[string]string{
		"YUNIKORN_K8SHIM_URL":                shim,
		"YUNIKORN_K8SHIM_AUTH_SHARED_SECRET": "shim-secret",
	})

	resp := doGet(t, http.DefaultClient, web+clusterPath)
	assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
}

// TestWebToShimTLS: the web verifies the k8shim server certificate against
// the configured CA; without the CA the proxied request fails.
func TestWebToShimTLS(t *testing.T) {
	pki := newPKI(t, "shim-ca")
	cert, key := pki.issue(t, "shim-server")
	shim := startCoreServer(t, map[string]string{
		"YUNIKORN_TLS_CERT_FILE": cert,
		"YUNIKORN_TLS_KEY_FILE":  key,
	}, echoRoutes())
	assert.Assert(t, strings.HasPrefix(shim, "https://"))

	t.Run("trusted CA", func(t *testing.T) {
		web := startWebServer(t, map[string]string{
			"YUNIKORN_K8SHIM_URL":         shim,
			"YUNIKORN_K8SHIM_TLS_CA_FILE": pki.CAFile,
		})
		resp := doGet(t, http.DefaultClient, web+clusterPath)
		assert.Equal(t, resp.StatusCode, http.StatusOK)
	})

	t.Run("untrusted server certificate", func(t *testing.T) {
		web := startWebServer(t, map[string]string{
			"YUNIKORN_K8SHIM_URL": shim,
		})
		resp := doGet(t, http.DefaultClient, web+clusterPath)
		assert.Equal(t, resp.StatusCode, http.StatusBadGateway)
	})
}

// TestWebToShimMTLS: the k8shim in mtls mode accepts only web instances
// presenting a client certificate signed by its CA.
func TestWebToShimMTLS(t *testing.T) {
	pki := newPKI(t, "shim-ca")
	serverCert, serverKey := pki.issue(t, "shim-server")
	webCert, webKey := pki.issue(t, "web-client")
	shim := startCoreServer(t, map[string]string{
		"YUNIKORN_AUTH_MODE":     "mtls",
		"YUNIKORN_TLS_CERT_FILE": serverCert,
		"YUNIKORN_TLS_KEY_FILE":  serverKey,
		"YUNIKORN_TLS_CA_FILE":   pki.CAFile,
	}, echoRoutes())

	t.Run("web with client certificate", func(t *testing.T) {
		web := startWebServer(t, map[string]string{
			"YUNIKORN_K8SHIM_URL":           shim,
			"YUNIKORN_K8SHIM_TLS_CERT_FILE": webCert,
			"YUNIKORN_K8SHIM_TLS_KEY_FILE":  webKey,
			"YUNIKORN_K8SHIM_TLS_CA_FILE":   pki.CAFile,
		})
		resp := doGet(t, http.DefaultClient, web+clusterPath)
		assert.Equal(t, resp.StatusCode, http.StatusOK)
	})

	t.Run("web without client certificate", func(t *testing.T) {
		web := startWebServer(t, map[string]string{
			"YUNIKORN_K8SHIM_URL":         shim,
			"YUNIKORN_K8SHIM_TLS_CA_FILE": pki.CAFile,
		})
		resp := doGet(t, http.DefaultClient, web+clusterPath)
		assert.Equal(t, resp.StatusCode, http.StatusBadGateway)
	})
}

// TestWebLDAPUserEndToEnd: browser -> web with LDAP BasicAuth and role based
// authorization, web -> k8shim with the signed token; identity and groups
// travel the whole chain.
func TestWebLDAPUserEndToEnd(t *testing.T) {
	l := startLDAPContainer(t)
	shim := startCoreServer(t, map[string]string{
		"YUNIKORN_AUTH_SHARED_SECRET": "shim-secret",
	}, echoRoutes())
	web := startWebServer(t, mergeEnv(ldapEnv(l), map[string]string{
		"YUNIKORN_AUTH_MODE":                 "ldap",
		"YUNIKORN_LDAP_COOKIE_SECRET":        "cookie-secret",
		"YUNIKORN_LDAP_ADMIN_GROUPS":         "yk-admins",
		"YUNIKORN_LDAP_VIEWER_GROUPS":        "yk-viewers",
		"YUNIKORN_K8SHIM_URL":                shim,
		"YUNIKORN_K8SHIM_AUTH_SHARED_SECRET": "shim-secret",
	}))

	t.Run("unauthenticated browser is challenged", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, web+clusterPath)
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
		assert.Assert(t, resp.Header.Get("WWW-Authenticate") != "")
	})

	t.Run("admin identity and groups reach the shim", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, web+clusterPath, withBasic("admin1", "admin1pw"))
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		echo := decodeEcho(t, resp)
		assert.Equal(t, echo.User, "admin1")
		assert.Assert(t, containsGroup(echo.Groups, "yk-admins"), "groups=%v", echo.Groups)
		assert.Assert(t, strings.HasPrefix(echo.Authorization, "Token "))

		var cookie *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == "YK_AUTH" {
				cookie = c
			}
		}
		assert.Assert(t, cookie != nil)
		replay := doGet(t, http.DefaultClient, web+clusterPath, withCookie(cookie))
		assert.Equal(t, replay.StatusCode, http.StatusOK)
		assert.Equal(t, decodeEcho(t, replay).User, "admin1")
	})

	t.Run("viewer role is enforced before proxying", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, web+schedulerPath, withBasic("viewer1", "viewer1pw"))
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		resp = doGet(t, http.DefaultClient, web+clusterPath, withBasic("viewer1", "viewer1pw"))
		assert.Equal(t, resp.StatusCode, http.StatusForbidden)
	})

	t.Run("static UI follows the same authorization", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, web+"/index.html", withBasic("admin1", "admin1pw"))
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		// the StaticUI route category is not among the viewer role's routes:
		// a viewer can query the scheduler API but not load the UI
		resp = doGet(t, http.DefaultClient, web+"/index.html", withBasic("viewer1", "viewer1pw"))
		assert.Equal(t, resp.StatusCode, http.StatusForbidden)
	})
}

// TestWebKerberosUserEndToEnd: browser -> web via SPNEGO (with X-Groups from
// an upstream proxy), web -> k8shim with the signed token.
func TestWebKerberosUserEndToEnd(t *testing.T) {
	kdc := startKDCContainer(t)
	shim := startCoreServer(t, map[string]string{
		"YUNIKORN_AUTH_SHARED_SECRET": "shim-secret",
	}, echoRoutes())
	web := startWebServer(t, map[string]string{
		"YUNIKORN_AUTH_MODE":                 "kerberos",
		"YUNIKORN_KEYTAB_PATH":               kdc.KeytabFile,
		"YUNIKORN_USE_X_GROUPS":              "true",
		"YUNIKORN_K8SHIM_URL":                shim,
		"YUNIKORN_K8SHIM_AUTH_SHARED_SECRET": "shim-secret",
	})

	t.Run("no ticket challenged", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, web+clusterPath)
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
	})

	t.Run("principal and X-Groups reach the shim", func(t *testing.T) {
		resp := spnegoGet(t, spnegoClient(t, kdc, "alice", "alicepw"), web+clusterPath,
			withHeader("X-Groups", "qa"))
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		echo := decodeEcho(t, resp)
		assert.Equal(t, stripRealm(echo.User), "alice")
		assert.Assert(t, containsGroup(echo.Groups, "qa"), "groups=%v", echo.Groups)
		assert.Assert(t, strings.HasPrefix(echo.Authorization, "Token "))
	})
}
