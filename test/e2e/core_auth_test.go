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

// End to end tests for every authentication mode of the yunikorn-core
// webservice — the listener the k8shim exposes on :9080. Each test starts the
// real webservice server (the same stack the shim's entrypoint starts) with
// the mode under test configured through YUNIKORN_* environment variables, and
// talks to it over real sockets. LDAP and Kerberos are provided by
// testcontainers (OpenLDAP and a MIT KDC).
package e2e

import (
	"maps"
	"net/http"
	"testing"
	"time"

	"github.com/apache/yunikorn-core/pkg/webservice"
	"gotest.tools/v3/assert"
)

// ldapEnv is the YUNIKORN_LDAP_* connection block shared by the LDAP-backed
// tests. Which group resolution path a test exercises depends on the directory
// it is pointed at, not on anything here.
func ldapEnv(l *ldapServer) map[string]string {
	return map[string]string{
		"YUNIKORN_LDAP_URL":           l.URL,
		"YUNIKORN_LDAP_BIND_DN":       ldapAdminDN,
		"YUNIKORN_LDAP_BIND_PASSWORD": ldapAdminPW,
		"YUNIKORN_LDAP_BASE_DN":       ldapBaseDN,
	}
}

func mergeEnv(ms ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range ms {
		maps.Copy(out, m)
	}
	return out
}

// TestCoreAuthDisabled: without any authentication configuration every route
// is served unauthenticated.
func TestCoreAuthDisabled(t *testing.T) {
	base := startCoreServer(t, nil, echoRoutes())

	for _, path := range []string{clusterPath, schedulerPath, metricsPath} {
		resp := doGet(t, http.DefaultClient, base+path)
		assert.Equal(t, resp.StatusCode, http.StatusOK, path)
		echo := decodeEcho(t, resp)
		assert.Equal(t, echo.Authenticated, false)
	}
}

// TestCoreSharedSecret: the shared_secret mode (inferred from the configured
// secret) accepts only requests carrying a valid HMAC-signed token in the
// "Authorization: Token" scheme.
func TestCoreSharedSecret(t *testing.T) {
	const secret = "core-secret"
	base := startCoreServer(t, map[string]string{
		"YUNIKORN_AUTH_SHARED_SECRET": secret,
	}, echoRoutes())

	tests := []struct {
		name string
		opts []func(*http.Request)
		want int
	}{
		{"no credentials", nil, http.StatusUnauthorized},
		{"wrong scheme", []func(*http.Request){withHeader("Authorization", "Bearer abc")}, http.StatusUnauthorized},
		{"malformed token", []func(*http.Request){withToken("garbage")}, http.StatusUnauthorized},
		{"wrong secret", []func(*http.Request){withToken(signToken("other-secret", "tester", nil, time.Hour))}, http.StatusUnauthorized},
		{"expired token", []func(*http.Request){withToken(signToken(secret, "tester", nil, -time.Minute))}, http.StatusUnauthorized},
		{"valid token", []func(*http.Request){withToken(signToken(secret, "tester", []string{"dev"}, time.Hour))}, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := doGet(t, http.DefaultClient, base+clusterPath, tc.opts...)
			assert.Equal(t, resp.StatusCode, tc.want)
			if tc.want == http.StatusOK {
				echo := decodeEcho(t, resp)
				assert.Equal(t, echo.User, "tester")
				assert.Assert(t, containsGroup(echo.Groups, "dev"))
				assert.Equal(t, echo.Authenticated, true)
			}
		})
	}
}

// TestCoreSharedSecretLDAPGroupEnrichment: in shared_secret mode with an LDAP
// section configured, a token that carries no groups gets the membership
// looked up in the directory; a token that carries groups keeps them.
func TestCoreSharedSecretLDAPGroupEnrichment(t *testing.T) {
	l := startLDAPContainer(t)
	const secret = "core-secret"
	base := startCoreServer(t, mergeEnv(ldapEnv(l), map[string]string{
		"YUNIKORN_AUTH_SHARED_SECRET": secret,
	}), echoRoutes())

	t.Run("groups from LDAP", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, base+clusterPath,
			withToken(signToken(secret, "admin1", nil, time.Hour)))
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		echo := decodeEcho(t, resp)
		assert.Assert(t, containsGroup(echo.Groups, "yk-admins"), "groups=%v", echo.Groups)
	})

	t.Run("groups from token take precedence", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, base+clusterPath,
			withToken(signToken(secret, "admin1", []string{"from-token"}, time.Hour)))
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		echo := decodeEcho(t, resp)
		assert.Assert(t, containsGroup(echo.Groups, "from-token"))
		assert.Assert(t, !containsGroup(echo.Groups, "yk-admins"))
	})
}

// TestCoreLDAPBasicAuthAndCookie: the ldap mode checks BasicAuth credentials
// against the directory, issues the signed YK_AUTH cookie and accepts the
// cookie on subsequent requests. Authenticated users still need a matching
// group (allowed-groups here) to pass authorization.
func TestCoreLDAPBasicAuthAndCookie(t *testing.T) {
	l := startLDAPContainer(t)
	base := startCoreServer(t, mergeEnv(ldapEnv(l), map[string]string{
		"YUNIKORN_AUTH_MODE":           "ldap",
		"YUNIKORN_LDAP_COOKIE_SECRET":  "cookie-secret",
		"YUNIKORN_LDAP_ALLOWED_GROUPS": "yk-admins,yk-users",
	}), echoRoutes())

	t.Run("no credentials challenges Basic", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, base+clusterPath)
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
		assert.Assert(t, resp.Header.Get("WWW-Authenticate") != "")
	})

	t.Run("wrong password rejected", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, base+clusterPath, withBasic("admin1", "wrong"))
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
	})

	t.Run("unknown user rejected", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, base+clusterPath, withBasic("nosuchuser", "pw"))
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
	})

	t.Run("valid credentials authenticate and set cookie", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, base+clusterPath, withBasic("admin1", "admin1pw"))
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		echo := decodeEcho(t, resp)
		assert.Equal(t, echo.User, "admin1")
		assert.Assert(t, containsGroup(echo.Groups, "yk-admins"), "groups=%v", echo.Groups)

		var cookie *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == "YK_AUTH" {
				cookie = c
			}
		}
		assert.Assert(t, cookie != nil, "YK_AUTH cookie not issued")

		// replaying the cookie authenticates without another Basic exchange
		replay := doGet(t, http.DefaultClient, base+clusterPath, withCookie(cookie))
		assert.Equal(t, replay.StatusCode, http.StatusOK)
		assert.Equal(t, decodeEcho(t, replay).User, "admin1")

		// a tampered cookie falls back to the Basic challenge
		bad := *cookie
		bad.Value += "x"
		resp = doGet(t, http.DefaultClient, base+clusterPath, withCookie(&bad))
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
	})

	t.Run("authenticated user without allowed group is forbidden", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, base+clusterPath, withBasic("bob", "bobpw"))
		assert.Equal(t, resp.StatusCode, http.StatusForbidden)
	})
}

// TestCoreLDAPAuthorizationRBAC: LDAP group membership maps to the admin,
// viewer and service roles; each role reaches only its route categories.
func TestCoreLDAPAuthorizationRBAC(t *testing.T) {
	l := startLDAPContainer(t)
	base := startCoreServer(t, mergeEnv(ldapEnv(l), map[string]string{
		"YUNIKORN_AUTH_MODE":           "ldap",
		"YUNIKORN_LDAP_COOKIE_SECRET":  "cookie-secret",
		"YUNIKORN_LDAP_ADMIN_GROUPS":   "yk-admins",
		"YUNIKORN_LDAP_VIEWER_GROUPS":  "yk-viewers",
		"YUNIKORN_LDAP_SERVICE_GROUPS": "yk-service",
	}), echoRoutes())

	tests := []struct {
		user, pass string
		wants      map[string]int
	}{
		{"admin1", "admin1pw", map[string]int{
			clusterPath:   http.StatusOK,
			schedulerPath: http.StatusOK,
			metricsPath:   http.StatusOK,
		}},
		{"viewer1", "viewer1pw", map[string]int{
			clusterPath:   http.StatusForbidden,
			schedulerPath: http.StatusOK,
			metricsPath:   http.StatusForbidden,
		}},
		{"svc1", "svc1pw", map[string]int{
			clusterPath:   http.StatusForbidden,
			schedulerPath: http.StatusForbidden,
			metricsPath:   http.StatusOK,
		}},
		{"bob", "bobpw", map[string]int{
			clusterPath:   http.StatusForbidden,
			schedulerPath: http.StatusForbidden,
			metricsPath:   http.StatusForbidden,
		}},
	}
	for _, tc := range tests {
		t.Run(tc.user, func(t *testing.T) {
			for path, want := range tc.wants {
				resp := doGet(t, http.DefaultClient, base+path, withBasic(tc.user, tc.pass))
				assert.Equal(t, resp.StatusCode, want, "%s on %s", tc.user, path)
			}
		})
	}

	t.Run("allowed groups grant access without a role", func(t *testing.T) {
		allowedBase := startCoreServer(t, mergeEnv(ldapEnv(l), map[string]string{
			"YUNIKORN_AUTH_MODE":           "ldap",
			"YUNIKORN_LDAP_COOKIE_SECRET":  "cookie-secret",
			"YUNIKORN_LDAP_ALLOWED_GROUPS": "yk-users",
		}), echoRoutes())

		for path, want := range map[string]int{clusterPath: http.StatusOK, schedulerPath: http.StatusOK} {
			resp := doGet(t, http.DefaultClient, allowedBase+path, withBasic("alice", "alicepw"))
			assert.Equal(t, resp.StatusCode, want, "alice on %s", path)
		}
		resp := doGet(t, http.DefaultClient, allowedBase+clusterPath, withBasic("admin1", "admin1pw"))
		assert.Equal(t, resp.StatusCode, http.StatusForbidden, "admin1 is not in yk-users")
	})
}

// TestCoreLDAPAuthorizationMemberOf: the same role based authorization as
// TestCoreLDAPAuthorizationRBAC, but against a directory that populates
// memberOf, so group membership resolves to DNs rather than through the group
// entry search. Configured group names stay short - that is the contract this
// pins.
func TestCoreLDAPAuthorizationMemberOf(t *testing.T) {
	l := startLDAPMemberOfContainer(t)
	// YUNIKORN_LDAP_GROUP_ATTRIBUTE is left unset so the memberOf default
	// applies; loadConfig clears every YUNIKORN_* first
	roleEnv := map[string]string{
		"YUNIKORN_AUTH_MODE":           "ldap",
		"YUNIKORN_LDAP_COOKIE_SECRET":  "cookie-secret",
		"YUNIKORN_LDAP_ADMIN_GROUPS":   "yk-admins",
		"YUNIKORN_LDAP_VIEWER_GROUPS":  "yk-viewers",
		"YUNIKORN_LDAP_SERVICE_GROUPS": "yk-service",
	}
	base := startCoreServer(t, mergeEnv(ldapEnv(l), roleEnv), echoRoutes())

	tests := []struct {
		user, pass string
		wants      map[string]int
	}{
		{"admin1", "admin1pw", map[string]int{
			clusterPath:   http.StatusOK,
			schedulerPath: http.StatusOK,
			metricsPath:   http.StatusOK,
		}},
		{"viewer1", "viewer1pw", map[string]int{
			clusterPath:   http.StatusForbidden,
			schedulerPath: http.StatusOK,
			metricsPath:   http.StatusForbidden,
		}},
		{"svc1", "svc1pw", map[string]int{
			clusterPath:   http.StatusForbidden,
			schedulerPath: http.StatusForbidden,
			metricsPath:   http.StatusOK,
		}},
		{"bob", "bobpw", map[string]int{
			clusterPath:   http.StatusForbidden,
			schedulerPath: http.StatusForbidden,
			metricsPath:   http.StatusForbidden,
		}},
	}
	for _, tc := range tests {
		t.Run(tc.user, func(t *testing.T) {
			for path, want := range tc.wants {
				resp := doGet(t, http.DefaultClient, base+path, withBasic(tc.user, tc.pass))
				assert.Equal(t, resp.StatusCode, want, "%s on %s", tc.user, path)
			}
		})
	}

	t.Run("wrong password rejected", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, base+schedulerPath, withBasic("svc1", "wrong"))
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
	})

	// Two independent reasons the DN below cannot match: GroupSet.UnmarshalText
	// splits the role lists on ",", and normalizeLDAPGroupNames keeps only the
	// leading RDN value. Only meaningful next to the subtests above, which prove
	// group resolution works on this directory - split out on its own this would
	// pass on a broken bootstrap.
	t.Run("group DN cannot be configured as a role", func(t *testing.T) {
		dnBase := startCoreServer(t, mergeEnv(ldapEnv(l), roleEnv, map[string]string{
			"YUNIKORN_LDAP_ADMIN_GROUPS": "cn=yk-admins,ou=groups," + ldapBaseDN,
		}), echoRoutes())
		resp := doGet(t, http.DefaultClient, dnBase+clusterPath, withBasic("admin1", "admin1pw"))
		assert.Equal(t, resp.StatusCode, http.StatusForbidden)
	})
}

// TestCoreMTLS: the mtls mode serves only TLS connections presenting a client
// certificate signed by the configured CA.
func TestCoreMTLS(t *testing.T) {
	pki := newPKI(t, "e2e-ca")
	serverCert, serverKey := pki.issue(t, "server")
	clientCert, clientKey := pki.issue(t, "client")

	otherPKI := newPKI(t, "other-ca")
	strangerCert, strangerKey := otherPKI.issue(t, "stranger")

	base := startCoreServer(t, map[string]string{
		"YUNIKORN_AUTH_MODE":     "mtls",
		"YUNIKORN_TLS_CERT_FILE": serverCert,
		"YUNIKORN_TLS_KEY_FILE":  serverKey,
		"YUNIKORN_TLS_CA_FILE":   pki.CAFile,
	}, echoRoutes())

	t.Run("client certificate accepted", func(t *testing.T) {
		resp := doGet(t, tlsClient(t, pki.CAFile, clientCert, clientKey), base+clusterPath)
		assert.Equal(t, resp.StatusCode, http.StatusOK)
	})

	t.Run("no client certificate rejected", func(t *testing.T) {
		_, err := tryGet(tlsClient(t, pki.CAFile, "", ""), base+clusterPath)
		assert.Assert(t, err != nil, "handshake without a client certificate must fail")
	})

	t.Run("certificate from unknown CA rejected", func(t *testing.T) {
		_, err := tryGet(tlsClient(t, pki.CAFile, strangerCert, strangerKey), base+clusterPath)
		assert.Assert(t, err != nil, "handshake with a foreign client certificate must fail")
	})
}

// TestCoreKerberosSPNEGO: the kerberos mode authenticates via SPNEGO against
// the service keytab; YUNIKORN_USE_X_GROUPS additionally injects
// proxy-provided groups into the identity.
func TestCoreKerberosSPNEGO(t *testing.T) {
	kdc := startKDCContainer(t)
	env := map[string]string{
		"YUNIKORN_AUTH_MODE":   "kerberos",
		"YUNIKORN_KEYTAB_PATH": kdc.KeytabFile,
	}
	base := startCoreServer(t, env, echoRoutes())

	t.Run("no ticket challenged", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, base+clusterPath)
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
	})

	t.Run("valid ticket authenticates", func(t *testing.T) {
		resp := spnegoGet(t, spnegoClient(t, kdc, "alice", "alicepw"), base+clusterPath)
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		echo := decodeEcho(t, resp)
		assert.Equal(t, stripRealm(echo.User), "alice")
		assert.Equal(t, echo.Authenticated, true)
	})

	t.Run("X-Groups ignored unless enabled", func(t *testing.T) {
		resp := spnegoGet(t, spnegoClient(t, kdc, "alice", "alicepw"), base+clusterPath,
			withHeader("X-Groups", "dev,ops"))
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		assert.Assert(t, !containsGroup(decodeEcho(t, resp).Groups, "dev"))
	})

	t.Run("X-Groups injected when enabled", func(t *testing.T) {
		xgBase := startCoreServer(t, mergeEnv(env, map[string]string{
			"YUNIKORN_USE_X_GROUPS": "true",
		}), echoRoutes())
		resp := spnegoGet(t, spnegoClient(t, kdc, "alice", "alicepw"), xgBase+clusterPath,
			withHeader("X-Groups", "dev, ops"))
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		echo := decodeEcho(t, resp)
		assert.Assert(t, containsGroup(echo.Groups, "dev"))
		assert.Assert(t, containsGroup(echo.Groups, "ops"))
	})

	t.Run("broken keytab rejects everything", func(t *testing.T) {
		brokenBase := startCoreServer(t, map[string]string{
			"YUNIKORN_AUTH_MODE":   "kerberos",
			"YUNIKORN_KEYTAB_PATH": "/nonexistent/service.keytab",
		}, echoRoutes())
		resp := spnegoGet(t, spnegoClient(t, kdc, "alice", "alicepw"), brokenBase+clusterPath)
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
	})
}

// TestCoreKerberosLDAPAuthorization: the kerberos_ldap mode authenticates via
// SPNEGO and authorizes via LDAP group role mappings.
func TestCoreKerberosLDAPAuthorization(t *testing.T) {
	kdc := startKDCContainer(t)
	l := startLDAPContainer(t)
	base := startCoreServer(t, mergeEnv(ldapEnv(l), map[string]string{
		"YUNIKORN_AUTH_MODE":          "kerberos_ldap",
		"YUNIKORN_KEYTAB_PATH":        kdc.KeytabFile,
		"YUNIKORN_LDAP_ADMIN_GROUPS":  "yk-admins",
		"YUNIKORN_LDAP_VIEWER_GROUPS": "yk-viewers",
	}), echoRoutes())

	t.Run("admin reaches every category", func(t *testing.T) {
		cl := spnegoClient(t, kdc, "admin1", "admin1pw")
		for _, path := range []string{clusterPath, schedulerPath, metricsPath} {
			resp := spnegoGet(t, cl, base+path)
			assert.Equal(t, resp.StatusCode, http.StatusOK, path)
		}
	})

	t.Run("viewer reaches only scheduler routes", func(t *testing.T) {
		cl := spnegoClient(t, kdc, "viewer1", "viewer1pw")
		resp := spnegoGet(t, cl, base+schedulerPath)
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		resp = spnegoGet(t, cl, base+clusterPath)
		assert.Equal(t, resp.StatusCode, http.StatusForbidden)
	})

	t.Run("principal without role is forbidden", func(t *testing.T) {
		cl := spnegoClient(t, kdc, "alice", "alicepw")
		resp := spnegoGet(t, cl, base+clusterPath)
		assert.Equal(t, resp.StatusCode, http.StatusForbidden)
	})
}

// TestCoreMetricsAuthOverride: the metrics-only listener (the k8shim
// exposeMetricsOnly mode) inherits the main authentication unless the
// YUNIKORN_METRICS_AUTH_* override changes or disables it.
func TestCoreMetricsAuthOverride(t *testing.T) {
	const mainSecret = "main-secret"

	t.Run("inherits main authentication", func(t *testing.T) {
		base := startMetricsServer(t, map[string]string{
			"YUNIKORN_AUTH_SHARED_SECRET": mainSecret,
		})
		resp := doGet(t, http.DefaultClient, base+"/metrics")
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
		resp = doGet(t, http.DefaultClient, base+"/metrics",
			withToken(signToken(mainSecret, "prometheus", nil, time.Hour)))
		assert.Equal(t, resp.StatusCode, http.StatusOK)
	})

	t.Run("none disables metrics authentication", func(t *testing.T) {
		base := startMetricsServer(t, map[string]string{
			"YUNIKORN_AUTH_SHARED_SECRET": mainSecret,
			"YUNIKORN_METRICS_AUTH_MODE":  "none",
		})
		resp := doGet(t, http.DefaultClient, base+"/metrics")
		assert.Equal(t, resp.StatusCode, http.StatusOK)
	})

	t.Run("dedicated metrics secret", func(t *testing.T) {
		base := startMetricsServer(t, map[string]string{
			"YUNIKORN_AUTH_SHARED_SECRET":         mainSecret,
			"YUNIKORN_METRICS_AUTH_SHARED_SECRET": "metrics-secret",
		})
		resp := doGet(t, http.DefaultClient, base+"/metrics",
			withToken(signToken(mainSecret, "prometheus", nil, time.Hour)))
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized, "main secret must not open metrics")
		resp = doGet(t, http.DefaultClient, base+"/metrics",
			withToken(signToken("metrics-secret", "prometheus", nil, time.Hour)))
		assert.Equal(t, resp.StatusCode, http.StatusOK)
	})
}

// TestCoreUnknownRouteNameForbidden: with authentication enabled, a route
// registered under an unknown category name is never served.
func TestCoreUnknownRouteNameForbidden(t *testing.T) {
	const secret = "core-secret"
	bogus := webservice.Route{
		Name:        "Bogus",
		Method:      http.MethodGet,
		Pattern:     "/bogus",
		HandlerFunc: identityEcho,
	}
	base := startCoreServer(t, map[string]string{
		"YUNIKORN_AUTH_SHARED_SECRET": secret,
	}, []webservice.Route{bogus})

	resp := doGet(t, http.DefaultClient, base+"/bogus",
		withToken(signToken(secret, "tester", nil, time.Hour)))
	assert.Equal(t, resp.StatusCode, http.StatusForbidden)
}
