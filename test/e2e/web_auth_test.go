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
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"gotest.tools/v3/assert"
)

const (
	loginPath  = "/auth/login"
	logoutPath = "/auth/logout"
	whoamiPath = "/auth/whoami"
)

type whoami struct {
	Mode        string `json:"mode"`
	User        string `json:"user"`
	DisplayName string `json:"displayName"`
}

func decodeWhoami(t *testing.T, resp *http.Response) whoami {
	t.Helper()
	var who whoami
	assert.NilError(t, json.NewDecoder(resp.Body).Decode(&who))
	_ = resp.Body.Close()
	return who
}

func authCookieOf(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == "YK_AUTH" {
			return c
		}
	}
	t.Fatal("no YK_AUTH cookie in the response")
	return nil
}

func loginAs(t *testing.T, web, user, password string) *http.Response {
	t.Helper()
	body := `{"username":"` + user + `","password":"` + password + `"}`
	return doPost(t, http.DefaultClient, web+loginPath, "application/json", body)
}

// TestWebAuthEndpoints: the login the UI uses instead of the browser dialog.
func TestWebAuthEndpoints(t *testing.T) {
	l := startLDAPContainer(t)
	shim := startCoreServer(t, map[string]string{
		"YUNIKORN_AUTH_SHARED_SECRET": "shim-secret",
	}, echoRoutes())
	web := startWebServer(t, mergeEnv(ldapEnv(l), map[string]string{
		"YUNIKORN_AUTH_MODE":                 "ldap",
		"YUNIKORN_LDAP_COOKIE_SECRET":        "cookie-secret",
		"YUNIKORN_LDAP_ADMIN_GROUPS":         "yk-admins",
		"YUNIKORN_K8SHIM_URL":                shim,
		"YUNIKORN_K8SHIM_AUTH_SHARED_SECRET": "shim-secret",
	}))

	t.Run("whoami without a session", func(t *testing.T) {
		who := decodeWhoami(t, doGet(t, http.DefaultClient, web+whoamiPath))
		assert.Equal(t, who.Mode, "ldap")
		assert.Equal(t, who.User, "")
	})

	t.Run("the browser is not challenged", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, web+clusterPath)
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
		assert.Equal(t, resp.Header.Get("WWW-Authenticate"), "")
	})

	t.Run("the static bundle is public", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, web+"/")
		assert.Equal(t, resp.StatusCode, http.StatusOK)
	})

	t.Run("wrong password", func(t *testing.T) {
		resp := loginAs(t, web, "alice", "nope")
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
		assert.Equal(t, resp.Header.Get("WWW-Authenticate"), "")
	})

	t.Run("body that is not a pair of credentials", func(t *testing.T) {
		resp := doPost(t, http.DefaultClient, web+loginPath, "application/json", `{"username":"alice"}`)
		assert.Equal(t, resp.StatusCode, http.StatusBadRequest)
	})

	t.Run("login and whoami", func(t *testing.T) {
		resp := loginAs(t, web, "alice", "alicepw")
		assert.Equal(t, resp.StatusCode, http.StatusNoContent)

		who := decodeWhoami(t, doGet(t, http.DefaultClient, web+whoamiPath, withCookie(authCookieOf(t, resp))))
		assert.Equal(t, who.User, "alice")
		assert.Equal(t, who.DisplayName, "Alice Liddell")
	})

	t.Run("the session reaches the scheduler API", func(t *testing.T) {
		cookie := authCookieOf(t, loginAs(t, web, "admin1", "admin1pw"))
		resp := doGet(t, http.DefaultClient, web+clusterPath, withCookie(cookie))
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		assert.Equal(t, decodeEcho(t, resp).User, "admin1")

		// the display name falls back to cn when the entry has none
		who := decodeWhoami(t, doGet(t, http.DefaultClient, web+whoamiPath, withCookie(cookie)))
		assert.Equal(t, who.DisplayName, "admin1")
	})

	t.Run("logout clears the cookie", func(t *testing.T) {
		resp := doPost(t, http.DefaultClient, web+logoutPath, "", "")
		assert.Equal(t, resp.StatusCode, http.StatusNoContent)
		assert.Equal(t, authCookieOf(t, resp).MaxAge, -1)

		// without the cookie the browser is back to an unauthenticated client
		assert.Equal(t, doGet(t, http.DefaultClient, web+clusterPath).StatusCode, http.StatusUnauthorized)
	})

	t.Run("basic auth still works for api clients", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, web+clusterPath, withBasic("admin1", "admin1pw"))
		assert.Equal(t, resp.StatusCode, http.StatusOK)
	})
}

// TestWebAuthKerberos: no login page in the Kerberos modes, only whoami.
func TestWebAuthKerberos(t *testing.T) {
	kdc := startKDCContainer(t)
	shim := startCoreServer(t, map[string]string{
		"YUNIKORN_AUTH_SHARED_SECRET": "shim-secret",
	}, echoRoutes())
	web := startWebServer(t, map[string]string{
		"YUNIKORN_AUTH_MODE":                 "kerberos",
		"YUNIKORN_KEYTAB_PATH":               kdc.KeytabFile,
		"YUNIKORN_K8SHIM_URL":                shim,
		"YUNIKORN_K8SHIM_AUTH_SHARED_SECRET": "shim-secret",
	})

	t.Run("without a ticket", func(t *testing.T) {
		resp := doGet(t, http.DefaultClient, web+whoamiPath)
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
		assert.Equal(t, resp.Header.Get("WWW-Authenticate"), "Negotiate")
	})

	t.Run("whoami reports the principal", func(t *testing.T) {
		resp := spnegoGet(t, spnegoClient(t, kdc, "alice", "alicepw"), web+whoamiPath)
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		who := decodeWhoami(t, resp)
		assert.Equal(t, who.Mode, "kerberos")
		assert.Equal(t, stripRealm(who.User), "alice")
		assert.Equal(t, who.DisplayName, who.User)
	})

	t.Run("there is no login endpoint", func(t *testing.T) {
		resp := doPost(t, http.DefaultClient, web+loginPath, "application/json", `{"username":"alice","password":"alicepw"}`)
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
	})
}

// TestWebSessionRenewal: an active session outlives the cookie TTL and ends at
// the absolute limit.
func TestWebSessionRenewal(t *testing.T) {
	l := startLDAPContainer(t)
	shim := startCoreServer(t, map[string]string{
		"YUNIKORN_AUTH_SHARED_SECRET": "shim-secret",
	}, echoRoutes())
	web := startWebServer(t, mergeEnv(ldapEnv(l), map[string]string{
		"YUNIKORN_AUTH_MODE":                 "ldap",
		"YUNIKORN_LDAP_COOKIE_SECRET":        "cookie-secret",
		"YUNIKORN_LDAP_ADMIN_GROUPS":         "yk-admins",
		"YUNIKORN_LDAP_COOKIE_TTL":           "6s",
		"YUNIKORN_LDAP_SESSION_MAX_LIFETIME": "12s",
		"YUNIKORN_K8SHIM_URL":                shim,
		"YUNIKORN_K8SHIM_AUTH_SHARED_SECRET": "shim-secret",
	}))

	cookie := authCookieOf(t, loginAs(t, web, "admin1", "admin1pw"))
	deadline := time.Now().Add(9 * time.Second)
	renewals := 0
	for time.Now().Before(deadline) {
		time.Sleep(4 * time.Second)
		resp := doGet(t, http.DefaultClient, web+clusterPath, withCookie(cookie))
		assert.Equal(t, resp.StatusCode, http.StatusOK, "the session should survive activity")
		for _, c := range resp.Cookies() {
			if c.Name == "YK_AUTH" {
				cookie = c
				renewals++
			}
		}
	}
	assert.Assert(t, renewals > 0, "the cookie was never renewed")

	// past the absolute limit no activity helps any more
	time.Sleep(7 * time.Second)
	resp := doGet(t, http.DefaultClient, web+clusterPath, withCookie(cookie))
	assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
}
