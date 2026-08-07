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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apache/yunikorn-core/pkg/webservice"
	"gotest.tools/v3/assert"
)

func TestWebServerServesEmbeddedStaticAndProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "OK")
	}))
	defer proxy.Close()

	server, err := NewWebServer(&webservice.Config{ListenAddress: "127.0.0.1:40002", K8Shim: webservice.K8ShimConfig{URL: proxy.URL}})
	assert.NilError(t, err)
	server.Start()
	defer server.Stop()

	getBody := func(path string) string {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			res, err := http.Get("http://127.0.0.1:40002" + path)
			if err != nil {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			body, err := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if err != nil {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return string(body)
		}
		t.Fatal("timed out waiting for server response")
		return ""
	}

	body := getBody("/index.html")
	assert.Assert(t, len(body) > 0)
	assert.Assert(t, strings.Contains(body, "<html") || strings.Contains(body, "<!doctype"))
	assert.Assert(t, strings.Contains(getBody("/ws/v1/clusters"), "OK"))
}

func TestWebServerAddsSharedSecretToProxyRequests(t *testing.T) {
	// user -> web and web -> k8shim are independent legs with their own secrets
	userSecret := "user-secret"
	k8shimSecret := "k8shim-secret"
	signToken := func(secret, user string) string {
		payload, err := json.Marshal(map[string]any{"user": user, "exp": time.Now().Add(time.Hour).Unix()})
		assert.NilError(t, err)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(payload)
		return base64.StdEncoding.EncodeToString(payload) + "." + hex.EncodeToString(mac.Sum(nil))
	}

	var proxiedAuth string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxiedAuth = r.Header.Get("Authorization")
		fmt.Fprintln(w, "OK")
	}))
	defer proxy.Close()

	server, err := NewWebServer(&webservice.Config{
		ListenAddress: "127.0.0.1:40003",
		Mode:          webservice.AuthModeSharedSecret,
		SharedSecret:  userSecret,
		K8Shim: webservice.K8ShimConfig{
			URL:          proxy.URL,
			SharedSecret: k8shimSecret,
		},
	})
	assert.NilError(t, err)
	server.Start()
	defer server.Stop()

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:40003/ws/v1/clusters", nil)
	assert.NilError(t, err)
	req.Header.Set("Authorization", "Token "+signToken(userSecret, "tester"))

	var res *http.Response
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		res, err = http.DefaultClient.Do(req)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	assert.NilError(t, err)
	defer res.Body.Close()
	assert.Equal(t, res.StatusCode, http.StatusOK)

	// the proxied request carries a token signed with the k8shim secret,
	// not the user's incoming token
	assert.Assert(t, strings.HasPrefix(proxiedAuth, "Token "))
	proxiedToken := strings.TrimPrefix(proxiedAuth, "Token ")
	segs := strings.Split(proxiedToken, ".")
	assert.Equal(t, len(segs), 2)
	payload, err := base64.StdEncoding.DecodeString(segs[0])
	assert.NilError(t, err)
	mac := hmac.New(sha256.New, []byte(k8shimSecret))
	mac.Write(payload)
	assert.Equal(t, segs[1], hex.EncodeToString(mac.Sum(nil)))
}
