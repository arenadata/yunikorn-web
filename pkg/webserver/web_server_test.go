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
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestParseK8ShimURL(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		origin     string
		socketPath string
		wantErr    string
	}{
		{name: "http", raw: "http://127.0.0.1:9080", origin: "http://127.0.0.1:9080"},
		{name: "https with path", raw: "https://k8shim:9080/base", origin: "https://k8shim:9080/base"},
		{name: "unix absolute", raw: "unix:///tmp/k8shim.sock", origin: "http://localhost", socketPath: "/tmp/k8shim.sock"},
		{name: "unix without authority", raw: "unix:/tmp/k8shim.sock", origin: "http://localhost", socketPath: "/tmp/k8shim.sock"},
		{name: "unix relative", raw: "unix://k8shim.sock", origin: "http://localhost", socketPath: "k8shim.sock"},
		{name: "unix opaque", raw: "unix:k8shim.sock", origin: "http://localhost", socketPath: "k8shim.sock"},
		{name: "unix without path", raw: "unix://", wantErr: "missing socket path"},
		{name: "http without host", raw: "http:///ws/v1", wantErr: "missing host"},
		{name: "no scheme", raw: "127.0.0.1/ws", wantErr: "unsupported k8shim URL scheme"},
		{name: "host port only", raw: "127.0.0.1:9080", wantErr: "invalid k8shim URL"},
		{name: "unknown scheme", raw: "tcp://127.0.0.1:9080", wantErr: "unsupported k8shim URL scheme"},
		{name: "unparsable", raw: "http://[::1", wantErr: "invalid k8shim URL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origin, socketPath, err := parseK8ShimURL(tt.raw)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			assert.NilError(t, err)
			assert.Equal(t, origin.String(), tt.origin)
			assert.Equal(t, socketPath, tt.socketPath)
		})
	}
}

func TestNewK8ShimProxyRejectsTLSOverUnixSocket(t *testing.T) {
	_, err := newK8ShimProxy(&webservice.Config{
		K8Shim: webservice.K8ShimConfig{
			URL: "unix:///tmp/k8shim.sock",
			TLS: &webservice.TLSConfig{CAFile: "ca.pem"},
		},
	})
	assert.ErrorContains(t, err, "TLS is not supported with a unix socket URL")
}

func TestWebServerProxiesOverUnixSocket(t *testing.T) {
	// not t.TempDir(): its path blows the ~100 byte sockaddr_un limit on macOS
	dir, err := os.MkdirTemp("", "yk")
	assert.NilError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socketPath := filepath.Join(dir, "k8shim.sock")
	listener, err := net.Listen("unix", socketPath)
	assert.NilError(t, err)

	shim := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "OK %s", r.URL.Path)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = shim.Serve(listener) }()
	defer func() { _ = shim.Close() }()

	server, err := NewWebServer(&webservice.Config{
		ListenAddress: "127.0.0.1:40004",
		K8Shim:        webservice.K8ShimConfig{URL: "unix://" + socketPath},
	})
	assert.NilError(t, err)
	server.Start()
	defer server.Stop()

	var body string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		res, err := http.Get("http://127.0.0.1:40004/ws/v1/clusters")
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		raw, err := io.ReadAll(res.Body)
		_ = res.Body.Close()
		assert.NilError(t, err)
		assert.Equal(t, res.StatusCode, http.StatusOK)
		body = string(raw)
		break
	}
	assert.Equal(t, body, "OK /ws/v1/clusters")
}
