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
	"net/http"
	"testing"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/spnego"
	"gotest.tools/v3/assert"
)

// spnegoClient logs the given principal in against the containerized KDC and
// returns an HTTP client performing SPNEGO for the HTTP/localhost service.
// It uses the same Kerberos library as the server side.
func spnegoClient(t *testing.T, kdc *kdcServer, user, password string) *spnego.Client {
	t.Helper()
	krbConf, err := config.NewFromString(kdc.ClientConf)
	assert.NilError(t, err)
	cl := client.NewWithPassword(user, kdc.Realm, password, krbConf, client.DisablePAFXFAST(true))
	assert.NilError(t, cl.Login())
	t.Cleanup(cl.Destroy)
	return spnego.NewClient(cl, nil, kerbSPN)
}

func spnegoGet(t *testing.T, cl *spnego.Client, url string, opts ...func(*http.Request)) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	assert.NilError(t, err)
	for _, o := range opts {
		o(req)
	}
	resp, err := cl.Do(req)
	assert.NilError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}
