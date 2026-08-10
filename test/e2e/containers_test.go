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
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// The test users seeded into both the LDAP directory (testdata/ldap/seed.ldif)
// and the Kerberos KDC (testdata/kdc/entrypoint.sh):
//
//	admin1/admin1pw   member of yk-admins  (admin role)
//	viewer1/viewer1pw member of yk-viewers (viewer role)
//	svc1/svc1pw       member of yk-service (service role)
//	alice/alicepw     member of yk-users   (no role, for allowed-groups tests)
//	bob/bobpw         no groups            (LDAP only)
const (
	ldapAdminDN = "cn=admin,dc=example,dc=org"
	ldapAdminPW = "adminpassword"
	ldapBaseDN  = "dc=example,dc=org"
	kerbRealm   = "EXAMPLE.ORG"
	kerbSPN     = "HTTP/localhost"
)

type ldapServer struct {
	URL string
}

type kdcServer struct {
	Realm      string
	ClientConf string // krb5.conf contents for clients running on the host
	KeytabFile string // HTTP/localhost service keytab copied out of the container
}

var (
	ldapOnce sync.Once
	ldapSrv  *ldapServer
	ldapErr  error

	kdcOnce sync.Once
	kdcSrv  *kdcServer
	kdcErr  error

	cleanupMu  sync.Mutex
	cleanupFns []func()
)

func TestMain(m *testing.M) {
	code := m.Run()
	cleanupMu.Lock()
	for _, f := range cleanupFns {
		f()
	}
	cleanupMu.Unlock()
	os.Exit(code)
}

func registerCleanup(f func()) {
	cleanupMu.Lock()
	cleanupFns = append(cleanupFns, f)
	cleanupMu.Unlock()
}

// startLDAPContainer starts (once per test run) an OpenLDAP server seeded with
// the test users and groups.
func startLDAPContainer(t *testing.T) *ldapServer {
	t.Helper()
	ldapOnce.Do(func() { ldapSrv, ldapErr = launchLDAP() })
	if ldapErr != nil {
		t.Fatalf("unable to start LDAP container: %v", ldapErr)
	}
	return ldapSrv
}

func launchLDAP() (*ldapServer, error) {
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "osixia/openldap:1.5.0",
			ExposedPorts: []string{"389/tcp"},
			Env: map[string]string{
				"LDAP_ORGANISATION":   "Example",
				"LDAP_DOMAIN":         "example.org",
				"LDAP_ADMIN_PASSWORD": ldapAdminPW,
			},
			Files: []testcontainers.ContainerFile{{
				HostFilePath:      "testdata/ldap/seed.ldif",
				ContainerFilePath: "/tmp/seed.ldif",
				FileMode:          0o644,
			}, {
				HostFilePath:      "testdata/ldap/acl.ldif",
				ContainerFilePath: "/tmp/acl.ldif",
				FileMode:          0o644,
			}},
			WaitingFor: wait.ForListeningPort("389/tcp").WithStartupTimeout(3 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		return nil, err
	}
	registerCleanup(func() { _ = c.Terminate(context.Background()) })

	// slapd may still be bootstrapping right after the port opens: retry the
	// seed until it applies (exit 0) or already exists (exit 68).
	deadline := time.Now().Add(2 * time.Minute)
	for {
		code, out, execErr := c.Exec(ctx, []string{
			"ldapadd", "-x", "-H", "ldap://localhost",
			"-D", ldapAdminDN, "-w", ldapAdminPW, "-f", "/tmp/seed.ldif",
		})
		if execErr == nil && (code == 0 || code == 68) {
			break
		}
		if time.Now().After(deadline) {
			var msg []byte
			if out != nil {
				msg, _ = io.ReadAll(out)
			}
			return nil, fmt.Errorf("seeding LDAP failed: exit=%d err=%v output=%s", code, execErr, msg)
		}
		time.Sleep(2 * time.Second)
	}

	// The webservice looks groups up on the connection re-bound as the
	// authenticated user, so authenticated users must be able to read the
	// directory (as they can in Active Directory); the default ACL of this
	// image only lets a user read their own entry.
	code, out, execErr := c.Exec(ctx, []string{"ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///", "-f", "/tmp/acl.ldif"})
	if execErr != nil || code != 0 {
		var msg []byte
		if out != nil {
			msg, _ = io.ReadAll(out)
		}
		return nil, fmt.Errorf("applying LDAP ACL failed: exit=%d err=%v output=%s", code, execErr, msg)
	}

	host, err := c.Host(ctx)
	if err != nil {
		return nil, err
	}
	port, err := c.MappedPort(ctx, "389/tcp")
	if err != nil {
		return nil, err
	}
	return &ldapServer{URL: fmt.Sprintf("ldap://%s:%s", host, port.Port())}, nil
}

// startKDCContainer builds and starts (once per test run) a MIT Kerberos KDC
// with the test principals, and copies the HTTP/localhost service keytab to the
// host.
func startKDCContainer(t *testing.T) *kdcServer {
	t.Helper()
	kdcOnce.Do(func() { kdcSrv, kdcErr = launchKDC() })
	if kdcErr != nil {
		t.Fatalf("unable to start KDC container: %v", kdcErr)
	}
	return kdcSrv
}

func launchKDC() (*kdcServer, error) {
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context: "testdata/kdc",
			},
			ExposedPorts: []string{"88/tcp"},
			WaitingFor:   wait.ForListeningPort("88/tcp").WithStartupTimeout(5 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		return nil, err
	}
	registerCleanup(func() { _ = c.Terminate(context.Background()) })

	dir, err := os.MkdirTemp("", "yk-e2e-kdc-")
	if err != nil {
		return nil, err
	}
	registerCleanup(func() { _ = os.RemoveAll(dir) })

	// the keytab is written by the container entrypoint before the KDC starts
	// listening, so it exists by now
	rc, err := c.CopyFileFromContainer(ctx, "/var/keytabs/service.keytab")
	if err != nil {
		return nil, fmt.Errorf("copying service keytab: %w", err)
	}
	defer func() { _ = rc.Close() }()
	keytab, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	keytabFile := filepath.Join(dir, "service.keytab")
	if err = os.WriteFile(keytabFile, keytab, 0o600); err != nil {
		return nil, err
	}

	host, err := c.Host(ctx)
	if err != nil {
		return nil, err
	}
	port, err := c.MappedPort(ctx, "88/tcp")
	if err != nil {
		return nil, err
	}

	// udp_preference_limit forces TCP: only the TCP port is mapped to the host
	clientConf := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_realm = false
    dns_lookup_kdc = false
    udp_preference_limit = 1

[realms]
    %s = {
        kdc = %s:%s
    }
`, kerbRealm, kerbRealm, host, port.Port())

	return &kdcServer{Realm: kerbRealm, ClientConf: clientConf, KeytabFile: keytabFile}, nil
}
