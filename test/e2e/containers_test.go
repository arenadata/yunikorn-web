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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
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

	ldapMemberOfOnce sync.Once
	ldapMemberOfSrv  *ldapServer
	ldapMemberOfErr  error

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
			// the port first opens on a temporary slapd the image then stops and
			// reconfigures, discarding anything seeded into it; "slapd starting"
			// is logged once, by the final slapd
			WaitingFor: wait.ForAll(
				wait.ForLog("slapd starting"),
				wait.ForListeningPort("389/tcp"),
			).WithDeadline(3 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		return nil, err
	}
	registerCleanup(func() { _ = c.Terminate(context.Background()) })

	// The port opens while the image's first-start bootstrap may still be
	// running, and that bootstrap can overwrite cn=config changes applied too
	// early. Instead of relying on timing, repeat the whole sequence — seed
	// the entries, apply the ACL, verify — until the directory is actually in
	// the state the tests need. The ACL is required because the webservice
	// looks groups up on the connection re-bound as the authenticated user,
	// so users must be able to read the directory (as they can in Active
	// Directory); the image's default ACL only lets a user read their own
	// entry. The verification therefore searches as a regular user.
	exec := func(cmd ...string) (int, string, error) {
		code, out, execErr := c.Exec(ctx, cmd)
		var msg []byte
		if out != nil {
			msg, _ = io.ReadAll(out)
		}
		return code, string(msg), execErr
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		var step, msg string
		var code int
		var execErr error

		// exit 0 = seeded, exit 68 = entries already exist
		step = "seed"
		code, msg, execErr = exec("ldapadd", "-x", "-H", "ldap://localhost",
			"-D", ldapAdminDN, "-w", ldapAdminPW, "-f", "/tmp/seed.ldif")
		if execErr == nil && (code == 0 || code == 68) {
			step = "acl"
			code, msg, execErr = exec("ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///", "-f", "/tmp/acl.ldif")
		}
		if execErr == nil && code == 0 {
			step = "verify user read access"
			code, msg, execErr = exec("ldapsearch", "-x", "-H", "ldap://localhost",
				"-D", "uid=bob,ou=people,"+ldapBaseDN, "-w", "bobpw",
				"-b", "ou=groups,"+ldapBaseDN, "-s", "base", "dn")
		}
		if execErr == nil && code == 0 {
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("LDAP bootstrap failed at %q: exit=%d err=%v output=%s", step, code, execErr, msg)
		}
		time.Sleep(2 * time.Second)
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

// startLDAPMemberOfContainer starts (once per test run) a second OpenLDAP
// server, seeded like startLDAPContainer but with the memberof overlay, so
// users carry a memberOf attribute holding group DNs.
func startLDAPMemberOfContainer(t *testing.T) *ldapServer {
	t.Helper()
	ldapMemberOfOnce.Do(func() { ldapMemberOfSrv, ldapMemberOfErr = launchLDAPMemberOf() })
	if ldapMemberOfErr != nil {
		t.Fatalf("unable to start memberOf LDAP container: %v", ldapMemberOfErr)
	}
	return ldapMemberOfSrv
}

// launchLDAPMemberOf is a deliberate near duplicate of launchLDAP: the group
// entry search runs only when the group attribute yields nothing, so one
// directory can cover only one of the two paths. Keep them separate.
//
// The overlay does not backfill, and ldapadd will not rewrite entries that
// already exist, so every attempt deletes the data tree before seeding. Groups
// go first: olcMemberOfRefInt rewrites surviving group entries when their
// members disappear, which can leave a groupOfNames with no member at all.
func launchLDAPMemberOf() (*ldapServer, error) {
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
				HostFilePath:      "testdata/ldap/memberof.ldif",
				ContainerFilePath: "/tmp/memberof.ldif",
				FileMode:          0o644,
			}, {
				HostFilePath:      "testdata/ldap/seed.ldif",
				ContainerFilePath: "/tmp/seed.ldif",
				FileMode:          0o644,
			}, {
				HostFilePath:      "testdata/ldap/acl.ldif",
				ContainerFilePath: "/tmp/acl.ldif",
				FileMode:          0o644,
			}},
			// see launchLDAP
			WaitingFor: wait.ForAll(
				wait.ForLog("slapd starting"),
				wait.ForListeningPort("389/tcp"),
			).WithDeadline(3 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		return nil, err
	}
	registerCleanup(func() { _ = c.Terminate(context.Background()) })

	// Multiplexed strips the docker stream framing, whose frame headers can
	// otherwise land mid line and defeat the content check below.
	exec := func(cmd ...string) (int, string, error) {
		code, out, execErr := c.Exec(ctx, cmd, tcexec.Multiplexed())
		var msg []byte
		if out != nil {
			msg, _ = io.ReadAll(out)
		}
		return code, string(msg), execErr
	}
	svcDN := "uid=svc1,ou=people," + ldapBaseDN
	deadline := time.Now().Add(3 * time.Minute)
	for {
		var step, msg string
		var code int
		var execErr error
		ok := true

		// each step runs only once the previous one succeeded; the reset makes
		// every attempt rewrite the entries, so the verification at the end is
		// the only real gate
		run := func(name string, tolerate []int, cmd ...string) {
			if !ok {
				return
			}
			step = name
			code, msg, execErr = exec(cmd...)
			ok = execErr == nil && slices.Contains(tolerate, code)
		}

		// exit 32 = the subtree is not there
		run("reset groups", []int{0, 32}, "ldapdelete", "-x", "-H", "ldap://localhost",
			"-D", ldapAdminDN, "-w", ldapAdminPW, "-r", "ou=groups,"+ldapBaseDN)
		run("reset people", []int{0, 32}, "ldapdelete", "-x", "-H", "ldap://localhost",
			"-D", ldapAdminDN, "-w", ldapAdminPW, "-r", "ou=people,"+ldapBaseDN)
		// exit 20 = the overlay survived an earlier attempt; the module itself
		// is already loaded by the image
		run("memberof overlay", []int{0, 20},
			"ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///", "-f", "/tmp/memberof.ldif")
		// exit 0 = seeded, exit 68 = a reset did not take; verification decides
		run("seed", []int{0, 68}, "ldapadd", "-x", "-H", "ldap://localhost",
			"-D", ldapAdminDN, "-w", ldapAdminPW, "-f", "/tmp/seed.ldif")
		run("acl", []int{0},
			"ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///", "-f", "/tmp/acl.ldif")
		run("verify user read access", []int{0}, "ldapsearch", "-x", "-H", "ldap://localhost",
			"-D", "uid=bob,ou=people,"+ldapBaseDN, "-w", "bobpw",
			"-b", "ou=groups,"+ldapBaseDN, "-s", "base", "dn")
		// memberOf is operational, so it must be asked for by name, and a search
		// returning the entry without it still exits 0 - hence the content check
		run("verify memberOf populated", []int{0}, "ldapsearch", "-x", "-H", "ldap://localhost",
			"-D", svcDN, "-w", "svc1pw", "-b", svcDN, "-s", "base", "-LLL", "memberOf")
		if ok && !strings.Contains(strings.ToLower(msg), "memberof: cn=yk-service") {
			step, ok = "verify memberOf populated: attribute missing", false
		}
		if ok {
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("memberOf LDAP bootstrap failed at %q: exit=%d err=%v output=%s",
				step, code, execErr, msg)
		}
		time.Sleep(2 * time.Second)
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
