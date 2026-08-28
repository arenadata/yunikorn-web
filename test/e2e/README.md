# E2E authentication tests

End to end tests for every authentication mode of the yunikorn-core webservice
and for the variants of the leg between yunikorn-web and the yunikorn-k8shim
REST API: the authentication of that leg and its two transports, TCP and the
unix socket.

The servers under test are the real ones:

- the **core webservice** server (`webservice.NewWebServer`) — the exact stack
  the k8shim serves on `:9080` (`entrypoint` → `StartWebApp`) and as the
  metrics-only listener (`exposeMetricsOnly`). The route table is the real
  scheduler REST route table; only the handlers are replaced with an identity
  echo so tests can observe the authenticated user, groups and headers that
  reached the handler.
- the **yunikorn-web** server (`webserver.NewWebServer`) — embedded UI plus
  the `/ws/` reverse proxy towards the k8shim.
- the **k8shim unix socket listener** — the listener the shim starts in
  `exposeMetricsOnly` mode (k8shim `pkg/cmd/shim/main.go`, `localServer`): the
  scheduler REST route table on a bare httprouter, served over a `0660` socket
  file with the timeouts of the shim and no authentication of its own.

They are configured through `YUNIKORN_*` environment variables, exactly like
the deployed services. External dependencies run in
[testcontainers](https://golang.testcontainers.org/):

- **OpenLDAP** (`osixia/openldap`) ×2, both seeded from `testdata/ldap/seed.ldif`:
  one plain, one with the `memberof` overlay (`testdata/ldap/memberof.ldif`).
  The group entry search runs only when the group attribute yields nothing, so
  a single directory can cover only one of the two paths.
- **MIT Kerberos KDC**, built from `testdata/kdc/`

## Running

Requires Docker.

```sh
cd test/e2e
go test ./...
```

The LDAP and KDC containers start once per `go test` run, on first use.

## Coverage

Core webservice authentication (user → k8shim listener), `core_auth_test.go`:

| Mode | Tests |
|---|---|
| disabled | all route categories served unauthenticated |
| `shared_secret` | valid/invalid/expired/foreign-secret tokens, wrong scheme, identity propagation |
| `shared_secret` + LDAP | group enrichment from the directory when the token carries no groups |
| `ldap` | BasicAuth against the directory, `YK_AUTH` cookie issue/replay/tamper, allowed-groups authorization |
| `ldap` RBAC | admin/viewer/service roles mapped from LDAP groups per route category; no-role and allowed-groups-only users |
| `ldap` RBAC + `memberOf` | the same role outcomes against the overlay directory, where membership resolves to DNs; also pins that a group DN cannot be configured as a role |
| `kerberos` | SPNEGO against the service keytab, `X-Groups` injection (only with `YUNIKORN_USE_X_GROUPS`), broken keytab fails closed |
| `kerberos_ldap` | SPNEGO authentication plus LDAP role authorization |
| metrics override | `YUNIKORN_METRICS_AUTH_MODE=none` and a dedicated metrics secret on the metrics-only listener |
| `mtls` | client certificate required and verified against the configured CA |
| route guard | unknown route categories are 403 whenever authentication is enabled |

yunikorn-web ↔ yunikorn-k8shim (`web_shim_test.go`):

| Variant | Tests |
|---|---|
| header hygiene | the user's `Authorization` header never reaches the shim |
| shared secret leg | proxy signs a fresh token from the authenticated identity; user and groups propagate; the user token itself does not |
| secret mismatch | shim with a different secret rejects proxied requests |
| no user auth | without an authenticated identity no token is attached — protected shim rejects |
| TLS | web verifies the shim server certificate against `YUNIKORN_K8SHIM_TLS_CA_FILE`; untrusted certificate → 502 |
| mTLS | shim in `mtls` mode accepts only web instances presenting the configured client certificate |
| LDAP end to end | browser BasicAuth → web (`ldap` mode, RBAC) → shim (`shared_secret`); cookie replay; viewer role enforced before proxying |
| Kerberos end to end | browser SPNEGO → web (`kerberos` mode, `X-Groups`) → shim (`shared_secret`) |

yunikorn-web ↔ yunikorn-k8shim over a unix socket (`web_socket_test.go`),
`YUNIKORN_K8SHIM_URL=unix:///var/run/yunikorn/k8shim.sock`:

| Variant | Tests |
|---|---|
| proxying | method, path, path parameters, query, request body, status, response headers and a ~1 MiB body survive the socket; the static UI stays local |
| URL forms | `unix:///path` and `unix:/path` reach the same listener |
| header hygiene | the user's `Authorization` header never reaches the socket listener |
| shared secret leg | the proxy signs a token from the authenticated identity over the socket too; user, groups and expiry travel in it, the user's own token does not |
| no user auth | without an authenticated identity no token is attached |
| token validation | a socket listener that does validate the token (the full core stack on the socket) accepts it and sees the identity; a different secret is rejected |
| shim lifecycle | web starting before the shim, the shim going down and being restarted on the same path — all without restarting web |
| socket permissions | a socket file web may not open is a 502, never a proxied response |
| concurrency | parallel browsers are served over the same socket file |
| event stream | `/ws/v1/events/stream` is forwarded incrementally, not buffered until the stream ends |
| config validation | k8shim TLS on a socket URL, a URL without a socket path and an unknown scheme keep the server from starting |
| LDAP end to end | browser BasicAuth → web (`ldap` mode, RBAC) → shim over the socket; role authorization happens before anything is proxied |

## Deployment notes discovered by these tests

- **MIT krb5 ≥ 1.20 KDC**: service tickets carry a minimal PAC by default and
  the SPNEGO service in yunikorn-core fails to decode it
  (`PAC Info Buffers does not contain a KerbValidationInfo`). Create the HTTP
  service principal with `+no_auth_data_required` (see
  `testdata/kdc/entrypoint.sh`), or the `kerberos`/`kerberos_ldap` modes reject
  every ticket. Active Directory KDCs are not affected.
- **LDAP ACLs**: group membership is looked up on the connection re-bound as
  the authenticated user, so users need read access to the user and group
  subtrees (Active Directory default). For OpenLDAP an explicit
  `to * by users read` ACL is required (see `testdata/ldap/acl.ldif`).
- **memberOf vs group entries**: both resolution paths end up matching the
  plain group name (cn), so the `YUNIKORN_LDAP_*_GROUPS` role sets are
  configured the same way either way. When the directory returns a `memberOf`
  attribute the raw tokens are full DNs, and only the leading RDN value is kept;
  when it does not, membership is resolved through the group entry search
  (`member=<dn>`), which yields the cn directly. A group DN can therefore never
  be configured as a role: the role lists are also comma separated, and DNs
  contain commas. The group entry search only runs when the group attribute
  yields nothing, which is why the two paths need two directories to test.
- **`ldap` mode always authorizes**: with `YUNIKORN_AUTH_MODE=ldap` every
  route (including the static UI) goes through role authorization; without any
  `YUNIKORN_LDAP_{ADMIN,VIEWER,SERVICE,ALLOWED}_GROUPS` configured all users
  are 403. The viewer role can query the scheduler API but cannot load the
  static UI (the `StaticUI` category is not among its allowed routes).
- **the socket leg is unauthenticated**: the shim serves the socket without any
  authentication middleware, so the socket file permissions (`0660`) are the
  entire access control. web and the shim must share the socket volume and a
  user or group, and `YUNIKORN_K8SHIM_SOCKET_PATH` on the shim must name the
  same file as `YUNIKORN_K8SHIM_URL` on web. A signed token is still attached
  when `YUNIKORN_K8SHIM_AUTH_SHARED_SECRET` is configured, the socket listener
  simply ignores it today.
- **k8shim TLS and a unix URL are mutually exclusive**: the socket listener
  speaks plain HTTP, so `YUNIKORN_K8SHIM_TLS_*` together with a `unix://` URL
  fails at startup instead of silently dropping the client certificates.
- **socket paths are short**: `sockaddr_un` holds ~104 bytes on macOS and 108
  on Linux, which the Go test temporary directories (`t.TempDir()`, test name
  included) can exceed on their own; the tests create their own short temp dir.
- **the shim socket server has a 10 second `WriteTimeout`**: a long lived
  `/ws/v1/events/stream` over the socket is cut after 10 seconds, where the
  same stream over the `:9080` listener is not. The tests assert that events
  are forwarded incrementally, not that a stream can be held open.
