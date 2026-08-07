<!--
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 -->

# Yunikorn web UI
YuniKorn web provides a web interface on top of the scheduler. It provides insight in the current and historic scheduler status.
It depends on `yunikorn-core` which encapsulates all the actual scheduling logic.

For detailed information on the components and how to build the overall scheduler please see the [yunikorn-core](https://github.com/apache/yunikorn-core).

This project was generated with [Angular CLI](https://github.com/angular/angular-cli) version 13.3.0.

## Development Environment setup
### Dependencies
The project requires a number of external tools to be installed before the build and development:
- [Node.js](https://nodejs.org/en/)
- [Angular CLI](https://github.com/angular/angular-cli)
- [Karma](https://karma-runner.github.io)
- [pnpm](https://www.npmjs.com/package/pnpm)
- [json-server](https://www.npmjs.com/package/json-server)

To manage our node packages, we've chosen pnpm. Simply execute the command `pnpm install` to set up all necessary dependencies. This single step ensures that your environment is fully prepared with all the required packages.

### Development server

Run `make start-dev` for a development server. Navigate to `http://localhost:4200/`. The application will automatically reload if you change any of the source files.

## Build

Run `make build` to build the project. The build artifacts will be stored in the `dist/` directory. Use `make build-prod` for a production build.
Production builds will add the `--prod` flag to the angular build.

### Docker image build
Image builds are geared towards a production build and will always build with the `--prod` flag set.

Run `make image` to build the docker image `apache/yunikorn:web-latest`.
Run `make run` to build the image and deploy the container from the docker image `apache/yunikorn:web-latest`.

You can set `REGISTRY`, `VERSION` and `DOCKER_ARCH` in the commandline to build docker image with a specified version, registry and host architecture. For example,
```
make image REGISTRY=apache VERSION=latest DOCKER_ARCH=amd64
```
This command will build binary with version `web-latest` and the docker full image tag is `apache/yunikorn:web-amd64-latest`.

The Makefile is smart enough to detect your host architecture but it will tag the image name.

### Running tests

All tests can be executed via `make test`. It will first build the project and then execute the unit tests followed by the end to end tests.
If you want to run the unit tests separately, run `pnpm test` to execute them via [Karma](https://karma-runner.github.io). If you want to run the unit tests with code coverage, run `pnpm test:coverage`.

## Local development
Beside the simple all in way to start the development server via make you can also start a development environment manually.

The application depends on [json-server](https://www.npmjs.com/package/json-server) for data. Install json-server locally. Run `pnpm start:srv` to start json-server for local development.
Run `pnpm start` to start the angular development server and navigate to `http://localhost:4200/`.

After updating the context in the `json-db.json` or `json-route.json`, checking the json server is available  by running `make json-server`.

## Security fixes
To fix CVEs reported by dependabot, first try to understand if the fix is in direct or indirect dependency. You can use `pnpm why <dependency-name>` command for this. If the dependency is direct dependency update it to the version in which it is fixed - `pnpm up <dependency-name@fixed-version>`. If it is transitive dependency, check if it got updated in the direct dependency of which it is part of. If yes, then update the direct dependency as previously explained. If not, override the transitive dependency only for the affected direct depepndency. For example of this refer to `pnpm.overrides` section of package.json.

## Further help
To get more help on the Angular CLI use `ng help` or go check out the [Angular CLI README](https://github.com/angular/angular-cli/blob/master/README.md).

## Code scaffolding
Run `ng generate component component-name` to generate a new component.

You can also use `ng generate directive|pipe|service|class|guard|interface|enum|module`.

## Web server
The Go web server (`pkg/webserver`) is built on the shared webservice from
`yunikorn-core` (`pkg/webservice`): the router serves the embedded static UI,
while a proxy middleware forwards requests under `/ws/` to the k8shim REST API
at `YUNIKORN_K8SHIM_URL` (default `http://127.0.0.1:9080`). All configuration
is read from `YUNIKORN_`-prefixed environment variables by the single
`webservice.Config` type — see the `yunikorn-core` README for the full
variable reference.

## Port configurations
The default port used for the web server is port 9889; it can be changed with
the `YUNIKORN_LISTEN_ADDRESS` environment variable. TLS for the listener is
enabled with `YUNIKORN_TLS_CERT_FILE` / `YUNIKORN_TLS_KEY_FILE`.

## Authentication
Authentication is split into two independent legs configured separately so the
settings cannot be confused:

- user -> web: how end users authenticate to this web server, configured with
  `YUNIKORN_AUTH_MODE` (`mtls`, `shared_secret`, `ldap`, `kerberos`,
  `kerberos_ldap`) and the related `YUNIKORN_AUTH_*` / `YUNIKORN_LDAP_*` /
  `YUNIKORN_KEYTAB_PATH` variables;
- web -> k8shim: how this web server authenticates to the k8shim REST API when
  proxying `/ws/` requests. The user's `Authorization` header is never
  forwarded. Options:
  - shared secret: `YUNIKORN_K8SHIM_AUTH_SHARED_SECRET=<secret>` here, and the
    same secret on the k8shim side as `YUNIKORN_AUTH_MODE=shared_secret` +
    `YUNIKORN_AUTH_SHARED_SECRET=<secret>`; the proxy attaches a token signed
    from the authenticated user identity to every forwarded request;
  - mTLS: `YUNIKORN_K8SHIM_TLS_CERT_FILE`, `YUNIKORN_K8SHIM_TLS_KEY_FILE`,
    `YUNIKORN_K8SHIM_TLS_CA_FILE` here, and `YUNIKORN_AUTH_MODE=mtls` with
    `YUNIKORN_TLS_*` on the k8shim side.

## How do I contribute code?
See how to contribute code from [this guide](https://yunikorn.apache.org/community/how_to_contribute).
