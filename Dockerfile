#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Build frontend assets
FROM node:24.16-alpine AS frontend
WORKDIR /work
COPY *.json *.js *.yaml .browserslistrc /work/
COPY src /work/src/
ARG PNPM_VERSION=11.5
RUN npm install -g pnpm@$PNPM_VERSION
RUN pnpm fetch
RUN pnpm install -r --offline
RUN pnpm build:prod

# Build Go binary with embedded frontend assets
FROM golang:1.25-alpine as backend
WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download
COPY pkg ./pkg
COPY --from=frontend /work/pkg/webserver/dist ./pkg/webserver/dist

RUN CGO_ENABLED=0 go build -a -o /out/yunikorn-web -trimpath -ldflags '-s -w' ./pkg/cmd/web

# Final image
FROM scratch

COPY --from=backend /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=backend /out/yunikorn-web /yunikorn-web

EXPOSE 9889
ENTRYPOINT [ "/yunikorn-web" ]
