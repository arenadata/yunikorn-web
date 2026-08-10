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

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/apache/yunikorn-core/pkg/webservice"
	"github.com/apache/yunikorn-web/pkg/webserver"
)

var (
	version string
	date    string
)

func main() {
	config, err := webservice.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Starting yunikorn-web version: %s, buildDate: %s, listenAddress: %s",
		version, date, config.ListenAddress)

	server, err := webserver.NewWebServer(config)
	if err != nil {
		log.Fatal(err)
	}
	server.Start()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	server.Stop()
}
