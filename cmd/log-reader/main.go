// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/praetorian-inc/log4j-remediation/pkg/build"
	detector "github.com/praetorian-inc/log4j-remediation/pkg/detector/spring"
	"github.com/praetorian-inc/log4j-remediation/pkg/types"
)

var (
	debugmode    bool
	printversion bool
	outputjson   bool
	logFile      string
)

func main() {
	flag.StringVar(&logFile, "log", "log4j-remediation.log", "log file to parse")
	flag.BoolVar(&outputjson, "json", false, "output in json format")
	flag.BoolVar(&printversion, "v", false, "prints current version")
	flag.BoolVar(&debugmode, "d", false, "prints additional Debug information")
	flag.Parse()

	if printversion {
		fmt.Printf("log-reader version %s", build.Version)
		return
	}

	js := json.NewEncoder(os.Stdout)

	b, err := os.ReadFile(logFile)
	if err != nil {
		log.Fatalf("failed to read file: %s", err)
	}
	lines := bytes.Split(b, []byte("\n"))

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		// nolint:errcheck
		processReport(line, js)
	}
}

func processReport(line []byte, js *json.Encoder) int {
	var report types.Report
	var err error

	err = json.Unmarshal(line, &report)
	if err != nil {
		log.Fatalf("failed to unmarshal json: %s", err)
	}

	var cnt int
	cnt = 0
	for _, vuln := range detector.DetectVulnerabilities(report, debugmode) {
		if outputjson {
			js.Encode(vuln)
		} else {
			fmt.Printf("%s: vulnerable version %s loaded by process [%d] %s in %s\n",
				vuln.Hostname, vuln.Version, vuln.ProcessID, vuln.ProcessName, vuln.Path)
		}
		cnt++
	}

	return cnt
}
