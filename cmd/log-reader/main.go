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
    "strings"
     
	"github.com/hashicorp/go-version"
	"github.com/praetorian-inc/log4j-remediation/pkg/build"
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

		var report types.Report
		err = json.Unmarshal(line, &report)
		if err != nil {
			log.Fatalf("failed to unmarshal json: %s", err)
		}

		for _, vuln := range DetectVulnerabilities(report) {
			if outputjson {
				js.Encode(vuln) // nolint:errcheck
			} else {
				fmt.Printf("%s: vulnerable version %s loaded by process [%d] %s in %s\n",
					vuln.Hostname, vuln.Version, vuln.ProcessID, vuln.ProcessName, vuln.Path)
			}
		}
	}
}

// Per https://tanzu.vmware.com/security/cve-2022-22965
var (
	// Version fixes vulnerability.
	fixedVersion_5_3 = version.Must(version.NewVersion("5.3.18"))
	fixedVersion_5_2 = version.Must(version.NewVersion("5.2.20"))
)

func DetectVulnerabilities(report types.Report) []types.Vulnerability {
	var vulns []types.Vulnerability

	for _, r := range report.Results {
		var vulnerableJAR *types.JAREntry

		for i, jar := range r.JARs {
            if "unknown" == jar.Version {
                if (debugmode) {
    			     fmt.Printf("Ignoring Version jar %s: version %s\n", jar.Path, jar.Version)
                }
				continue
            }
            
            stringcontainsrelease := strings.Contains(jar.Version, "RELEASE")
            if(debugmode) {
   			   fmt.Printf("Check if String contains Release %s: %s\n", jar.Version, stringcontainsrelease)
            }
               
            if stringcontainsrelease {
                if(debugmode) {
       			   fmt.Printf("Versuche Fehler beim decoding der Version zu beheben: decoding Version jar %s: version %s\n", jar.Path, jar.Version)
                }
                jar.Version = strings.Replace(jar.Version, ".RELEASE", "", 1)
            }
                        
			v, err := version.NewVersion(jar.Version)
			if err != nil {
  			   fmt.Printf("Failure decoding Version jar %s: version %s\n", jar.Path, jar.Version)
			   continue
			}
            
            if(debugmode) {
			 fmt.Printf("Processing jar %s: version %s\n", jar.Path, jar.Version)
            }

			if v.Equal(fixedVersion_5_2) {
			     fmt.Printf("Ignored (fixed) 5.2.x jar %s: version %s\n", jar.Path, jar.Version)
				continue
			}
            
			if v.Equal(fixedVersion_5_3) {
			     fmt.Printf("Ignored (fixed) 5.3.x jar %s: version %s\n", jar.Path, jar.Version)
				continue
			}

			if v.LessThan(fixedVersion_5_2) || v.LessThan(fixedVersion_5_3) {
                if(debugmode) {
			     fmt.Printf("Match for  jar %s: version %s\n", jar.Path, jar.Version)
                 }
				vulnerableJAR = &r.JARs[i]

        		// If we get here, we're vulnerable
        		vulns = append(vulns, types.Vulnerability{
        			Hostname:    report.Hostname,
        			ProcessID:   r.PID,
        			ProcessName: r.ProcessName,
        			Version:     vulnerableJAR.Version,
        			Path:        vulnerableJAR.Path,
        			SHA256:      vulnerableJAR.SHA256,
        		})

			}
		}

	}

	return vulns
}