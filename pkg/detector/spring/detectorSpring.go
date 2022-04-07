// Copyright (c) 2021- Stripe, Inc. (https://stripe.com)
// This code is licensed under MIT license (see LICENSE-MIT for details)

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

package detector

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/go-version"

	"github.com/praetorian-inc/log4j-remediation/pkg/detector/jar"
	"github.com/praetorian-inc/log4j-remediation/pkg/fingerprint"
	"github.com/praetorian-inc/log4j-remediation/pkg/types"
)

// Per https://tanzu.vmware.com/security/cve-2022-22965
var (
	// Version fixes vulnerability.
	fixedVersion_5_3 = version.Must(version.NewVersion("5.3.18"))
	fixedVersion_5_2 = version.Must(version.NewVersion("5.2.20"))
)

func DetectVulnerabilities(report types.Report, debugmode bool) (vulns []types.Vulnerability) {

	for _, r := range report.Results {

		for _, jar := range r.JARs {
			// If we get here, we're vulnerable
			var vuln *types.Vulnerability
			vuln = AnalyzeJar(jar, debugmode)

			if nil != vuln {
				var vulnerability types.Vulnerability
				vulnerability = *vuln

				vulnerability.Hostname = report.Hostname
				vulnerability.ProcessID = r.PID
				vulnerability.ProcessName = r.ProcessName

				vulns = append(vulns, vulnerability)
			}
		}

	}

	return vulns
}

func AnalyzeJar(jarEntry types.JAREntry, debugmode bool) *types.Vulnerability {

	if "unknown" == jarEntry.Version {

		// Try to find out Version
		name, vers, hash, vuln := jar.CheckHashAgainstVulnerabilitiesDB(jarEntry.SHA256, debugmode)
		if vuln {
			jarEntry.Name = name
			jarEntry.Version = vers
			jarEntry.SHA256 = hash
			jarEntry.Vulnerable = vuln
		} else {
			if debugmode {
				fmt.Printf("Ignoring Version jar %s: version %s\n", jarEntry.Path, jarEntry.Version)
			}
			return nil
		}
	}

	if !jarEntry.Vulnerable {

		vulnerabilitiesToCheck := fingerprint.GetVulnerabilitiesToCheck()

		// For each known vulnerability ...
	out:
		for _, vul := range vulnerabilitiesToCheck.Vulnerabilities {

			// ... check all known remediations
			for _, remediation := range vul.Remediations {
				if remediation.SHA256 == jarEntry.SHA256 {
					jarEntry.Vulnerable = false
					break out
				}
			}

			// check hashes vor vulnerable files
			for _, fp := range vul.Fingerprints {

				if fp.SHA256 == jarEntry.SHA256 {
					jarEntry.Vulnerable = true
					break out
				}
			}

			// ... check all known file-names
			for _, fp := range vul.Fingerprints {
				// If fileName matches
				if strings.HasPrefix(jarEntry.Name, fp.File) {
					//		var vulnerableJAR *types.JAREntry
					//		vulnerableJAR = &jarEntry

					// Check if version is vulnerable
					result, e := checkVersionVulnerable(fp.File, vul.RemediationVersion, jarEntry, debugmode)
					if nil == e {
						if result && debugmode {
							fmt.Printf("File rated as Vulnerable! Path: %s File: %s Version %s\n", jarEntry.Path, jarEntry.Name, jarEntry.Version)
						}

						jarEntry.Vulnerable = result
						break out
					}
				}
			}
		}

	}

	if jarEntry.Vulnerable {
		vuln := types.Vulnerability{
			//			Hostname:    report.Hostname,
			//			ProcessID:   r.PID,
			//			ProcessName: r.ProcessName,
			Version: jarEntry.Version,
			Path:    jarEntry.Path,
			SHA256:  jarEntry.SHA256,
		}

		return &vuln
	}

	return nil
}

func checkVersionVulnerable(vunerableFileName string, remediationVersion string, jarEntry types.JAREntry, debugmode bool) (bool, error) {
	stringcontainsrelease := strings.Contains(jarEntry.Version, "RELEASE")

	if "" == jarEntry.Name || "" == vunerableFileName {
		//		if debugmode {
		fmt.Printf("Filename or searchpattern filename empty:  %s: version %s\n", jarEntry.Name, vunerableFileName)
		//		}
		return false, errors.New("FileName empty and does not match search pattern!")
	}

	// If fileName matches
	if !strings.HasPrefix(jarEntry.Name, vunerableFileName) {
		return false, errors.New("FileName does not match search pattern.")
	}

	if stringcontainsrelease {
		if debugmode {
			fmt.Printf("Versuche Fehler beim decoding der Version zu beheben: decoding Version jar %s: version %s\n", jarEntry.Path, jarEntry.Version)
		}
		jarEntry.Version = strings.Replace(jarEntry.Version, ".RELEASE", "", 1)
	}

	v, err := version.NewVersion(jarEntry.Version)
	if err != nil {
		fmt.Printf("Failure decoding Version jar %s: version %s\n", jarEntry.Path, jarEntry.Version)
		return false, errors.New("Failure decoding Version")
	}

	if debugmode {
		fmt.Printf("Processing jar %s: version %s\n", jarEntry.Name, jarEntry.Version)
	}

	parts := strings.Split(remediationVersion, ";")
	for _, part := range parts {

		partsOfRange := strings.Split(part, "..")

		var fixedVersionUpperBound *version.Version

		fixedVersionLowBound, err := version.NewVersion(partsOfRange[0])
		if err != nil {
			fmt.Printf("Failure decoding Remediation-Version version %s\n", part)
			continue
		}

		if len(partsOfRange) == 2 {
			fixedVersionUpperBound, err = version.NewVersion(partsOfRange[1])
			if err != nil {
				fmt.Printf("Failure decoding Remediation-Version version %s\n", part)
				continue
			}
		} else {
			fixedVersionUpperBound = nil
		}

		if v.GreaterThanOrEqual(fixedVersionLowBound) {
			if fixedVersionUpperBound != nil {
				if v.LessThanOrEqual(fixedVersionUpperBound) {
					fmt.Printf("Ignored (fixed) %s: version %s - version between remediationVersion %s and %s\n", jarEntry.Name, jarEntry.Version, fixedVersionLowBound.Original(), fixedVersionUpperBound.Original())
					return false, nil
				}
			} else {
				fmt.Printf("Ignored (fixed) %s: version %s - version >= remediationVersion %s\n", jarEntry.Name, jarEntry.Version, fixedVersionLowBound.Original())
				return false, nil
			}
		}

	}

	fmt.Printf("jar %s: matched name of vulnerable File %s \n", jarEntry.Name, vunerableFileName)
	fmt.Printf("jar %s: version %s did not match Remediation Versions \n", jarEntry.Path, jarEntry.Version)
	return true, nil
}
