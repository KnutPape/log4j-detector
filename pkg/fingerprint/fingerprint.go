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

package fingerprint

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type Vulnerabilities struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	Name               string          `json:"name"`
	Description        string          `json:"description"`
	Remediation        string          `json:"remediation"`
	RemediationVersion string          // `json:"remediationVersion"`
	Remediations       []Fingerprint   // `json:"remediations"`
	Fingerprints       []Fingerprint   // `json:"fingerprints"`
	ManifestEntries    []manifestentry // `json:"manifestEntries"`
}

type Fingerprint struct {
	File    string `json:"file"`
	SHA256  string `json:"sha256"`
	Version string `json:"version"`
}

type manifestentry struct {
	Name          string `json:"name"`
	Key           string `json:"key"`
	ExpectedValue string `json:"expectedvalue"`
}

// content holds our static search patterns.
//go:embed vulnerabilities.json
var contentSearchPatterns embed.FS

var vulnerabilitiesToCheck Vulnerabilities

func GetVulnerabilitiesToCheck() Vulnerabilities {

	var knownVulnerabilities Vulnerabilities

	if len(vulnerabilitiesToCheck.Vulnerabilities) == 0 {
		//var err error
		//var jsonFile *fs.File
		var byteValue []byte
		// if local file exists ...
		if _, err := os.Stat("vulnerabilities.json"); err == nil {
			// Read local file
			fmt.Println("Read local vulnerabilities.json")
			jsonFile, err := os.Open("vulnerabilities.json")

			// if we os.Open returns an error then handle it
			if err != nil {
				fmt.Println(err)
			} else {
				fmt.Println("Successfully Opened vulnerabilities.json")
			}

			// defer the closing of our jsonFile so that we can parse it later on
			defer jsonFile.Close()

			// read our opened jsonFile as a byte array.
			byteValue, _ = ioutil.ReadAll(jsonFile)

		} else { // if errors.Is(err, os.ErrNotExist)
			// else read embedded file
			fmt.Println("Read embedded vulnerabilities.json")
			jsonFile, err := contentSearchPatterns.Open("vulnerabilities.json")

			// if we os.Open returns an error then handle it
			if err != nil {
				fmt.Println(err)
			} else {
				fmt.Println("Successfully Opened vulnerabilities.json")
			}

			// defer the closing of our jsonFile so that we can parse it later on
			defer jsonFile.Close()

			// read our opened jsonFile as a byte array.
			byteValue, _ = ioutil.ReadAll(jsonFile)
		}

		//         var result map[string]interface{}
		//         json.Unmarshal([]byte(byteValue), &result)
		//         fmt.Println(result)

		// we unmarshal our byteArray which contains our
		// jsonFile's content into 'vulnerabilitiesToCheck' which we defined above
		//json.Unmarshal(byteValue, &knownVulnerabilities)
		// Unmarshall JSOn with Error handling / Reporting
		if err := json.Unmarshal(byteValue, &knownVulnerabilities); err != nil {
			if jsonErr, ok := err.(*json.SyntaxError); ok {
				problemPart := byteValue[jsonErr.Offset-10 : jsonErr.Offset+10]
				err = fmt.Errorf("%w ~ error near '%s' (offset %d)", err, problemPart, jsonErr.Offset)
			}
		}

		// fmt.Printf("Data")
		//fmt.Println(knownVulnerabilities)

		// Readable diagnostics for Vulnearability Specs
		for i := 0; i < len(knownVulnerabilities.Vulnerabilities); i++ {
			fmt.Println("Known Vunerability: " + knownVulnerabilities.Vulnerabilities[i].Name + " " + knownVulnerabilities.Vulnerabilities[i].Description)
			fmt.Println("Search Fingerprints: ", len(knownVulnerabilities.Vulnerabilities[i].Fingerprints))
			fmt.Println("Search ManifestEntries: ", len(knownVulnerabilities.Vulnerabilities[i].ManifestEntries))
		}
	}

	if len(knownVulnerabilities.Vulnerabilities) > 0 {
		vulnerabilitiesToCheck = knownVulnerabilities
	}

	if len(vulnerabilitiesToCheck.Vulnerabilities) == 0 {
		fmt.Fprintf(os.Stderr, "error: no vulnerability-specs found!\n")
		os.Exit(-1)
	}

	return vulnerabilitiesToCheck
}
