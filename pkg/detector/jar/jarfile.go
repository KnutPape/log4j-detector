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

package jar

import (
	"archive/zip"
	"bufio"
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/praetorian-inc/log4j-remediation/pkg/detector/file"
	"github.com/praetorian-inc/log4j-remediation/pkg/fingerprint"
	"github.com/praetorian-inc/log4j-remediation/pkg/types"
)

const (
	Unknown = "unknown"
)

var vulnerabilitiesToCheck fingerprint.Vulnerabilities

func JarEntryFromZip(path string, r *zip.Reader, verbose bool) types.JAREntry {
	src, name, ver, hash, vulnerable := versionFromJARArchive(path, r, verbose)
	if hash == "" {
		hash = file.HashFile(path)
	}

	return types.JAREntry{
		Path:          path,
		Name:          name,
		Version:       ver,
		VersionSource: src,
		SHA256:        hash,
		Vulnerable:    vulnerable,
	}
}

func versionFromJARArchive(path string, r *zip.Reader, verbose bool) (src types.VersionSource, name, version, hash string, vulnerable bool) {
	if filename, ver, hash, matched := versionFromJARFingerprint(path, verbose); matched {
		return types.SourceJAR, filename, ver, hash, matched
	}
	if filename, ver, hash, matched := versionFromJARArchiveFingerprint(r, verbose); matched {
		return types.SourceClass, filename, ver, hash, matched
	}
	if filename, ver, matched := versionFromJARArchiveMeta(r, verbose); matched || ver != Unknown {
		return types.SourceMetadata, filename, ver, "", matched
	}

	filename, ver := versionFromJARFileName(path, verbose)
	if ver != Unknown {
		return types.SourceFilename, filename, ver, "", false
	}

	return "", "", Unknown, "", false
}

func versionFromJARFileName(path string, verbose bool) (name, foundVersion string) {
	filename := FilenameWithoutExtension(path)
	parts := strings.Split(filename, "-")
	versionStr := parts[len(parts)-1]

	_, err := version.NewVersion(strings.Replace(versionStr, ".RELEASE", "", 1))
	if err != nil {
		if verbose {
			fmt.Printf("Failure decoding Version from path %s, found jar %s: version %s\n", path, filename, versionStr)
		}
		return filename, Unknown
	}

	return filename, versionStr
}

func FilenameWithoutExtension(fullPath string) string {
	_, fileName := path.Split(fullPath)
	return strings.TrimSuffix(fileName, path.Ext(fileName))
}

func versionFromJARFingerprint(path string, verbose bool) (name, version, hash string, vulnerable bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", Unknown, "", false
	}
	defer f.Close()

	hash = file.HashFsFile(f)

	return CheckHashAgainstVulnerabilitiesDB(hash, verbose)
}

func CheckHashAgainstVulnerabilitiesDB(inputHash string, verbose bool) (filename, version, hash string, vulnerable bool) {

	if len(vulnerabilitiesToCheck.Vulnerabilities) == 0 {
		vulnerabilitiesToCheck = fingerprint.GetVulnerabilitiesToCheck()
	}

	// For each known vulnerability ...
	for _, vul := range vulnerabilitiesToCheck.Vulnerabilities {
		// ... check all known search patterns based on files-hash
		for _, fp := range vul.Fingerprints {
			shouldReturn := compareHashValues(inputHash, vul.Name, fp, verbose)
			if shouldReturn {
				return fp.File, fp.Version, fp.SHA256, true
			}
		}
	}

	return "", Unknown, "", false
}

func compareHashValues(inputHash string, vulName string, fp fingerprint.Fingerprint, verbose bool) bool {
	if inputHash == fp.SHA256 {
		if verbose {
			log.Printf("found %s, file %s version %q by fingerprint", vulName, fp.File, fp.Version)
		}
		return true
	}
	return false
}

func versionFromJARArchiveFingerprint(r *zip.Reader, verbose bool) (filename, version, hash string, vulnerable bool) {

	if len(vulnerabilitiesToCheck.Vulnerabilities) == 0 {
		vulnerabilitiesToCheck = fingerprint.GetVulnerabilitiesToCheck()
	}

	// For each known vulnerability ...
	for _, vul := range vulnerabilitiesToCheck.Vulnerabilities {
		// ... check all known search patterns based on files-hash
		for _, fp := range vul.Fingerprints {
			// try to open file from Fingerprint in zip.File
			f, err := r.Open(fp.File)
			if err != nil {
				// File not found, coninue with next fingerprint
				continue
			}
			defer f.Close()

			hash := file.HashFsFile(f)

			shouldReturn := compareHashValues(hash, vul.Name, fp, verbose)
			if shouldReturn {
				return fp.File, fp.Version, fp.SHA256, true
			}
		}
	}

	return "", Unknown, "", false
}

func versionFromJARArchiveMeta(r *zip.Reader, verbose bool) (filename, version string, vulnerable bool) {
	f, err := r.Open("META-INF/MANIFEST.MF")
	if err != nil {
		return filename, Unknown, false
	}
	defer f.Close()

	metadata := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ": ", 2)
		if len(parts) == 2 {
			metadata[parts[0]] = parts[1]
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("error reading manifest file: %v", err)
		return filename, Unknown, false
	}

	if len(vulnerabilitiesToCheck.Vulnerabilities) == 0 {
		vulnerabilitiesToCheck = fingerprint.GetVulnerabilitiesToCheck()
	}

	var metadataMatch bool
	metadataMatch = false
	// For each known vulnerability ...
	for _, vul := range vulnerabilitiesToCheck.Vulnerabilities {

		// ... check all known search patterns based on files-hash
		for _, manifestEntry := range vul.ManifestEntries {
			if metadata[manifestEntry.Key] == manifestEntry.ExpectedValue {
				log.Printf("%s identified from manifest %s with value %s", manifestEntry.Name, manifestEntry.Key, manifestEntry.ExpectedValue)
				metadataMatch = true
				break
			}
		}

		if metadataMatch {
			break
		}
	}

	//	if !extractedVersion {
	//		log.Printf("No matching pattern found => unknown")
	//		return Unknown
	//	}
	/*
		var filename string
		candidatesFilename := []string{"Implementation-Title", "Bundle-Name"}
		for _, candidate := range candidatesFilename {
			if s, ok := metadata[candidate]; ok {
				if verbose {
					log.Printf("Filename is %v", s)
				}
				filename = s
			}
		}
	*/
	candidates := []string{"Implementation-Version", "Bundle-Version"}
	for _, candidate := range candidates {
		if version, ok := metadata[candidate]; ok {
			if verbose {
				log.Printf("Version is %v", version)
			}
			return filename, version, metadataMatch
		}
	}

	return filename, Unknown, false
}
