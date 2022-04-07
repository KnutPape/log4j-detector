package detector

import (
	"testing"

	"github.com/praetorian-inc/log4j-remediation/pkg/types"
)

func TestDetectVulnerabilities(t *testing.T) {
	/*
		b, err := os.ReadFile("sample_report.json")
		if err != nil {
			log.Fatalf("failed to read file: %s", err)
		}
		lines := bytes.Split(b, []byte("\n"))

		var report types.Report
		err = json.Unmarshal(lines[0], &report)
		if err != nil {
			log.Fatalf("failed to unmarshal json: %s", err)
		}
	*/
	var jarEntry types.JAREntry
	vulnerability1 := AnalyzeJar(jarEntry, true)

	if nil != vulnerability1 {
		t.Errorf("Didn't Expected Vulnerability!")
	}

	jarEntry.Path = "abc.jar"
	vulnerability2 := AnalyzeJar(jarEntry, true)

	if nil != vulnerability2 {
		t.Errorf("Didn't Expected Vulnerability!")
	}

	// {"path":"\\\\?\\C:\\Users\\Pape\\.m2\\repository\\org\\springframework\\spring-webmvc\\5.3.15\\spring-webmvc-5.3.15.jar","version":"unknown","sha256":"77ee2f3d7ff5eef47e15937033de6c478c84bb40a3b90405645f03780dcd9fe1"}
	jarEntry.Path = "C:\\Users\\Pape\\.m2\\repository\\org\\springframework\\spring-webmvc\\5.3.15\\spring-webmvc-5.3.15.jar"
	jarEntry.Version = "unknown"
	jarEntry.SHA256 = "77ee2f3d7ff5eef47e15937033de6c478c84bb40a3b90405645f03780dcd9fe1"
	vulnerability3 := AnalyzeJar(jarEntry, true)

	if nil != vulnerability3 {
		t.Errorf("Didn't Expected Vulnerability!")
	}

	if nil == vulnerability3 {
		t.Errorf("Expected Vulnerability!")
	}

}

func TestCheckVersionVulnerable(t *testing.T) {
	var jarEntry types.JAREntry
	jarEntry.Path = "C:\\Users\\Pape\\.m2\\repository\\org\\springframework\\spring-webmvc\\5.3.15\\spring-webmvc-5.3.15.jar"
	jarEntry.Name = "spring-webmvc-5.3.15"
	jarEntry.Version = "5.3.15"
	jarEntry.SHA256 = ""

	result1, _ := checkVersionVulnerable("spring-webmvc", "5.2.19..5.2.99;5.3.17", jarEntry, true)

	if false == result1 {
		t.Errorf("Expected jar to match Vulnerability!")
	}

	jarEntry.Path = "C:\\Users\\Pape\\.m2\\repository\\org\\springframework\\spring-webmvc\\5.3.15\\spring-web-5.3.17.jar"
	jarEntry.Name = "spring-web-5.3.17"
	jarEntry.Version = "5.3.17"
	jarEntry.SHA256 = ""

	result2, _ := checkVersionVulnerable("spring-webmvc", "5.2.19..5.2.99;5.3.17", jarEntry, true)

	if true == result2 {
		t.Errorf("Expected jar NOT to match Vulnerability!")
	}

	jarEntry.Path = "\\?\\C:\\Users\\Pape\\.m2\\repository\\org\\apache\\tomcat\\tomcat-annotations-api\\9.0.39\\tomcat-annotations-api-9.0.39.jar"
	//"": version 1.3.FR"
}
