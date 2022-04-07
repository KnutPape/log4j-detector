package main

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"testing"
)

func TestAdd(t *testing.T) {
	b, err := os.ReadFile("sample_report.json")
	if err != nil {
		log.Fatalf("failed to read file: %s", err)
	}
	lines := bytes.Split(b, []byte("\n"))

	js := json.NewEncoder(os.Stdout)
	got := processReport(lines[0], js)
	want := 10

	if got != want {
		t.Errorf("got %d, wanted %d", got, want)
	}
}
