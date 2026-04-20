package jcs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type generatedVectors struct {
	GeneratedBy string    `json:"generated_by"`
	GeneratedAt string    `json:"generated_at"`
	Libraries   libraries `json:"libraries"`
	Source      string    `json:"source_inputs"`
	Cases       []vector  `json:"cases"`
}

type libraries struct {
	TS libInfo `json:"ts"`
	Go libInfo `json:"go"`
}

type libInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type vector struct {
	Name              string          `json:"name"`
	Input             json.RawMessage `json:"input"`
	Rationale         string          `json:"rationale"`
	ExpectedCanonical string          `json:"expected_canonical"`
	LibrariesAgree    bool            `json:"libraries_agree"`
	ManualRequired    string          `json:"MANUAL_RESOLUTION_REQUIRED"`
}

func specDir(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("SOA_HARNESS_SPEC_PATH"); p != "" {
		return p
	}
	candidate := filepath.Join("..", "..", "..", "soa-harness=specification")
	if _, err := os.Stat(candidate); err == nil {
		abs, _ := filepath.Abs(candidate)
		return abs
	}
	t.Skip("spec repo not available; set SOA_HARNESS_SPEC_PATH")
	return ""
}

func TestJCSParity(t *testing.T) {
	dir := filepath.Join(specDir(t), "test-vectors", "jcs-parity", "generated")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read generated dir: %v", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			files = append(files, e.Name())
		}
	}
	if len(files) == 0 {
		t.Fatal("no generated vector files found; run generate-vectors.mjs in the spec repo")
	}

	for _, file := range files {
		file := file
		t.Run(file, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(dir, file))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			var v generatedVectors
			if err := json.Unmarshal(b, &v); err != nil {
				t.Fatalf("parse: %v", err)
			}
			for _, c := range v.Cases {
				c := c
				t.Run(c.Name, func(t *testing.T) {
					if !c.LibrariesAgree {
						t.Skipf("libraries disagree (manual resolution required): %s", c.ManualRequired)
					}
					var input interface{}
					if err := json.Unmarshal(c.Input, &input); err != nil {
						t.Fatalf("decode input: %v", err)
					}
					got, err := Canonicalize(input)
					if err != nil {
						t.Fatalf("canonicalize: %v", err)
					}
					if string(got) != c.ExpectedCanonical {
						t.Errorf("DIVERGENCE from generated vector\n  case:      %s\n  expected:  %q\n  got:       %q\n  rationale: %s",
							c.Name, c.ExpectedCanonical, string(got), c.Rationale)
					}
				})
			}
		})
	}
}
