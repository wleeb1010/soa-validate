package jcs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type parityVector struct {
	Cases []parityCase `json:"cases"`
}

type parityCase struct {
	Name              string          `json:"name"`
	Input             json.RawMessage `json:"input"`
	ExpectedCanonical string          `json:"expected_canonical"`
	Rationale         string          `json:"rationale"`
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
	dir := filepath.Join(specDir(t), "test-vectors", "jcs-parity")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read parity dir: %v", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			files = append(files, e.Name())
		}
	}
	if len(files) == 0 {
		t.Fatal("no parity vector files found")
	}

	for _, file := range files {
		file := file
		t.Run(file, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(dir, file))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			var v parityVector
			if err := json.Unmarshal(b, &v); err != nil {
				t.Fatalf("parse: %v", err)
			}
			for _, c := range v.Cases {
				c := c
				t.Run(c.Name, func(t *testing.T) {
					var input interface{}
					dec := json.NewDecoder(nil)
					_ = dec
					if err := json.Unmarshal(c.Input, &input); err != nil {
						t.Fatalf("decode input: %v", err)
					}
					got, err := Canonicalize(input)
					if err != nil {
						t.Fatalf("canonicalize: %v", err)
					}
					if string(got) != c.ExpectedCanonical {
						t.Errorf("DIVERGENCE\n  case:     %s\n  expected: %q\n  got:      %q\n  rationale: %s",
							c.Name, c.ExpectedCanonical, string(got), c.Rationale)
					}
				})
			}
		})
	}
}
