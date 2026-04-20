// Package specvec loads the pinned test vectors the validator runs assertions
// against. All paths are relative to the spec repo root (the --spec-vectors flag).
package specvec

import (
	"fmt"
	"os"
	"path/filepath"
)

// Locator points at a spec-repo checkout. Construct once per run.
type Locator struct {
	Root string
}

func New(root string) Locator { return Locator{Root: root} }

// Path returns absolute path to a file relative to the spec repo root.
func (l Locator) Path(rel string) string {
	return filepath.Join(l.Root, rel)
}

// Read returns the bytes of a spec-repo-relative path. Fails loudly if the
// file is missing — pinned vectors must exist at the pinned commit.
func (l Locator) Read(rel string) ([]byte, error) {
	p := l.Path(rel)
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("specvec: read %s: %w", rel, err)
	}
	return b, nil
}

// Well-known paths — one place to change if the spec restructures.
const (
	AgentCardJSON    = "test-vectors/agent-card.json"
	AgentCardJWS     = "test-vectors/agent-card.json.jws"
	AgentCardSchema  = "schemas/agent-card.schema.json"
)
