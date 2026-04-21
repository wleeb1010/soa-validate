// Package toolregistry loads and validates the pinned Tool Registry fixture
// from test-vectors/tool-registry/tools.json. Consumed by SV-PERM-01 to drive
// the 24-cell (tool × activeMode) decision matrix.
package toolregistry

import (
	"encoding/json"
	"fmt"
)

type Registry struct {
	Schema      string `json:"schema"`
	Description string `json:"description"`
	Version     string `json:"version"`
	Tools       []Tool `json:"tools"`
}

type Tool struct {
	Name           string `json:"name"`
	RiskClass      string `json:"risk_class"`      // ReadOnly | Mutating | Destructive | Egress
	DefaultControl string `json:"default_control"` // AutoAllow | Prompt | Deny
	Description    string `json:"description"`
}

func Parse(data []byte) (*Registry, error) {
	var r Registry
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse tool registry: %w", err)
	}
	return &r, nil
}

// ByName returns the tool with that name or (nil, false).
func (r *Registry) ByName(name string) (*Tool, bool) {
	for i := range r.Tools {
		if r.Tools[i].Name == name {
			return &r.Tools[i], true
		}
	}
	return nil, false
}
