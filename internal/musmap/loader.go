package musmap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	SVFileName = "soa-validate-must-map.json"
	UVFileName = "ui-validate-must-map.json"
)

func LoadSV(specDir string) (*SVMustMap, error) {
	p := filepath.Join(specDir, SVFileName)
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	var m SVMustMap
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	return &m, nil
}

func LoadUV(specDir string) (*UVMustMap, error) {
	p := filepath.Join(specDir, UVFileName)
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	var m UVMustMap
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	return &m, nil
}
