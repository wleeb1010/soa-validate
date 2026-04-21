package musmap

import (
	"os"
	"path/filepath"
	"testing"
)

// specDir locates the pinned spec repo. Tests set SOA_HARNESS_SPEC_PATH to the
// spec repo root; otherwise we fall back to the sibling-checkout convention
// used during development (../soa-harness=specification from repo root).
// If neither is available, loader tests are skipped rather than failed — CI
// sets the env var explicitly.
func specDir(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("SOA_HARNESS_SPEC_PATH"); p != "" {
		return p
	}
	// repo-root-relative fallback when running from internal/musmap
	candidate := filepath.Join("..", "..", "..", "soa-harness=specification")
	if _, err := os.Stat(filepath.Join(candidate, SVFileName)); err == nil {
		abs, _ := filepath.Abs(candidate)
		return abs
	}
	t.Skip("spec repo not available; set SOA_HARNESS_SPEC_PATH")
	return ""
}

func TestLoadSV(t *testing.T) {
	m, err := LoadSV(specDir(t))
	if err != nil {
		t.Fatalf("LoadSV: %v", err)
	}
	// Catalog growth: 213 → 221 at spec commit 8b35375 (L-13 must-map integration);
	// 221 → 222 → 223 at L-27 + L-28 (M2 additions: SV-AUDIT-SINK-EVENTS-01 added, 6 SV-SESS tagged M2).
	if len(m.Tests) != 223 {
		t.Errorf("expected 223 tests, got %d", len(m.Tests))
	}
	for _, id := range []string{"HR-01", "HR-02", "HR-12", "HR-14", "SV-SIGN-01", "SV-CARD-01", "SV-BOOT-01", "SV-PERM-01"} {
		if _, ok := m.Tests[id]; !ok {
			t.Errorf("M1 test ID %s missing from SV must-map", id)
		}
	}
}

func TestLoadUV(t *testing.T) {
	m, err := LoadUV(specDir(t))
	if err != nil {
		t.Fatalf("LoadUV: %v", err)
	}
	if len(m.Tests) == 0 {
		t.Error("expected UV tests, got 0")
	}
}

func TestValidateSV(t *testing.T) {
	m, err := LoadSV(specDir(t))
	if err != nil {
		t.Fatalf("LoadSV: %v", err)
	}
	if err := ValidateSV(m); err != nil {
		t.Errorf("ValidateSV: %v", err)
	}
}

func TestValidateUV(t *testing.T) {
	m, err := LoadUV(specDir(t))
	if err != nil {
		t.Fatalf("LoadUV: %v", err)
	}
	if err := ValidateUV(m); err != nil {
		t.Errorf("ValidateUV: %v", err)
	}
}

func TestValidateSVRejectsBadID(t *testing.T) {
	m := &SVMustMap{
		Tests: map[string]SVTest{
			"BAD-ID": {Name: "x", Section: "§1", Profile: "core", Severity: "critical"},
		},
	}
	if err := ValidateSV(m); err == nil {
		t.Error("expected error for bad ID, got nil")
	}
}

func TestValidateSVRejectsOrphanPhaseRef(t *testing.T) {
	m := &SVMustMap{
		Tests: map[string]SVTest{
			"HR-01": {Name: "x", Section: "§1", Profile: "core", Severity: "critical"},
		},
		ExecutionOrder: ExecutionOrder{
			Phases: []Phase{{Phase: 1, Name: "p", Tests: []string{"HR-99"}}},
		},
	}
	if err := ValidateSV(m); err == nil {
		t.Error("expected error for orphan phase ref, got nil")
	}
}
