package subprocrunner

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// pythonBin locates a usable python interpreter; tests that need one
// Skip if nothing is available. The kill-at-marker harness itself is
// language-agnostic — we use python here purely as a controlled stderr
// producer for the test harness itself.
func pythonBin(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("python"); err == nil {
		return p
	}
	if p, err := exec.LookPath("python3"); err == nil {
		return p
	}
	t.Skip("no python on PATH; skipping marker-harness test")
	return ""
}

// TestSpawnUntilMarker_KillsOnMarker: spawn a script that prints a
// marker to stderr then sleeps forever. Harness must (1) observe the
// marker, (2) set MarkerSeen+KilledAfterMarker, (3) not time out,
// (4) capture the marker line in Stderr.
func TestSpawnUntilMarker_KillsOnMarker(t *testing.T) {
	py := pythonBin(t)
	script := `
import sys, time
print("noise before marker", file=sys.stderr, flush=True)
print("SOA_MARK_PENDING_WRITE_DONE", file=sys.stderr, flush=True)
time.sleep(30)
`
	start := time.Now()
	r := SpawnUntilMarker(context.Background(), KillAtMarkerConfig{
		Config: Config{
			Bin:     py,
			Args:    []string{"-c", script},
			Timeout: 10 * time.Second,
		},
		Marker: "SOA_MARK_PENDING_WRITE_DONE",
	})
	dur := time.Since(start)
	if r.StartErr != nil {
		t.Fatalf("StartErr: %v", r.StartErr)
	}
	if !r.MarkerSeen {
		t.Error("MarkerSeen=false; expected harness to observe the marker")
	}
	if !r.KilledAfterMarker {
		t.Error("KilledAfterMarker=false; expected harness to kill after marker")
	}
	if r.TimedOut {
		t.Error("TimedOut=true; expected the marker kill path, not timeout")
	}
	if dur > 5*time.Second {
		t.Errorf("Spawn took %v; expected sub-second kill after marker", dur)
	}
	if !strings.Contains(r.Stderr, "SOA_MARK_PENDING_WRITE_DONE") {
		t.Errorf("Stderr missing marker line: %q", r.Stderr)
	}
}

// TestSpawnUntilMarker_TimesOutIfNoMarker: subprocess emits stderr
// noise but never the expected marker. Harness must time out.
func TestSpawnUntilMarker_TimesOutIfNoMarker(t *testing.T) {
	py := pythonBin(t)
	script := `
import sys, time
for i in range(100):
    print(f"unrelated line {i}", file=sys.stderr, flush=True)
    time.sleep(0.02)
`
	r := SpawnUntilMarker(context.Background(), KillAtMarkerConfig{
		Config: Config{
			Bin:     py,
			Args:    []string{"-c", script},
			Timeout: 800 * time.Millisecond,
		},
		Marker: "SOA_MARK_PENDING_WRITE_DONE",
	})
	if r.StartErr != nil {
		t.Fatalf("StartErr: %v", r.StartErr)
	}
	if r.MarkerSeen {
		t.Error("MarkerSeen=true; expected missing marker")
	}
	if !r.TimedOut && !r.Exited {
		t.Errorf("expected timeout or natural exit without marker; got neither")
	}
}

// TestSpawnUntilMarker_PreKillDelayRespected: harness waits PreKillDelay
// after the marker before killing. Useful when the write that triggered
// the marker needs time to land on disk.
func TestSpawnUntilMarker_PreKillDelayRespected(t *testing.T) {
	py := pythonBin(t)
	script := `
import sys, time
print("SOA_MARK_COMMITTED_WRITE_DONE", file=sys.stderr, flush=True)
time.sleep(30)
`
	start := time.Now()
	r := SpawnUntilMarker(context.Background(), KillAtMarkerConfig{
		Config: Config{
			Bin:     py,
			Args:    []string{"-c", script},
			Timeout: 10 * time.Second,
		},
		Marker:       "SOA_MARK_COMMITTED_WRITE_DONE",
		PreKillDelay: 400 * time.Millisecond,
	})
	dur := time.Since(start)
	if r.StartErr != nil {
		t.Fatalf("StartErr: %v", r.StartErr)
	}
	if !r.KilledAfterMarker {
		t.Fatal("expected KilledAfterMarker")
	}
	if dur < 400*time.Millisecond {
		t.Errorf("total duration %v < PreKillDelay 400ms; harness killed too early", dur)
	}
	if dur > 3*time.Second {
		t.Errorf("total duration %v too long; harness should kill shortly after delay", dur)
	}
}

// TestSpawnUntilMarker_SelfExitBeforeMarker: if the subprocess exits on
// its own before the marker, we should record Exited=true with the real
// exit code and MarkerSeen=false.
func TestSpawnUntilMarker_SelfExitBeforeMarker(t *testing.T) {
	py := pythonBin(t)
	script := `
import sys
print("quick noise", file=sys.stderr, flush=True)
sys.exit(42)
`
	r := SpawnUntilMarker(context.Background(), KillAtMarkerConfig{
		Config: Config{
			Bin:     py,
			Args:    []string{"-c", script},
			Timeout: 5 * time.Second,
		},
		Marker: "SOA_MARK_PENDING_WRITE_DONE",
	})
	if r.StartErr != nil {
		t.Fatalf("StartErr: %v", r.StartErr)
	}
	if r.MarkerSeen {
		t.Error("MarkerSeen=true; expected marker never observed")
	}
	if !r.Exited {
		t.Error("Exited=false; expected natural self-exit")
	}
	if r.ExitCode != 42 {
		t.Errorf("ExitCode=%d; expected 42", r.ExitCode)
	}
}

// TestCrashMarkers_CoversFullSet: guardrail against accidental omission
// in the CrashMarkers catalog — if this test breaks the pin-bump review
// will surface any marker delta.
func TestCrashMarkers_CoversFullSet(t *testing.T) {
	expected := map[string]bool{
		"SOA_MARK_PENDING_WRITE_DONE":      false,
		"SOA_MARK_TOOL_INVOKE_START":       false,
		"SOA_MARK_TOOL_INVOKE_DONE":        false,
		"SOA_MARK_COMMITTED_WRITE_DONE":    false,
		"SOA_MARK_DIR_FSYNC_DONE":          false,
		"SOA_MARK_AUDIT_APPEND_DONE":       false,
		"SOA_MARK_AUDIT_BUFFER_WRITE_DONE": false,
	}
	for _, m := range CrashMarkers {
		if _, ok := expected[m]; !ok {
			t.Errorf("unexpected marker in CrashMarkers: %s", m)
		}
		expected[m] = true
	}
	for m, saw := range expected {
		if !saw {
			t.Errorf("CrashMarkers missing marker from §12.5.3: %s", m)
		}
	}
}

var _ = errors.New
