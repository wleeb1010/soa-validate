package subprocrunner

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Tests use the `go` toolchain itself as a controlled subprocess: it's
// available in any environment that can build this package.
func goBin(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("go binary not on PATH: %v", err)
	}
	return p
}

// TestSpawn_ExitsCleanCapturesOutput: `go version` exits 0 with output
// on stdout. Spawn should record ExitCode=0, Exited=true, populate stdout.
func TestSpawn_ExitsCleanCapturesOutput(t *testing.T) {
	r := Spawn(context.Background(), Config{
		Bin:     goBin(t),
		Args:    []string{"version"},
		Timeout: 5 * time.Second,
	})
	if r.StartErr != nil {
		t.Fatalf("StartErr: %v", r.StartErr)
	}
	if !r.Exited || r.ExitCode != 0 {
		t.Errorf("Exited=%v ExitCode=%d; want true,0", r.Exited, r.ExitCode)
	}
	if !strings.Contains(r.Stdout, "go version") {
		t.Errorf("stdout missing 'go version': %q", r.Stdout)
	}
}

// TestSpawn_NonZeroExitRecorded: `go badcommand` fails with non-zero exit
// and writes to stderr. Spawn must record both.
func TestSpawn_NonZeroExitRecorded(t *testing.T) {
	r := Spawn(context.Background(), Config{
		Bin:     goBin(t),
		Args:    []string{"this-is-not-a-go-subcommand"},
		Timeout: 5 * time.Second,
	})
	if !r.Exited {
		t.Fatal("expected process to exit")
	}
	if r.ExitCode == 0 {
		t.Errorf("ExitCode=%d; want non-zero", r.ExitCode)
	}
	if r.Stderr == "" {
		t.Error("expected stderr output for invalid subcommand")
	}
}

// TestSpawn_TimeoutKillsLongRunningProcess: spawn `go env` with a probe
// that never succeeds and zero-exit-time process is impossible, so we
// instead use a long-running command. On Unix `sleep`, on Windows
// `timeout`. To stay portable, use `go test` self-loop — actually skip
// platform-specific. Use Go itself with a long-running build: spawn
// `go run` of a tiny inline program would work but needs file I/O.
//
// Pragmatic: use ping with -n option which exists on both. Actually,
// the simplest reliable way is to shell to a built-in. On Windows
// `cmd /c timeout /t 10`, on Unix `sleep 10`. Skip unsupported.
func TestSpawn_TimeoutKillsLongRunningProcess(t *testing.T) {
	bin, args, err := longRunningCmd()
	if err != nil {
		t.Skipf("no portable long-running command: %v", err)
	}
	start := time.Now()
	r := Spawn(context.Background(), Config{
		Bin:     bin,
		Args:    args,
		Timeout: 600 * time.Millisecond,
	})
	dur := time.Since(start)
	if r.StartErr != nil {
		t.Fatalf("StartErr: %v", r.StartErr)
	}
	if !r.TimedOut {
		t.Errorf("expected TimedOut=true, got Exited=%v ExitCode=%d", r.Exited, r.ExitCode)
	}
	if dur > 4*time.Second {
		t.Errorf("Spawn took %v; expected to kill near 600ms timeout", dur)
	}
}

// TestSpawn_ReadinessProbeStopsEarly: process is long-running but the
// readiness probe immediately returns nil. Spawn should kill the
// process and report ReadinessReached=true.
func TestSpawn_ReadinessProbeStopsEarly(t *testing.T) {
	bin, args, err := longRunningCmd()
	if err != nil {
		t.Skipf("no portable long-running command: %v", err)
	}
	r := Spawn(context.Background(), Config{
		Bin:     bin,
		Args:    args,
		Timeout: 5 * time.Second,
		ReadinessProbe: func(ctx context.Context) error {
			return nil // always ready
		},
		PollInterval: 100 * time.Millisecond,
	})
	if r.StartErr != nil {
		t.Fatalf("StartErr: %v", r.StartErr)
	}
	if !r.ReadinessReached {
		t.Errorf("ReadinessReached=false; want true")
	}
	if r.TimedOut {
		t.Error("TimedOut=true; should have stopped on readiness, not timeout")
	}
}

// TestSpawn_StartErrOnMissingBinary: if Bin doesn't exist, StartErr
// must be populated.
func TestSpawn_StartErrOnMissingBinary(t *testing.T) {
	r := Spawn(context.Background(), Config{
		Bin:     "this-binary-definitely-does-not-exist-anywhere",
		Args:    nil,
		Timeout: 1 * time.Second,
	})
	if r.StartErr == nil {
		t.Error("expected StartErr for missing binary")
	}
}

// longRunningCmd returns a command that reliably runs for several seconds.
// Tries python first (cross-platform sleep that's been on this developer
// machine), then platform-specific shells. Returns error → caller skips.
func longRunningCmd() (string, []string, error) {
	if py, err := exec.LookPath("python"); err == nil {
		return py, []string{"-c", "import time; time.sleep(5)"}, nil
	}
	if py3, err := exec.LookPath("python3"); err == nil {
		return py3, []string{"-c", "import time; time.sleep(5)"}, nil
	}
	if runtime.GOOS == "windows" {
		// timeout /T N /NOBREAK is reliable when /c'd through cmd.
		return "cmd", []string{"/c", "timeout", "/t", "5", "/nobreak"}, nil
	}
	if sl, err := exec.LookPath("sleep"); err == nil {
		return sl, []string{"5"}, nil
	}
	return "", nil, errors.New("no portable sleep command available")
}
