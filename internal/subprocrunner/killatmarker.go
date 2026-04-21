// V-15 crash-test harness: spawn a Runner subprocess, stream its stderr,
// and Kill() the moment a named §12.5.3 crash-test marker is observed.
//
// Per Core §12.5.3 ("Crash-Test Marker Protocol"), the Runner — when
// started with RUNNER_CRASH_TEST_MARKERS=1 — emits stderr lines of the
// form `SOA_MARK_<PHASE>` at the seven well-known boundaries:
//
//	PENDING_WRITE_DONE    — pending journal flushed; side-effect is
//	                         crash-safe-recoverable but not yet invoked
//	TOOL_INVOKE_START     — tool implementation about to be called
//	TOOL_INVOKE_DONE      — tool implementation returned
//	COMMITTED_WRITE_DONE  — committed state flushed to session file
//	DIR_FSYNC_DONE        — directory fsync'd (atomic rename complete)
//	AUDIT_APPEND_DONE     — audit record appended to sink
//	AUDIT_BUFFER_WRITE_DONE — audit record buffered (sink degraded)
//
// Kill-at-marker is the *independent observation* — this harness never
// tells the Runner when to crash; it watches what the Runner announces
// and kills at the boundary the test cares about. If a marker never
// appears, the harness times out and the test fails honestly.

package subprocrunner

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// The seven crash-test markers defined by Core §12.5.3. Exported as a
// slice so tests and the crash-harness catalog stay in one place; if
// the spec adds a marker we update this slice and recompile (the pin
// bump is the review gate).
var CrashMarkers = []string{
	"SOA_MARK_PENDING_WRITE_DONE",
	"SOA_MARK_TOOL_INVOKE_START",
	"SOA_MARK_TOOL_INVOKE_DONE",
	"SOA_MARK_COMMITTED_WRITE_DONE",
	"SOA_MARK_DIR_FSYNC_DONE",
	"SOA_MARK_AUDIT_APPEND_DONE",
	"SOA_MARK_AUDIT_BUFFER_WRITE_DONE",
}

// KillAtMarkerConfig extends Config with marker-kill behavior.
type KillAtMarkerConfig struct {
	Config
	// Marker is the exact substring the harness watches for in stderr.
	// Use one of the CrashMarkers constants.
	Marker string
	// PreKillDelay, if >0, pauses briefly after the marker line is
	// observed before killing — useful when the test wants the write
	// that *triggered* the marker to land on disk before crash.
	PreKillDelay time.Duration
}

// KillAtMarkerResult extends Result with marker-observation fields.
type KillAtMarkerResult struct {
	Result
	// MarkerSeen is true iff the Marker substring appeared in stderr
	// before the process exited / timed out.
	MarkerSeen bool
	// KilledAfterMarker is true iff the harness issued Kill() in
	// response to observing the marker (as opposed to timing out or
	// seeing the process self-exit first).
	KilledAfterMarker bool
	// MarkerObservedAt is the wall-clock time the marker appeared.
	MarkerObservedAt time.Time
}

// SpawnUntilMarker runs cfg.Bin until one of:
//   - the Marker substring appears in stderr (Kill() issued after PreKillDelay; KilledAfterMarker=true)
//   - the process exits on its own (Exited=true)
//   - cfg.Timeout elapses (TimedOut=true)
//
// Unlike Spawn, this function does NOT use a readiness probe — it's
// specifically for crash-path testing where the process is expected
// to reach the marker boundary mid-flight.
func SpawnUntilMarker(ctx context.Context, cfg KillAtMarkerConfig) KillAtMarkerResult {
	r := KillAtMarkerResult{Result: Result{ExitCode: -1}}

	cmd := exec.CommandContext(ctx, cfg.Bin, cfg.Args...)
	if cfg.Dir != "" {
		cmd.Dir = cfg.Dir
	}
	cmd.Env = mergeEnv(cfg.Env, cfg.InheritEnv)

	var stdoutBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		r.StartErr = err
		return r
	}

	if err := cmd.Start(); err != nil {
		r.StartErr = err
		return r
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)

	// Stream stderr line-by-line; buffer every line so we can attribute
	// the crash after the fact. On the first line containing Marker,
	// signal via markerCh.
	var stderrBuf bytes.Buffer
	var stderrMu sync.Mutex
	markerCh := make(chan time.Time, 1)
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		scanner := bufio.NewScanner(stderrPipe)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		seen := false
		for scanner.Scan() {
			line := scanner.Text()
			stderrMu.Lock()
			stderrBuf.WriteString(line)
			stderrBuf.WriteByte('\n')
			stderrMu.Unlock()
			if !seen && cfg.Marker != "" && strings.Contains(line, cfg.Marker) {
				seen = true
				select {
				case markerCh <- time.Now():
				default:
				}
			}
		}
		// Drain any trailing bytes the scanner missed (error path).
		if err := scanner.Err(); err != nil && err != io.EOF {
			stderrMu.Lock()
			stderrBuf.WriteString("\n[subprocrunner: stderr-scan-err: " + err.Error() + "]\n")
			stderrMu.Unlock()
		}
	}()

	exitCh := make(chan error, 1)
	go func() { exitCh <- cmd.Wait() }()

	snapshot := func() {
		r.Stdout = stdoutBuf.String()
		stderrMu.Lock()
		r.Stderr = stderrBuf.String()
		stderrMu.Unlock()
	}

	for {
		select {
		case err := <-exitCh:
			<-scanDone
			r.Exited = true
			r.ExitCode = exitCodeFrom(cmd, err)
			snapshot()
			return r
		case at := <-markerCh:
			r.MarkerSeen = true
			r.MarkerObservedAt = at
			if cfg.PreKillDelay > 0 {
				select {
				case <-time.After(cfg.PreKillDelay):
				case <-ctx.Done():
				}
			}
			_ = killAndWait(cmd, exitCh)
			r.KilledAfterMarker = true
			<-scanDone
			snapshot()
			return r
		case <-time.After(100 * time.Millisecond):
			if time.Now().After(deadline) {
				r.TimedOut = true
				_ = killAndWait(cmd, exitCh)
				<-scanDone
				snapshot()
				return r
			}
		case <-ctx.Done():
			_ = killAndWait(cmd, exitCh)
			<-scanDone
			snapshot()
			return r
		}
	}
}
