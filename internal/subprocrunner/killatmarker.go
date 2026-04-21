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
	"net/http"
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

	// ReadyURL is polled at 250ms intervals. When the GET returns
	// 200, OnReady fires (once) in a dedicated goroutine. The marker
	// watcher continues in parallel — OnReady drives HTTP flows that
	// are expected to produce the marker.
	ReadyURL string

	// OnReady is invoked once after ReadyURL returns 200. It may
	// take any time; its return value is recorded but not used for
	// kill decisions (kill still fires on marker / self-exit / timeout).
	OnReady func(ctx context.Context) error
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
	// OnReadyFired is true iff OnReady was invoked (ReadyURL returned 200).
	OnReadyFired bool
	// OnReadyErr captures any error OnReady returned — e.g. HTTP error
	// from a driven POST. Useful for diagnostics when the marker never
	// fires (distinguishes "OnReady never ran" from "OnReady ran but
	// impl emitted a different marker").
	OnReadyErr error
	// ObservedMarkers lists every SOA_MARK_* line seen in stderr, in
	// order. Helps callers report "expected PENDING_WRITE_DONE, saw
	// DIR_FSYNC_DONE" precisely.
	ObservedMarkers []string
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
	// signal via markerCh. Also record every `SOA_MARK_*` line observed
	// so callers can diagnose "expected X but saw Y".
	var stderrBuf bytes.Buffer
	var stderrMu sync.Mutex
	var observedMarkers []string
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
			if idx := strings.Index(line, "SOA_MARK_"); idx >= 0 {
				// Extract the first-occurrence-through-end-of-token as
				// the observed marker (handles "SOA_MARK_X session_id=Y"
				// or bare "SOA_MARK_X" lines).
				trimmed := line[idx:]
				observedMarkers = append(observedMarkers, trimmed)
			}
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

	// If OnReady + ReadyURL configured, poll readiness in a goroutine
	// and fire OnReady once. The marker watcher continues in parallel.
	onReadyDone := make(chan struct{})
	if cfg.ReadyURL != "" && cfg.OnReady != nil {
		go func() {
			defer close(onReadyDone)
			client := &http.Client{Timeout: 1 * time.Second}
			deadline := time.Now().Add(timeout)
			for time.Now().Before(deadline) {
				req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, cfg.ReadyURL, nil)
				if reqErr == nil {
					if resp, err := client.Do(req); err == nil {
						resp.Body.Close()
						if resp.StatusCode == http.StatusOK {
							r.OnReadyFired = true
							readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
							r.OnReadyErr = cfg.OnReady(readyCtx)
							cancel()
							return
						}
					}
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(250 * time.Millisecond):
				}
			}
		}()
	} else {
		close(onReadyDone)
	}

	exitCh := make(chan error, 1)
	go func() { exitCh <- cmd.Wait() }()

	snapshot := func() {
		r.Stdout = stdoutBuf.String()
		stderrMu.Lock()
		r.Stderr = stderrBuf.String()
		r.ObservedMarkers = append([]string(nil), observedMarkers...)
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
