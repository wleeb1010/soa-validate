package subprocrunner

// Crash-recovery sequence helper: launch impl with crash markers enabled,
// wait for a named SOA_MARK_* to fire, kill mid-flight, then relaunch
// against the same session directory (or a mutated form) and run a
// caller-supplied post-relaunch probe. Used by the V2-09b/c handlers
// (SV-SESS-06/07 atomic-write conformance, SV-SESS-08/09/10 resume
// algorithm) per the Core §12.3 / §12.5 assertions.
//
// The helper enforces three properties the tests rely on:
//  1. First launch blocks until the marker fires (not readiness), so the
//     kill-point is spec-accurate rather than time-based.
//  2. The same RUNNER_SESSION_DIR is preserved across the kill boundary
//     — this is what allows the relaunched impl to observe the exact
//     state a crash-and-restart would produce.
//  3. The post-relaunch probe is given a /ready-proven handle to drive
//     HTTP at the relaunched Runner; the relaunched impl is killed
//     cleanly when the probe returns.

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// CrashRecoveryConfig describes a two-phase kill-and-relaunch.
type CrashRecoveryConfig struct {
	Bin  string
	Args []string

	// FirstLaunchEnv: env vars for the initial launch. Must include
	// RUNNER_CRASH_TEST_MARKERS=1 for the marker path to activate.
	FirstLaunchEnv map[string]string

	// Marker: the SOA_MARK_* token that signals the kill-point. Caller
	// picks the boundary the test cares about (e.g.
	// SOA_MARK_COMMITTED_WRITE_DONE for atomic-write tests).
	Marker string

	// PreKillDelay: optional post-marker pause before killing. Useful
	// for atomic-write tests where we want the write that *triggered*
	// the marker to land on disk, then kill before the next boundary.
	PreKillDelay time.Duration

	// FirstLaunchTimeout: total budget for first launch to reach the
	// marker. 30s is a reasonable default.
	FirstLaunchTimeout time.Duration

	// RelaunchEnv: env for the second launch. Usually equals FirstLaunchEnv
	// except for the test-specific mutation (e.g., SV-SESS-09 changes
	// the Agent Card card_version to exercise drift detection).
	// RUNNER_CRASH_TEST_MARKERS is NOT required on the relaunch — the
	// relaunched impl just needs to recover session state.
	RelaunchEnv map[string]string

	// RelaunchTimeout: total budget for relaunched impl to reach /ready.
	RelaunchTimeout time.Duration

	// RelaunchReadyURL: e.g., "http://127.0.0.1:7701/ready". Harness polls
	// this at 250ms intervals until 200 or RelaunchTimeout.
	RelaunchReadyURL string
}

// CrashRecoveryResult records what happened across both phases.
type CrashRecoveryResult struct {
	FirstLaunch KillAtMarkerResult

	// RelaunchStarted: true iff Cmd.Start() succeeded for the second
	// launch. False means the first launch's failure short-circuited
	// the sequence (caller inspects FirstLaunch for the reason).
	RelaunchStarted bool

	// RelaunchReached /ready=200 before RelaunchTimeout.
	RelaunchReady bool

	// RelaunchProcessResult: final Result of the relaunched subprocess
	// after the probe callback returned and we killed it.
	RelaunchProcessResult Result

	// ProbeMsg / ProbePass: caller's probe output. When the first launch
	// doesn't reach the marker OR the relaunch never readies, ProbeMsg
	// carries the short-circuit reason and ProbePass=false.
	ProbeMsg  string
	ProbePass bool
}

// RunCrashRecovery executes the full sequence. The probe callback is
// invoked only after the relaunched impl reaches /ready; it receives a
// context scoped to the relaunch window. The callback's (msg, pass) is
// propagated verbatim into the result.
func RunCrashRecovery(ctx context.Context, cfg CrashRecoveryConfig, probe func(ctx context.Context) (string, bool)) CrashRecoveryResult {
	r := CrashRecoveryResult{}

	if cfg.FirstLaunchTimeout <= 0 {
		cfg.FirstLaunchTimeout = 30 * time.Second
	}
	if cfg.RelaunchTimeout <= 0 {
		cfg.RelaunchTimeout = 20 * time.Second
	}

	// Phase 1: launch + kill at marker.
	r.FirstLaunch = SpawnUntilMarker(ctx, KillAtMarkerConfig{
		Config: Config{
			Bin:        cfg.Bin,
			Args:       cfg.Args,
			Env:        cfg.FirstLaunchEnv,
			InheritEnv: false,
			Timeout:    cfg.FirstLaunchTimeout,
		},
		Marker:       cfg.Marker,
		PreKillDelay: cfg.PreKillDelay,
	})
	if !r.FirstLaunch.MarkerSeen {
		r.ProbeMsg = fmt.Sprintf("first launch never emitted marker %s (TimedOut=%v Exited=%v ExitCode=%d) — impl likely lacks RUNNER_CRASH_TEST_MARKERS support or the code path was not exercised. Probe skipped.",
			cfg.Marker, r.FirstLaunch.TimedOut, r.FirstLaunch.Exited, r.FirstLaunch.ExitCode)
		return r
	}

	// Phase 2: relaunch, wait for /ready, run probe, kill.
	proceed := make(chan struct{})
	resCh := make(chan Result, 1)

	go func() {
		res := Spawn(ctx, Config{
			Bin:        cfg.Bin,
			Args:       cfg.Args,
			Env:        cfg.RelaunchEnv,
			InheritEnv: false,
			Timeout:    cfg.RelaunchTimeout + 5*time.Second,
			ReadinessProbe: func(probeCtx context.Context) error {
				select {
				case <-proceed:
					return nil
				case <-probeCtx.Done():
					return probeCtx.Err()
				}
			},
			PollInterval: 250 * time.Millisecond,
		})
		resCh <- res
	}()
	r.RelaunchStarted = true

	probeCtx, probeCancel := context.WithTimeout(ctx, cfg.RelaunchTimeout)
	defer probeCancel()
	client := &http.Client{Timeout: 1 * time.Second}
	deadline := time.Now().Add(cfg.RelaunchTimeout)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, cfg.RelaunchReadyURL, nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				r.RelaunchReady = true
				break
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !r.RelaunchReady {
		close(proceed)
		r.RelaunchProcessResult = <-resCh
		r.ProbeMsg = fmt.Sprintf("relaunched impl never reached %s within %s; TimedOut=%v ExitCode=%d",
			cfg.RelaunchReadyURL, cfg.RelaunchTimeout, r.RelaunchProcessResult.TimedOut, r.RelaunchProcessResult.ExitCode)
		return r
	}

	r.ProbeMsg, r.ProbePass = probe(probeCtx)
	close(proceed)
	r.RelaunchProcessResult = <-resCh
	return r
}
