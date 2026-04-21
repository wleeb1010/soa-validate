// Package subprocrunner spawns the implementation Runner as a subprocess
// for boot-time-failure conformance tests (HR-12 / SV-BOOT-01 negatives).
// The Runner is started with controlled env vars and we observe whether
// it boots clean, exits non-zero with a documented reason, or times out.
package subprocrunner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// Config describes a subprocess invocation.
type Config struct {
	Bin     string            // executable path (e.g., "node")
	Args    []string          // arguments (e.g., ["dist/bin/start-runner.js"])
	Env     map[string]string // env vars to pass (replaces inherited values for these keys)
	Dir     string            // working directory (empty = current)
	Timeout time.Duration     // wall-clock timeout for the spawn lifecycle
	// ReadinessProbe, if set, is polled every PollInterval until it
	// returns nil OR the process exits OR the timeout elapses. nil-return
	// means "ready" (e.g., GET /health succeeded).
	ReadinessProbe func(ctx context.Context) error
	PollInterval   time.Duration // default 250ms when ReadinessProbe set
}

// Result records what happened.
type Result struct {
	ExitCode         int    // -1 if process didn't exit (still running at kill time, or err)
	Exited           bool   // true if process exited on its own (not killed by us)
	TimedOut         bool   // true if we hit the timeout and killed it
	ReadinessReached bool   // true if ReadinessProbe returned nil before exit/timeout
	Stdout           string
	Stderr           string
	StartErr         error // non-nil if Cmd.Start() failed
}

// Spawn runs cfg.Bin with cfg.Args + cfg.Env, capturing stdout/stderr.
// Returns when one of these happens:
//   - the process exits on its own (Result.Exited = true, ExitCode set)
//   - the readiness probe returns nil (ReadinessReached = true, process
//     is then killed cleanly)
//   - cfg.Timeout elapses (TimedOut = true, process killed)
//
// The function never returns an error from Spawn itself except StartErr;
// the caller inspects Result.ExitCode + Stderr to decide pass/fail.
func Spawn(ctx context.Context, cfg Config) Result {
	r := Result{ExitCode: -1}
	cmd := exec.CommandContext(ctx, cfg.Bin, cfg.Args...)
	if cfg.Dir != "" {
		cmd.Dir = cfg.Dir
	}
	cmd.Env = mergeEnv(cfg.Env)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		r.StartErr = err
		return r
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	pollInterval := cfg.PollInterval
	if pollInterval <= 0 {
		pollInterval = 250 * time.Millisecond
	}

	exitCh := make(chan error, 1)
	go func() { exitCh <- cmd.Wait() }()

	for {
		select {
		case err := <-exitCh:
			r.Exited = true
			r.ExitCode = exitCodeFrom(cmd, err)
			r.Stdout = stdoutBuf.String()
			r.Stderr = stderrBuf.String()
			return r
		case <-time.After(pollInterval):
			if cfg.ReadinessProbe != nil {
				probeCtx, cancel := context.WithTimeout(ctx, pollInterval)
				if err := cfg.ReadinessProbe(probeCtx); err == nil {
					cancel()
					r.ReadinessReached = true
					_ = killAndWait(cmd, exitCh)
					r.Stdout = stdoutBuf.String()
					r.Stderr = stderrBuf.String()
					return r
				}
				cancel()
			}
			if time.Now().After(deadline) {
				r.TimedOut = true
				_ = killAndWait(cmd, exitCh)
				r.Stdout = stdoutBuf.String()
				r.Stderr = stderrBuf.String()
				return r
			}
		case <-ctx.Done():
			_ = killAndWait(cmd, exitCh)
			r.Stdout = stdoutBuf.String()
			r.Stderr = stderrBuf.String()
			return r
		}
	}
}

func mergeEnv(overrides map[string]string) []string {
	// Caller's env is the baseline; overrides replace matching keys.
	// Don't inherit by default — boot-time tests want a controlled env.
	// Caller can pass through specific keys (PATH, NODE_PATH) explicitly.
	out := make([]string, 0, len(overrides))
	for k, v := range overrides {
		out = append(out, fmt.Sprintf("%s=%s", k, v))
	}
	return out
}

func exitCodeFrom(cmd *exec.Cmd, waitErr error) int {
	if cmd.ProcessState != nil {
		return cmd.ProcessState.ExitCode()
	}
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return -1
}

func killAndWait(cmd *exec.Cmd, exitCh <-chan error) error {
	if cmd.Process == nil {
		return nil
	}
	_ = cmd.Process.Kill()
	select {
	case <-exitCh:
	case <-time.After(2 * time.Second):
	}
	return nil
}
