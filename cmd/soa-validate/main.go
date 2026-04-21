package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/wleeb1010/soa-validate/internal/junit"
	"github.com/wleeb1010/soa-validate/internal/musmap"
	"github.com/wleeb1010/soa-validate/internal/runner"
	"github.com/wleeb1010/soa-validate/internal/specvec"
	"github.com/wleeb1010/soa-validate/internal/testrunner"
)

// resolveDriverSession picks the session credentials the V-07 driver uses.
// Prefers a freshly-minted session (T-03 spec-normative path) when the
// bootstrap bearer is available; falls back to SOA_IMPL_DEMO_SESSION for
// pre-T-03 deployments. Returns (sid, bearer, err).
func resolveDriverSession(ctx context.Context, c *runner.Client) (string, string, error) {
	if bs := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER"); bs != "" {
		body := []byte(`{"requested_activeMode":"ReadOnly","user_sub":"v07-driver","request_decide_scope":true}`)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL()+"/sessions", bytes.NewReader(body))
		if err != nil {
			return "", "", err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+bs)
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			return "", "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusCreated {
			var sb struct {
				SessionID     string `json:"session_id"`
				SessionBearer string `json:"session_bearer"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&sb); err != nil {
				return "", "", fmt.Errorf("decode session bootstrap: %w", err)
			}
			return sb.SessionID, sb.SessionBearer, nil
		}
		// Bootstrap path failed (e.g., wrong bearer); fall back to demo session if present.
	}
	if demo := os.Getenv("SOA_IMPL_DEMO_SESSION"); demo != "" {
		parts := strings.SplitN(demo, ":", 2)
		if len(parts) == 2 {
			return parts[0], parts[1], nil
		}
	}
	return "", "", fmt.Errorf("no driver session source: set SOA_RUNNER_BOOTSTRAP_BEARER (preferred) or SOA_IMPL_DEMO_SESSION")
}

func driveAuditRecordsCount() int {
	raw := os.Getenv("SOA_DRIVE_AUDIT_RECORDS")
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// driveAuditRecords POSTs n /permissions/decisions calls cycling through
// tools listed in SOA_DRIVE_AUDIT_TOOLS (comma-separated; defaults to
// fs__read_file). Each accepted call writes one hash-chained audit row.
//
// Session source (preferred → fallback):
//   1. SOA_RUNNER_BOOTSTRAP_BEARER set → mint a fresh session with
//      request_decide_scope:true (T-03; spec-normative path)
//   2. SOA_IMPL_DEMO_SESSION set → use the pre-enrolled demo creds
//      (legacy convenience; pre-T-03)
//
// Pacing & rate-limit handling:
//   - 2.5 s default inter-request pace keeps the 30 rpm sliding window
//     per-bearer rate limit from filling. After 60 s of pacing the
//     window holds 24 requests — leaving 6 of headroom for subsequent
//     SV-PERM-20 etc. runs that share the bearer.
//   - On 429: read Retry-After, sleep that+1 s, retry the same record
//     without counting it.
//
// Mixed-tool tolerance:
//   - On 503 pda-verify-unavailable (Prompt-resolving tool against a
//     deployment without PDA verify wired): log, count as "skipped",
//     continue to the next tool. The driver does NOT fail the run on
//     this code — it's an expected outcome on the current deployment.
//
// Other non-201 responses (400, 401, 403, 5xx other than 503-pda) stop
// the driver and return what was written so far + the error.
func driveAuditRecords(ctx context.Context, c *runner.Client, n int) (driveStats, error) {
	sid, bearer, err := resolveDriverSession(ctx, c)
	if err != nil {
		return driveStats{}, err
	}
	tools := []string{"fs__read_file"}
	if raw := strings.TrimSpace(os.Getenv("SOA_DRIVE_AUDIT_TOOLS")); raw != "" {
		tools = nil
		for _, t := range strings.Split(raw, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tools = append(tools, t)
			}
		}
	}
	pace := 2500 * time.Millisecond
	if raw := os.Getenv("SOA_DRIVE_PACE_MS"); raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms >= 0 {
			pace = time.Duration(ms) * time.Millisecond
		}
	}
	hc := &http.Client{Timeout: 10 * time.Second}
	return driveAuditRecordsWith(ctx, hc, c.BaseURL(), sid, bearer, tools, n, pace)
}

type driveStats struct {
	Written            int
	SkippedPdaUnavail  int
	RetriedAfter429    int
}

// driveAuditRecordsWith is the testable inner loop — accepts an explicit
// http.Client + base URL + tool list + pace so unit tests can drive it
// against an httptest.Server without real impl pacing delays.
func driveAuditRecordsWith(ctx context.Context, hc *http.Client, baseURL, sid, bearer string, tools []string, n int, pace time.Duration) (driveStats, error) {
	stats := driveStats{}
	if len(tools) == 0 {
		return stats, fmt.Errorf("driveAuditRecordsWith: tools list empty")
	}
	for i := 0; i < n; i++ {
		tool := tools[i%len(tools)]
		body := []byte(fmt.Sprintf(`{"tool":"%s","session_id":"%s","args_digest":"sha256:%s"}`,
			tool, sid, strings.Repeat("0", 64)))
		for {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/permissions/decisions", bytes.NewReader(body))
			if err != nil {
				return stats, err
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+bearer)
			resp, err := hc.Do(req)
			if err != nil {
				return stats, err
			}
			retryAfter := resp.Header.Get("Retry-After")
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusCreated:
				stats.Written++
				if pace > 0 {
					time.Sleep(pace)
				}
				goto nextRecord
			case http.StatusTooManyRequests:
				stats.RetriedAfter429++
				secs, _ := strconv.Atoi(retryAfter)
				if secs <= 0 {
					secs = 5
				}
				time.Sleep(time.Duration(secs+1) * time.Second)
				continue
			case http.StatusServiceUnavailable:
				if bytes.Contains(raw, []byte("pda-verify-unavailable")) {
					stats.SkippedPdaUnavail++
					if pace > 0 {
						time.Sleep(pace)
					}
					goto nextRecord
				}
				return stats, fmt.Errorf("decision %d/%d (tool=%s): 503 body=%s", i+1, n, tool, string(raw))
			default:
				return stats, fmt.Errorf("decision %d/%d (tool=%s): status %d body=%s", i+1, n, tool, resp.StatusCode, string(raw))
			}
		}
	nextRecord:
	}
	return stats, nil
}

const version = "0.1.0-week1"

type config struct {
	profile     string
	runnerURL   string
	specVectors string
	out         string
	implURL     string // SOA_IMPL_URL or --impl-url; if reachable, enables live path
}

func main() {
	cfg := parseFlags(os.Args[1:])
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "soa-validate:", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) config {
	fs := flag.NewFlagSet("soa-validate", flag.ExitOnError)
	var cfg config
	fs.StringVar(&cfg.profile, "profile", "core", "conformance profile: core|ui|si|handoff")
	fs.StringVar(&cfg.runnerURL, "runner-url", "", "(deprecated alias for --impl-url)")
	fs.StringVar(&cfg.implURL, "impl-url", "", "base URL of the sibling implementation Runner to validate against")
	fs.StringVar(&cfg.specVectors, "spec-vectors", "", "path to pinned spec repo (source of must-maps + test vectors)")
	fs.StringVar(&cfg.out, "out", "release-gate.json", "output path for release-gate.json (JUnit XML written alongside)")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Parse(args)
	if *showVersion {
		fmt.Println("soa-validate", version)
		os.Exit(0)
	}
	// Env var fallback: SOA_IMPL_URL overrides implURL only if flag unset.
	if cfg.implURL == "" {
		cfg.implURL = os.Getenv("SOA_IMPL_URL")
	}
	if cfg.implURL == "" {
		cfg.implURL = cfg.runnerURL // accept the old name for back-compat
	}
	return cfg
}

func run(cfg config) error {
	if cfg.specVectors == "" {
		return fmt.Errorf("--spec-vectors is required (path to pinned spec repo)")
	}

	mm, err := musmap.LoadSV(cfg.specVectors)
	if err != nil {
		return fmt.Errorf("load SV must-map: %w", err)
	}
	if err := musmap.ValidateSV(mm); err != nil {
		return fmt.Errorf("validate SV must-map: %w", err)
	}

	var client *runner.Client
	var live bool
	if cfg.implURL != "" {
		// Live path is enabled as soon as --impl-url / SOA_IMPL_URL is set.
		// The handler for each test performs its own endpoint probe — a
		// missing endpoint becomes a PathLive failure on that test, not a
		// silent skip at startup.
		client = runner.New(runner.Config{BaseURL: cfg.implURL, Timeout: 5 * time.Second})
		live = true
	} else {
		client = runner.New(runner.Config{BaseURL: ""})
	}

	// V-07 audit-record driver: if SOA_DRIVE_AUDIT_RECORDS=N is set, fire
	// N POST /permissions/decisions for tools in SOA_DRIVE_AUDIT_TOOLS (or
	// fs__read_file by default) against the demo session before running
	// tests. Grows the audit chain for V-06/V-10 to exercise non-trivial
	// pagination + tamper detection.
	if live {
		if n := driveAuditRecordsCount(); n > 0 {
			stats, err := driveAuditRecords(context.Background(), client, n)
			if err != nil {
				fmt.Fprintf(os.Stderr, "soa-validate: V-07 driver error after %d records: %v\n", stats.Written, err)
			} else {
				fmt.Fprintf(os.Stdout, "V-07 driver: wrote %d records, skipped %d (pda-verify-unavailable), retried %d (429 backoff)\n",
					stats.Written, stats.SkippedPdaUnavail, stats.RetriedAfter429)
			}
		}
	}

	results := testrunner.Run(context.Background(), testrunner.Config{
		Profile: cfg.profile,
		Client:  client,
		Spec:    specvec.New(cfg.specVectors),
		Live:    live,
	}, mm)

	junitPath := strings.TrimSuffix(cfg.out, filepath.Ext(cfg.out)) + ".junit.xml"
	if err := writeJUnit(junitPath, cfg.profile, results); err != nil {
		return fmt.Errorf("write junit: %w", err)
	}
	if err := writeReleaseGate(cfg.out, cfg, results, live); err != nil {
		return fmt.Errorf("write release-gate: %w", err)
	}

	summarize(os.Stdout, cfg, results, junitPath, live)
	if anyFailed(results) {
		return fmt.Errorf("one or more tests failed")
	}
	return nil
}

func writeJUnit(path, profile string, results []testrunner.Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return junit.Write(f, "soa-validate "+profile, results)
}

type releaseGate struct {
	Tool       string      `json:"tool"`
	Version    string      `json:"version"`
	Profile    string      `json:"profile"`
	ImplURL    string      `json:"impl_url"`
	LivePath   bool        `json:"live_path_enabled"`
	Total      int         `json:"total"`
	Passed     int         `json:"passed"`
	Failed     int         `json:"failed"`
	Skipped    int         `json:"skipped"`
	Errored    int         `json:"errored"`
	Results    []resultDTO `json:"results"`
}

type resultDTO struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	Section  string        `json:"section"`
	Profile  string        `json:"profile"`
	Severity string        `json:"severity"`
	Status   string        `json:"status"`
	Seconds  float64       `json:"seconds"`
	Message  string        `json:"message,omitempty"`
	Evidence []evidenceDTO `json:"evidence,omitempty"`
}

type evidenceDTO struct {
	Path    string `json:"path"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

func writeReleaseGate(path string, cfg config, results []testrunner.Result, live bool) error {
	g := releaseGate{
		Tool: "soa-validate", Version: version, Profile: cfg.profile,
		ImplURL: cfg.implURL, LivePath: live, Total: len(results),
	}
	for _, r := range results {
		switch r.Status {
		case testrunner.StatusPass:
			g.Passed++
		case testrunner.StatusFail:
			g.Failed++
		case testrunner.StatusSkip:
			g.Skipped++
		case testrunner.StatusError:
			g.Errored++
		}
		dto := resultDTO{
			ID: r.ID, Name: r.Name, Section: r.Section,
			Profile: r.Profile, Severity: r.Severity,
			Status: string(r.Status), Seconds: r.Duration.Seconds(),
			Message: r.Message,
		}
		for _, e := range r.Evidence {
			dto.Evidence = append(dto.Evidence, evidenceDTO{
				Path: string(e.Path), Status: string(e.Status), Message: e.Message,
			})
		}
		g.Results = append(g.Results, dto)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(g)
}

func summarize(w *os.File, cfg config, results []testrunner.Result, junitPath string, live bool) {
	livestr := "off"
	if live {
		livestr = "on"
	}
	fmt.Fprintf(w, "soa-validate %s — profile=%s impl=%s live=%s\n", version, cfg.profile, cfg.implURL, livestr)
	var passed, failed, skipped, errored int
	for _, r := range results {
		switch r.Status {
		case testrunner.StatusPass:
			passed++
		case testrunner.StatusFail:
			failed++
		case testrunner.StatusSkip:
			skipped++
		case testrunner.StatusError:
			errored++
		}
		fmt.Fprintf(w, "  %-14s %-5s %s\n", r.ID, string(r.Status), r.Message)
	}
	fmt.Fprintf(w, "total=%d pass=%d fail=%d skip=%d error=%d\n",
		len(results), passed, failed, skipped, errored)
	fmt.Fprintf(w, "junit:        %s\nrelease-gate: %s\n", junitPath, cfg.out)
}

func anyFailed(results []testrunner.Result) bool {
	for _, r := range results {
		if r.Status == testrunner.StatusFail || r.Status == testrunner.StatusError {
			return true
		}
	}
	return false
}
