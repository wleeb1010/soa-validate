package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wleeb1010/soa-validate/internal/junit"
	"github.com/wleeb1010/soa-validate/internal/musmap"
	"github.com/wleeb1010/soa-validate/internal/runner"
	"github.com/wleeb1010/soa-validate/internal/specvec"
	"github.com/wleeb1010/soa-validate/internal/testrunner"
)

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
		client = runner.New(runner.Config{BaseURL: cfg.implURL, Timeout: 5 * time.Second})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := client.Health(ctx); err == nil {
			live = true
		}
	}
	if client == nil {
		// No impl URL at all: construct an unusable client so handlers have a
		// non-nil value but live path is disabled.
		client = runner.New(runner.Config{BaseURL: ""})
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
