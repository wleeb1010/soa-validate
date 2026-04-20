package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wleeb1010/soa-validate/internal/junit"
	"github.com/wleeb1010/soa-validate/internal/musmap"
	"github.com/wleeb1010/soa-validate/internal/runner"
	"github.com/wleeb1010/soa-validate/internal/testrunner"
)

const version = "0.0.0-week0"

type config struct {
	profile     string
	runnerURL   string
	specVectors string
	out         string
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
	fs.StringVar(&cfg.runnerURL, "runner-url", "", "base URL of the Runner under test")
	fs.StringVar(&cfg.specVectors, "spec-vectors", "", "path to pinned spec repo (source of must-maps + test vectors)")
	fs.StringVar(&cfg.out, "out", "release-gate.json", "output path for release-gate.json (JUnit XML written alongside)")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Parse(args)
	if *showVersion {
		fmt.Println("soa-validate", version)
		os.Exit(0)
	}
	return cfg
}

func run(cfg config) error {
	if cfg.specVectors == "" {
		return fmt.Errorf("--spec-vectors is required (path to pinned spec repo)")
	}
	if cfg.runnerURL == "" {
		return fmt.Errorf("--runner-url is required")
	}

	mm, err := musmap.LoadSV(cfg.specVectors)
	if err != nil {
		return fmt.Errorf("load SV must-map: %w", err)
	}
	if err := musmap.ValidateSV(mm); err != nil {
		return fmt.Errorf("validate SV must-map: %w", err)
	}

	client := runner.New(runner.Config{BaseURL: cfg.runnerURL})
	results := testrunner.Run(context.Background(), testrunner.Config{
		Profile: cfg.profile,
		Client:  client,
	}, mm)

	junitPath := strings.TrimSuffix(cfg.out, filepath.Ext(cfg.out)) + ".junit.xml"
	if err := writeJUnit(junitPath, cfg.profile, results); err != nil {
		return fmt.Errorf("write junit: %w", err)
	}
	if err := writeReleaseGate(cfg.out, cfg.profile, cfg.runnerURL, results); err != nil {
		return fmt.Errorf("write release-gate: %w", err)
	}

	summarize(os.Stdout, cfg, results, junitPath)
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
	Tool      string      `json:"tool"`
	Version   string      `json:"version"`
	Profile   string      `json:"profile"`
	RunnerURL string      `json:"runner_url"`
	Total     int         `json:"total"`
	Passed    int         `json:"passed"`
	Failed    int         `json:"failed"`
	Skipped   int         `json:"skipped"`
	Errored   int         `json:"errored"`
	Results   []resultDTO `json:"results"`
}

type resultDTO struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Section  string  `json:"section"`
	Profile  string  `json:"profile"`
	Severity string  `json:"severity"`
	Status   string  `json:"status"`
	Seconds  float64 `json:"seconds"`
	Message  string  `json:"message,omitempty"`
}

func writeReleaseGate(path, profile, runnerURL string, results []testrunner.Result) error {
	g := releaseGate{
		Tool:      "soa-validate",
		Version:   version,
		Profile:   profile,
		RunnerURL: runnerURL,
		Total:     len(results),
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
		g.Results = append(g.Results, resultDTO{
			ID: r.ID, Name: r.Name, Section: r.Section,
			Profile: r.Profile, Severity: r.Severity,
			Status: string(r.Status), Seconds: r.Duration.Seconds(),
			Message: r.Message,
		})
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

func summarize(w *os.File, cfg config, results []testrunner.Result, junitPath string) {
	fmt.Fprintf(w, "soa-validate %s — profile=%s runner=%s\n", version, cfg.profile, cfg.runnerURL)
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
