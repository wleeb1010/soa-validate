package main

import (
	"flag"
	"fmt"
	"os"
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
	fmt.Printf("soa-validate %s\n", version)
	fmt.Printf("  profile:      %s\n", cfg.profile)
	fmt.Printf("  runner-url:   %s\n", cfg.runnerURL)
	fmt.Printf("  spec-vectors: %s\n", cfg.specVectors)
	fmt.Printf("  out:          %s\n", cfg.out)
	fmt.Println("(week-0 skeleton: no tests executed)")
	return nil
}
