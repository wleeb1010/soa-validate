package testrunner

import "time"

type Status string

const (
	StatusPass  Status = "pass"
	StatusFail  Status = "fail"
	StatusSkip  Status = "skip"
	StatusError Status = "error"
)

// EvidencePath identifies which probe path produced a check result. A single
// test ID may run multiple paths (e.g. both a spec-vector check and a live
// Runner check); JUnit output surfaces each as its own <property>.
type EvidencePath string

const (
	PathVector EvidencePath = "vector" // pinned spec test vector on disk
	PathLive   EvidencePath = "live"   // live Runner/Gateway over HTTP
)

type Evidence struct {
	Path    EvidencePath
	Status  Status
	Message string
}

type Result struct {
	ID       string
	Name     string
	Section  string
	Profile  string
	Severity string
	Status   Status // aggregate status across all evidence
	Duration time.Duration
	Message  string // short human summary
	Detail   string
	Evidence []Evidence
}

// Aggregate picks the overall Status from a slice of Evidence.
// Rules: any FAIL → fail. any ERROR → error. any PASS and no FAIL/ERROR → pass.
// all SKIP → skip. empty → skip.
func Aggregate(ev []Evidence) Status {
	if len(ev) == 0 {
		return StatusSkip
	}
	var pass, skip int
	for _, e := range ev {
		switch e.Status {
		case StatusFail:
			return StatusFail
		case StatusError:
			return StatusError
		case StatusPass:
			pass++
		case StatusSkip:
			skip++
		}
	}
	if pass > 0 {
		return StatusPass
	}
	return StatusSkip
}
