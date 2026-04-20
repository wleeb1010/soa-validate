package testrunner

import "time"

type Status string

const (
	StatusPass  Status = "pass"
	StatusFail  Status = "fail"
	StatusSkip  Status = "skip"
	StatusError Status = "error"
)

type Result struct {
	ID       string
	Name     string
	Section  string
	Profile  string
	Severity string
	Status   Status
	Duration time.Duration
	Message  string // short one-line
	Detail   string // optional longer diagnostic
}
