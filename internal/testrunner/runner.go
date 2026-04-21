package testrunner

import (
	"context"
	"fmt"
	"time"

	"github.com/wleeb1010/soa-validate/internal/musmap"
	"github.com/wleeb1010/soa-validate/internal/runner"
	"github.com/wleeb1010/soa-validate/internal/specvec"
)

type Config struct {
	Profile string
	TestIDs []string // if empty, run every test whose handler is registered
	Client  *runner.Client
	Spec    specvec.Locator
	Live    bool
}

func Run(ctx context.Context, cfg Config, mm *musmap.SVMustMap) []Result {
	ids := cfg.TestIDs
	if len(ids) == 0 {
		for id := range Handlers {
			ids = append(ids, id)
		}
	}
	ordered := orderByPhase(ids, mm)
	hctx := HandlerCtx{Client: cfg.Client, Spec: cfg.Spec, Live: cfg.Live}

	results := make([]Result, 0, len(ordered))
	for _, id := range ordered {
		def, ok := mm.Tests[id]
		if !ok {
			results = append(results, Result{ID: id, Status: StatusError,
				Message: "test id not found in must-map"})
			continue
		}
		// Spec-authored deferral: tests with implementation_milestone set
		// to anything other than M1 skip automatically with the spec's
		// declared reason. Catalog carries the source of truth here.
		if def.ImplMilestone != "" && def.ImplMilestone != "M1" {
			results = append(results, Result{
				ID: id, Name: def.Name, Section: def.Section,
				Profile: def.Profile, Severity: def.Severity,
				Status: StatusSkip,
				Message: fmt.Sprintf("deferred to %s per must-map: %s",
					def.ImplMilestone, def.MilestoneReason),
				Evidence: []Evidence{{
					Path: PathVector, Status: StatusSkip,
					Message: fmt.Sprintf("%s-deferred: %s", def.ImplMilestone, def.MilestoneReason),
				}},
			})
			continue
		}
		h, hasHandler := Handlers[id]
		if !hasHandler {
			results = append(results, Result{
				ID: id, Name: def.Name, Section: def.Section,
				Profile: def.Profile, Severity: def.Severity,
				Status: StatusError, Message: "no handler registered for test",
			})
			continue
		}
		start := time.Now()
		evidence := h(ctx, hctx)
		status := Aggregate(evidence)
		results = append(results, Result{
			ID: id, Name: def.Name, Section: def.Section,
			Profile: def.Profile, Severity: def.Severity,
			Status:   status,
			Duration: time.Since(start),
			Message:  summarize(status, evidence),
			Evidence: evidence,
		})
	}
	return results
}

func summarize(status Status, ev []Evidence) string {
	switch status {
	case StatusPass:
		return "passed (" + pathsWith(ev, StatusPass) + ")"
	case StatusFail:
		for _, e := range ev {
			if e.Status == StatusFail {
				return string(e.Path) + ": " + e.Message
			}
		}
	case StatusError:
		for _, e := range ev {
			if e.Status == StatusError {
				return string(e.Path) + ": " + e.Message
			}
		}
	case StatusSkip:
		return "skipped (" + pathsWith(ev, StatusSkip) + ")"
	}
	return ""
}

func pathsWith(ev []Evidence, s Status) string {
	var out string
	for _, e := range ev {
		if e.Status == s {
			if out != "" {
				out += ","
			}
			out += string(e.Path)
		}
	}
	return out
}

func orderByPhase(ids []string, mm *musmap.SVMustMap) []string {
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	var ordered []string
	seen := make(map[string]bool)
	for _, phase := range mm.ExecutionOrder.Phases {
		for _, id := range phase.Tests {
			if want[id] && !seen[id] {
				ordered = append(ordered, id)
				seen[id] = true
			}
		}
	}
	for _, id := range ids {
		if !seen[id] {
			ordered = append(ordered, id)
			seen[id] = true
		}
	}
	return ordered
}
