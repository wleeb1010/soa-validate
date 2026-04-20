package testrunner

import (
	"context"
	"time"

	"github.com/wleeb1010/soa-validate/internal/musmap"
	"github.com/wleeb1010/soa-validate/internal/runner"
)

type Config struct {
	Profile string
	TestIDs []string // if empty, run every test whose handler is registered
	Client  *runner.Client
}

// Run executes each selected test from the must-map in deterministic order
// and returns results. Tests without a registered handler report StatusError.
func Run(ctx context.Context, cfg Config, mm *musmap.SVMustMap) []Result {
	ids := cfg.TestIDs
	if len(ids) == 0 {
		for id := range Handlers {
			ids = append(ids, id)
		}
	}
	// Deterministic order: iterate the must-map's phases so output is stable.
	ordered := orderByPhase(ids, mm)

	results := make([]Result, 0, len(ordered))
	for _, id := range ordered {
		def, ok := mm.Tests[id]
		if !ok {
			results = append(results, Result{
				ID:      id,
				Status:  StatusError,
				Message: "test id not found in must-map",
			})
			continue
		}
		h, hasHandler := Handlers[id]
		if !hasHandler {
			results = append(results, Result{
				ID:       id,
				Name:     def.Name,
				Section:  def.Section,
				Profile:  def.Profile,
				Severity: def.Severity,
				Status:   StatusError,
				Message:  "no handler registered for test",
			})
			continue
		}
		start := time.Now()
		status, msg, detail := h(ctx, cfg.Client)
		results = append(results, Result{
			ID:       id,
			Name:     def.Name,
			Section:  def.Section,
			Profile:  def.Profile,
			Severity: def.Severity,
			Status:   status,
			Duration: time.Since(start),
			Message:  msg,
			Detail:   detail,
		})
	}
	return results
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
	// Append any ids that aren't covered by execution_order (shouldn't happen
	// for valid must-maps, but keeps the runner robust).
	for _, id := range ids {
		if !seen[id] {
			ordered = append(ordered, id)
			seen[id] = true
		}
	}
	return ordered
}
