package testrunner

import (
	"context"

	"github.com/wleeb1010/soa-validate/internal/runner"
)

type Handler func(ctx context.Context, c *runner.Client) (Status, string, string)

// Handlers maps test IDs to their implementation. Week 0 registers stubs for
// the 8 M1 test IDs; real assertions land week-by-week during M1.
var Handlers = map[string]Handler{
	"HR-01":      stubSkipped("week-0 stub; assertions land in M1 week 6"),
	"HR-02":      stubSkipped("week-0 stub; assertions land in M1 week 6"),
	"HR-12":      stubSkipped("week-0 stub; assertions land in M1 week 5"),
	"HR-14":      stubSkipped("week-0 stub; assertions land in M1 week 5"),
	"SV-SIGN-01": stubSkipped("week-0 stub; assertions land in M1 week 1"),
	"SV-CARD-01": stubSkipped("week-0 stub; assertions land in M1 week 1"),
	"SV-BOOT-01": stubSkipped("week-0 stub; assertions land in M1 week 5"),
	"SV-PERM-01": stubSkipped("week-0 stub; assertions land in M1 week 3"),
}

func stubSkipped(reason string) Handler {
	return func(ctx context.Context, c *runner.Client) (Status, string, string) {
		return StatusSkip, reason, ""
	}
}
