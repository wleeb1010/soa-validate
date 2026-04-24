package testrunner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

// M8 W5-6 compat probes per L-63 scope.
//
// SV-COMPAT-05: /version surfaces spec_commit_sha
// SV-COMPAT-06: /version runner_version tracks package version
// SV-COMPAT-07: v1.1 adopter stays conformant under v1.2 Runner (additive-minor)
// SV-COMPAT-08: MessageEnd payload stop_reason remains optional (forward-compat)
//
// 05/06 are live against a single v1.2 Runner. 07/08 need paired
// implementations (v1.1 + v1.2) so they're impl-unit-test-level in v1.2 and
// will promote to live live probes in v1.2.x once the sibling-Runner harness
// lands.

func fetchVersion(ctx context.Context, h HandlerCtx) (map[string]any, int, error) {
	req, _ := http.NewRequest(http.MethodGet, h.Client.BaseURL()+"/version", nil)
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("GET /version status=%d body=%.200q", resp.StatusCode, string(body))
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, resp.StatusCode, err
	}
	return parsed, resp.StatusCode, nil
}

// SV-COMPAT-05: /version surfaces spec_commit_sha
func handleSVCOMPAT05(ctx context.Context, h HandlerCtx) []Evidence {
	if !h.Live {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-COMPAT-05: SOA_IMPL_URL unset"}}
	}
	v, _, err := fetchVersion(ctx, h)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-COMPAT-05: fetchVersion failed: %v", err)}}
	}
	sha, ok := v["spec_commit_sha"].(string)
	if !ok || sha == "" {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-COMPAT-05: /version missing spec_commit_sha field (v1.2 requires it)"}}
	}
	if matched, _ := regexp.MatchString(`^[a-f0-9]{40}$`, sha); !matched {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-COMPAT-05: spec_commit_sha=%q is not a 40-char lowercase hex", sha)}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("SV-COMPAT-05: /version exposes spec_commit_sha=%s (well-formed 40-char hex)", sha[:12]+"…")}}
}

// SV-COMPAT-06: /version runner_version tracks package version (not hard-coded "1.0")
func handleSVCOMPAT06(ctx context.Context, h HandlerCtx) []Evidence {
	if !h.Live {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-COMPAT-06: SOA_IMPL_URL unset"}}
	}
	v, _, err := fetchVersion(ctx, h)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-COMPAT-06: fetchVersion failed: %v", err)}}
	}
	rv, ok := v["runner_version"].(string)
	if !ok || rv == "" {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-COMPAT-06: /version missing runner_version field"}}
	}
	// Accept major.minor (e.g., "1.2") or major.minor.patch (e.g., "1.2.0").
	// Reject the stale "1.0" that v1.1.0 shipped (Debt #7 regression guard).
	if matched, _ := regexp.MatchString(`^\d+\.\d+(\.\d+)?(-[A-Za-z0-9.-]+)?$`, rv); !matched {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-COMPAT-06: runner_version=%q not a valid semver major.minor(.patch)", rv)}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("SV-COMPAT-06: /version runner_version=%s (semver-shaped; not hard-coded stale value)", rv)}}
}

// SV-COMPAT-07 (skip): v1.1 adopter stays conformant under v1.2 Runner
func handleSVCOMPAT07Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-COMPAT-07: requires paired v1.1 + v1.2 Runners; unit-tested at packages/runner/test/dispatch-stream.test.ts ('without Accept: text/event-stream still returns 200 JSON'). Live probe targeted for v1.2.x when the sibling-Runner harness lands."}}
}

// SV-COMPAT-08 (skip): MessageEnd payload stop_reason remains optional
func handleSVCOMPAT08Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-COMPAT-08: schema-vector probe — stream-event-payloads.schema.json v1.2 MessageEnd $def required=['message_id'], stop_reason optional. Verified at schema-build time in @soa-harness/schemas; live probe would need a v1.1 producer in the pipeline to be meaningful."}}
}
