// Package sidiff implements the §9.3 SI diff-validator: accept unified
// diffs whose hunks touch only bytes inside the EDITABLE SURFACES span,
// reject anything else with the spec's §24 error codes.
//
// Pure-function validator (no SI runtime, no impl dependency). Used by
// HR-09 (SI marker escape) and HR-10 (SI immutable task).
package sidiff

import (
	"fmt"
	"regexp"
	"strings"
)

// Span records the [start, end) line numbers of the EDITABLE SURFACES
// block in a source file. Lines are 1-indexed. `end` is the line of
// the END-SURFACES marker (exclusive-of-marker is cleaner for range
// comparisons).
type Span struct {
	Start int // first editable line (line AFTER the opening marker)
	End   int // first non-editable line (the END marker)
}

// Result is the validator verdict.
type Result struct {
	Accepted     bool
	RejectReason string // §24 error code when !Accepted
	Detail       string // human-readable diagnostic
}

// FindEditableSpan scans a single-file source body for the paired markers
// `=== EDITABLE SURFACES ...` / `=== END EDITABLE SURFACES ===` and returns
// the inclusive-start / exclusive-end line numbers. Returns err when the
// markers are absent or appear > once.
func FindEditableSpan(source string) (Span, error) {
	lines := strings.Split(source, "\n")
	startRe := regexp.MustCompile(`===\s*EDITABLE SURFACES\b`)
	endRe := regexp.MustCompile(`===\s*END EDITABLE SURFACES\s*===`)
	var startIdx, endIdx int
	startCount, endCount := 0, 0
	for i, line := range lines {
		if startRe.MatchString(line) && !endRe.MatchString(line) {
			startIdx = i + 1 // 1-indexed; start on next line
			startCount++
		}
		if endRe.MatchString(line) {
			endIdx = i + 1
			endCount++
		}
	}
	if startCount != 1 {
		return Span{}, fmt.Errorf("§9.3 requires exactly 1 EDITABLE SURFACES marker pair; found %d start markers", startCount)
	}
	if endCount != 1 {
		return Span{}, fmt.Errorf("§9.3 requires exactly 1 END EDITABLE SURFACES marker; found %d end markers", endCount)
	}
	if endIdx <= startIdx {
		return Span{}, fmt.Errorf("§9.3 END marker at line %d precedes START at line %d", endIdx, startIdx)
	}
	return Span{Start: startIdx + 1 /* span begins the line AFTER opening marker */, End: endIdx}, nil
}

// Hunk captures one unified-diff hunk header + its target line range.
type Hunk struct {
	Path      string // filename from the +++ line (destination)
	StartLine int    // new-file starting line from @@ -x,y +a,b @@
	Length    int    // new-file hunk length `b`
}

// ParseUnifiedDiff extracts the hunk headers from a unified diff string.
// Minimal parser — we only need the target-file path + new-line range
// per hunk to decide if the modified bytes land inside the editable span.
func ParseUnifiedDiff(diff string) ([]Hunk, error) {
	var hunks []Hunk
	var curPath string
	lines := strings.Split(diff, "\n")
	// +++ path header: `+++ b/agent.py` or `+++ agent.py` or `+++ a/tasks/foo.harbor`
	// @@ header: `@@ -10,5 +12,7 @@` — we want the `+a,b` piece.
	plusRe := regexp.MustCompile(`^\+\+\+\s+(?:b/)?([^\s]+)`)
	hunkRe := regexp.MustCompile(`^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@`)
	for _, line := range lines {
		if m := plusRe.FindStringSubmatch(line); m != nil {
			curPath = m[1]
			continue
		}
		if m := hunkRe.FindStringSubmatch(line); m != nil {
			if curPath == "" {
				return nil, fmt.Errorf("unified-diff hunk precedes +++ header: %q", line)
			}
			startLine := 0
			length := 1
			fmt.Sscanf(m[1], "%d", &startLine)
			if m[2] != "" {
				fmt.Sscanf(m[2], "%d", &length)
			}
			hunks = append(hunks, Hunk{Path: curPath, StartLine: startLine, Length: length})
		}
	}
	return hunks, nil
}

// ImmutableTasksDir is the §9.1 normative immutable directory.
const ImmutableTasksDir = "tasks/"

// ImmutableTargets is the closed set of §9.1 immutable paths + prefixes.
// /tasks/ is the load-bearing one; additional entries can be composed in.
var ImmutableTargets = []string{"tasks/", "/tasks/"}

// ValidateDiff applies §9.3 (EDITABLE SURFACES span enforcement on the
// entrypoint file) + §9.1 (/tasks/ immutable) + §24 error-code mapping.
//
//   entrypointPath: the path the Card declares as self_improvement.entrypoint_file
//   entrypointBody: the current contents of that file (for span lookup)
//   diff:           unified diff to validate
func ValidateDiff(entrypointPath, entrypointBody, diff string) Result {
	hunks, err := ParseUnifiedDiff(diff)
	if err != nil {
		return Result{RejectReason: "SelfImprovementRejected", Detail: "parse: " + err.Error()}
	}
	if len(hunks) == 0 {
		return Result{Accepted: true, Detail: "no hunks — empty diff is a no-op"}
	}
	for _, hk := range hunks {
		// §9.1 immutable-target check first (fail fast with the sharper code).
		for _, target := range ImmutableTargets {
			if strings.HasPrefix(hk.Path, target) {
				return Result{
					RejectReason: "ImmutableTargetEdit",
					Detail:       fmt.Sprintf("hunk touches immutable path %q under §9.1 immutable set (%s)", hk.Path, target),
				}
			}
		}
		// §9.3 EDITABLE SURFACES span check — only applies to the entrypoint file.
		if hk.Path == entrypointPath || strings.HasSuffix(hk.Path, "/"+entrypointPath) {
			span, err := FindEditableSpan(entrypointBody)
			if err != nil {
				return Result{RejectReason: "SelfImprovementRejected", Detail: "§9.3 markers: " + err.Error()}
			}
			// New-file hunk line range is [startLine, startLine+length).
			hkEnd := hk.StartLine + hk.Length
			if hk.StartLine < span.Start || hkEnd > span.End {
				return Result{
					RejectReason: "SelfImprovementRejected",
					Detail: fmt.Sprintf("hunk at %s:%d-%d lies outside EDITABLE SURFACES span [%d, %d) — §9.3 marker-escape",
						hk.Path, hk.StartLine, hkEnd, span.Start, span.End),
				}
			}
		}
	}
	return Result{Accepted: true, Detail: fmt.Sprintf("diff accepted: %d hunk(s), all within §9.3 editable span + no §9.1 immutable-target touch", len(hunks))}
}
