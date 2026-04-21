// Package permresolve is the validator's independent re-implementation of the
// Core §10.3 permission-resolution algorithm. Pure function; callers supply
// (tool, capability, toolRequirements). Used by SV-PERM-01 vector path to
// assert the spec-authored 24-cell matrix AND (when impl ships POST /sessions
// + GET /permissions/resolve) to cross-validate the live Runner's decisions.
//
// This is the "independent judge" role: a second implementation of §10.3
// alongside the Runner's, so that cross-impl disagreement on any cell is
// caught at the validator, not accepted as impl's self-report.
package permresolve

import "fmt"

// Capability is the session's activeMode (Core §10.1).
type Capability string

const (
	CapReadOnly         Capability = "ReadOnly"
	CapWorkspaceWrite   Capability = "WorkspaceWrite"
	CapDangerFullAccess Capability = "DangerFullAccess"
)

// RiskClass is a tool's classification per Core §10.2.
type RiskClass string

const (
	RiskReadOnly    RiskClass = "ReadOnly"
	RiskMutating    RiskClass = "Mutating"
	RiskDestructive RiskClass = "Destructive"
	RiskEgress      RiskClass = "Egress"
)

// Control is a §10.2 gate level — AutoAllow < Prompt < Deny (tighten-only).
type Control string

const (
	CtrlAutoAllow Control = "AutoAllow"
	CtrlPrompt    Control = "Prompt"
	CtrlDeny      Control = "Deny"
)

// Decision is the terminal §10.3 output.
type Decision string

const (
	DecAutoAllow                 Decision = "AutoAllow"
	DecPrompt                    Decision = "Prompt"
	DecDeny                      Decision = "Deny"
	DecCapabilityDenied          Decision = "CapabilityDenied"
	DecConfigPrecedenceViolation Decision = "ConfigPrecedenceViolation"
)

// capabilityAllowsRisk encodes the §10.2/§10.3 risk-class-vs-activeMode lattice:
//
//	ReadOnly capability  → ReadOnly risk only
//	WorkspaceWrite       → ReadOnly, Mutating
//	DangerFullAccess     → ReadOnly, Mutating, Destructive, Egress
func capabilityAllowsRisk(cap Capability, risk RiskClass) bool {
	switch cap {
	case CapReadOnly:
		return risk == RiskReadOnly
	case CapWorkspaceWrite:
		return risk == RiskReadOnly || risk == RiskMutating
	case CapDangerFullAccess:
		return true
	}
	return false
}

// controlStrictness gives a numeric order for tighten-only composition.
func controlStrictness(c Control) int {
	switch c {
	case CtrlAutoAllow:
		return 0
	case CtrlPrompt:
		return 1
	case CtrlDeny:
		return 2
	}
	return -1
}

// Resolve executes §10.3 steps 1–4 against (tool, capability, overrideControl).
// overrideControl is the Agent Card's permissions.toolRequirements[tool.name]
// if present; empty Control means no override. Step 5 (dispatch) is NOT part of
// this function — /permissions/resolve stops at the decision.
func Resolve(risk RiskClass, defaultControl Control, cap Capability, overrideControl Control) Decision {
	// Step 1: tool known — caller has already resolved this before calling.

	// Step 2: capability gate.
	if !capabilityAllowsRisk(cap, risk) {
		return DecCapabilityDenied
	}

	// Step 3: tighten-only control composition.
	effective := defaultControl
	if overrideControl != "" {
		if controlStrictness(overrideControl) < controlStrictness(defaultControl) {
			return DecConfigPrecedenceViolation
		}
		if controlStrictness(overrideControl) > controlStrictness(effective) {
			effective = overrideControl
		}
	}

	// Step 4: policyEndpoint may tighten further. Not modeled here — spec
	// says the Runner MAY invoke it when computing the /permissions/resolve
	// response; /permissions/resolve callers see the effect via
	// policy_endpoint_applied. For the 24-cell matrix, policyEndpoint is
	// unconfigured, so step 4 is skipped.

	// Map final control to terminal decision.
	switch effective {
	case CtrlAutoAllow:
		return DecAutoAllow
	case CtrlPrompt:
		return DecPrompt
	case CtrlDeny:
		return DecDeny
	}
	return Decision(fmt.Sprintf("unknown-control=%s", effective))
}
