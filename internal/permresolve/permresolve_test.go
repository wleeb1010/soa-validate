package permresolve

import "testing"

// Expected24Cells mirrors the table in test-vectors/tool-registry/README.md.
// It is the spec-authoritative statement; the oracle must agree with it.
func TestOracleMatchesSpec24CellMatrix(t *testing.T) {
	type row struct {
		name           string
		risk           RiskClass
		defaultControl Control
		expected       map[Capability]Decision
	}
	cases := []row{
		{"fs__read_file", RiskReadOnly, CtrlAutoAllow, map[Capability]Decision{
			CapReadOnly: DecAutoAllow, CapWorkspaceWrite: DecAutoAllow, CapDangerFullAccess: DecAutoAllow,
		}},
		{"fs__list_directory", RiskReadOnly, CtrlAutoAllow, map[Capability]Decision{
			CapReadOnly: DecAutoAllow, CapWorkspaceWrite: DecAutoAllow, CapDangerFullAccess: DecAutoAllow,
		}},
		{"fs__write_file", RiskMutating, CtrlPrompt, map[Capability]Decision{
			CapReadOnly: DecCapabilityDenied, CapWorkspaceWrite: DecPrompt, CapDangerFullAccess: DecPrompt,
		}},
		{"fs__append_file", RiskMutating, CtrlAutoAllow, map[Capability]Decision{
			CapReadOnly: DecCapabilityDenied, CapWorkspaceWrite: DecAutoAllow, CapDangerFullAccess: DecAutoAllow,
		}},
		{"fs__delete_file", RiskDestructive, CtrlPrompt, map[Capability]Decision{
			CapReadOnly: DecCapabilityDenied, CapWorkspaceWrite: DecCapabilityDenied, CapDangerFullAccess: DecPrompt,
		}},
		{"net__http_get", RiskReadOnly, CtrlPrompt, map[Capability]Decision{
			CapReadOnly: DecPrompt, CapWorkspaceWrite: DecPrompt, CapDangerFullAccess: DecPrompt,
		}},
		{"proc__spawn_shell", RiskDestructive, CtrlDeny, map[Capability]Decision{
			CapReadOnly: DecCapabilityDenied, CapWorkspaceWrite: DecCapabilityDenied, CapDangerFullAccess: DecDeny,
		}},
		{"mem__recall", RiskReadOnly, CtrlAutoAllow, map[Capability]Decision{
			CapReadOnly: DecAutoAllow, CapWorkspaceWrite: DecAutoAllow, CapDangerFullAccess: DecAutoAllow,
		}},
	}
	caps := []Capability{CapReadOnly, CapWorkspaceWrite, CapDangerFullAccess}
	for _, c := range cases {
		for _, cap := range caps {
			want := c.expected[cap]
			got := Resolve(c.risk, c.defaultControl, cap, "")
			if got != want {
				t.Errorf("%s × %s: got %s, want %s", c.name, cap, got, want)
			}
		}
	}
}

func TestOracleConfigPrecedenceViolation(t *testing.T) {
	// default=Prompt, override=AutoAllow → LOOSENING attempt.
	got := Resolve(RiskReadOnly, CtrlPrompt, CapReadOnly, CtrlAutoAllow)
	if got != DecConfigPrecedenceViolation {
		t.Errorf("got %s, want ConfigPrecedenceViolation", got)
	}
}

func TestOracleTightenOnlyAllowsEqualOrTighter(t *testing.T) {
	// default=AutoAllow, override=Prompt → tightens; result is Prompt.
	got := Resolve(RiskReadOnly, CtrlAutoAllow, CapReadOnly, CtrlPrompt)
	if got != DecPrompt {
		t.Errorf("got %s, want Prompt (override tightens)", got)
	}
	// default=Prompt, override=Prompt → equal; still Prompt.
	got = Resolve(RiskReadOnly, CtrlPrompt, CapReadOnly, CtrlPrompt)
	if got != DecPrompt {
		t.Errorf("equal override: got %s, want Prompt", got)
	}
}
