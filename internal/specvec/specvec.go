// Package specvec loads the pinned test vectors the validator runs assertions
// against. All paths are relative to the spec repo root (the --spec-vectors flag).
package specvec

import (
	"fmt"
	"os"
	"path/filepath"
)

// Locator points at a spec-repo checkout. Construct once per run.
// The Root field is exported so subprocess-driven handlers (HR-12,
// SV-BOOT-01 negatives) can compose absolute paths to fixtures.
type Locator struct {
	Root string
}

func New(root string) Locator { return Locator{Root: root} }

// Path returns absolute path to a file relative to the spec repo root.
func (l Locator) Path(rel string) string {
	return filepath.Join(l.Root, rel)
}

// Read returns the bytes of a spec-repo-relative path. Fails loudly if the
// file is missing — pinned vectors must exist at the pinned commit.
func (l Locator) Read(rel string) ([]byte, error) {
	p := l.Path(rel)
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("specvec: read %s: %w", rel, err)
	}
	return b, nil
}

// Well-known paths — one place to change if the spec restructures.
const (
	AgentCardJSON   = "test-vectors/agent-card.json"
	AgentCardJWS    = "test-vectors/agent-card.json.jws"
	AgentCardSchema = "schemas/agent-card.schema.json"

	PermissionPromptJSON    = "test-vectors/permission-prompt/permission-prompt.json"
	CanonicalDecisionJSON   = "test-vectors/permission-prompt/canonical-decision.json"
	PDAJWS                  = "test-vectors/permission-prompt/pda.jws"
	CanonicalDecisionSchema = "schemas/canonical-decision.schema.json"

	InitialTrustSchema = "schemas/initial-trust.schema.json"
	CRLSchema          = "schemas/crl.schema.json"

	InitialTrustValid           = "test-vectors/initial-trust/valid.json"
	InitialTrustExpired         = "test-vectors/initial-trust/expired.json"
	InitialTrustChannelMismatch = "test-vectors/initial-trust/channel-mismatch.json"

	CRLFresh   = "test-vectors/crl/fresh.json"
	CRLStale   = "test-vectors/crl/stale.json"
	CRLExpired = "test-vectors/crl/expired.json"

	TamperedCardJWS = "test-vectors/tampered-card/agent-card.json.tampered.jws"
	ConformanceCard = "test-vectors/conformance-card/agent-card.json"

	InitialTrustMismatchedKid = "test-vectors/initial-trust/mismatched-publisher-kid.json"

	HandlerKeyPairSPKI         = "test-vectors/handler-keypair/spki_sha256.txt"
	SignedPDAJWS               = "test-vectors/permission-prompt-signed/pda.jws"
	SignedCanonicalDecision    = "test-vectors/permission-prompt-signed/canonical-decision.json"
	HandlerKeyKID              = "soa-conformance-test-handler-v1.0"

	ToolRegistryJSON = "test-vectors/tool-registry/tools.json"

	AuditTailResponseSchema          = "schemas/audit-tail-response.schema.json"
	SessionBootstrapResponseSchema   = "schemas/session-bootstrap-response.schema.json"
	PermissionsResolveResponseSchema = "schemas/permissions-resolve-response.schema.json"
	PermissionDecisionResponseSchema = "schemas/permission-decision-response.schema.json"
	AuditRecordsResponseSchema       = "schemas/audit-records-response.schema.json"

	SessionStateResponseSchema    = "schemas/session-state-response.schema.json"
	AuditSinkEventsResponseSchema = "schemas/audit-sink-events-response.schema.json"
	SessionSchema                 = "schemas/session.schema.json"

	// L-33 / L-34 — M3 observability schemas.
	MemoryStateResponseSchema      = "schemas/memory-state-response.schema.json"
	BudgetProjectionResponseSchema = "schemas/budget-projection-response.schema.json"
	ToolsRegisteredResponseSchema  = "schemas/tools-registered-response.schema.json"
	EventsRecentResponseSchema     = "schemas/events-recent-response.schema.json"

	// L-35 — §14.1 closed 27-type enum schema + per-type payload dispatch.
	StreamEventSchema         = "schemas/stream-event.schema.json"
	StreamEventPayloadsSchema = "schemas/stream-event-payloads.schema.json"

	// L-36 — §14.5.2 + §14.5.3 new observability endpoints.
	OTelSpansRecentResponseSchema   = "schemas/otel-spans-recent-response.schema.json"
	BackpressureStatusResponseSchema = "schemas/backpressure-status-response.schema.json"

	// L-38 — §14.5.4 System Event Log observation surface.
	SystemLogRecentResponseSchema = "schemas/system-log-recent-response.schema.json"

	// L-39 — two conformance card fixture variants for SV-BUD-02 + SV-MEM-06.
	ConformanceCardLowBudget      = "test-vectors/conformance-card-low-budget/agent-card.json"
	ConformanceCardMemoryProject  = "test-vectors/conformance-card-memory-project/agent-card.json"

	// L-42 — SV-CARD-10 precedence-violation + SV-SIGN-02/05 program.md JWS fixtures.
	ConformanceCardPrecedenceViolation = "test-vectors/conformance-card-precedence-violation/agent-card.json"
	ProgramMD                          = "test-vectors/program-md/program.md"
	ProgramMDJWS                       = "test-vectors/program-md/program.md.jws"
	ProgramMDX5TJWS                    = "test-vectors/program-md/program.md.x5t.jws"
	HandlerKeypairPublicJWK            = "test-vectors/handler-keypair/public.jwk.json"

	// L-43 — SV-BOOT-03/05 fixtures for DNSSEC + secondary-channel split-brain.
	DnssecBootstrapValid             = "test-vectors/dnssec-bootstrap/valid.json"
	DnssecBootstrapEmpty             = "test-vectors/dnssec-bootstrap/empty.json"
	DnssecBootstrapMissingADBit      = "test-vectors/dnssec-bootstrap/missing-ad-bit.json"
	BootstrapSecondaryChannelTrust   = "test-vectors/bootstrap-secondary-channel/initial-trust.json"

	// JCS parity vectors (RFC 8785 Appendix-style) for SV-ENC-05.
	JCSParityGeneratedDir = "test-vectors/jcs-parity/generated"

	// L-44 — SV-ENC-06 JWT clock-skew fixtures (T_REF = 2026-04-22T12:00:00Z).
	JWTClockSkewIatInWindow = "test-vectors/jwt-clock-skew/iat-in-window.jwt"
	JWTClockSkewIatPast     = "test-vectors/jwt-clock-skew/iat-past.jwt"
	JWTClockSkewIatFuture   = "test-vectors/jwt-clock-skew/iat-future.jwt"
	JWTClockSkewExpExpired  = "test-vectors/jwt-clock-skew/exp-expired.jwt"

	// L-34 — memory-mcp-mock fixture dir (validator-driven mock consumer).
	MemoryMCPMockDir = "test-vectors/memory-mcp-mock"

	// L-30: v1.1 drift-pair card. Byte-identical to conformance-card
	// except version is "1.1.0". Enables SV-SESS-09 two-fixture swap
	// without validator-side card mutation (which would trip impl's
	// digest-check on the vanilla conformance-card path).
	ConformanceCardV1_1 = "test-vectors/conformance-card-v1_1/agent-card.json"

	ToolRegistryM2Dir              = "test-vectors/tool-registry-m2"
	ToolRegistryM2Combined         = "test-vectors/tool-registry-m2/tools.json"
	ToolRegistryM2CompliantOnly    = "test-vectors/tool-registry-m2/tools-compliant-only.json"
	ToolRegistryM2NonCompliantOnly = "test-vectors/tool-registry-m2/tools-non-compliant-only.json"
)
