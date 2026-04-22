# Graph Report - C:\Users\wbrumbalow\Documents\Projects\soa-validate  (2026-04-22)

## Corpus Check
- 69 files · ~146,358 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 381 nodes · 665 edges · 8 communities detected
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_soa-validate.lock|"soa-validate.lock"]]
- [[_COMMUNITY_STATUS|"STATUS.md"]]
- [[_COMMUNITY_docsplansm1|"docs/plans/m1.md"]]
- [[_COMMUNITY_docsplansm3|"docs/plans/m3.md"]]
- [[_COMMUNITY_CLAUDE|"CLAUDE.md"]]
- [[_COMMUNITY_CONTEXT|"CONTEXT.md"]]
- [[_COMMUNITY_docsM1-EXIT-GATE|"docs/M1-EXIT-GATE.md"]]
- [[_COMMUNITY_CONTRIBUTING|"CONTRIBUTING.md"]]

## God Nodes (most connected - your core abstractions)
1. `docs/plans/m1.md` - 46 edges
2. `docs/plans/m3.md` - 42 edges
3. `docs/plans/m2.md` - 29 edges
4. `docs/M1-EXIT-GATE.md` - 15 edges
5. `spec pin 5d3054562635… (current)` - 1 edges
6. `spec pin 782735c9c362…` - 1 edges
7. `spec pin 177f211f78a3…` - 1 edges
8. `spec pin eb5aedb2ab76…` - 1 edges
9. `spec pin aa49770890a2…` - 1 edges
10. `spec pin bebc6bd16d3c…` - 1 edges

## Surprising Connections (you probably didn't know these)
- `docs/plans/m1.md` --cites_section--> `Spec §10.6`  [EXTRACTED]
  docs/plans/m1.md → spec-reference  _Bridges community 4 → community 2_
- `docs/M1-EXIT-GATE.md` --references_test--> `SV-PERM-01`  [EXTRACTED]
  docs/M1-EXIT-GATE.md → test-id  _Bridges community 4 → community 6_
- `docs/M1-EXIT-GATE.md` --references_test--> `SV-SIGN-01`  [EXTRACTED]
  docs/M1-EXIT-GATE.md → test-id  _Bridges community 5 → community 6_
- `docs/plans/m1.md` --references_test--> `SV-SIGN-01`  [EXTRACTED]
  docs/plans/m1.md → test-id  _Bridges community 5 → community 2_
- `docs/plans/m3.md` --references_test--> `SV-CARD-01`  [EXTRACTED]
  docs/plans/m3.md → test-id  _Bridges community 5 → community 3_

## Communities

### Community 0 - ""soa-validate.lock""
Cohesion: 0.02
Nodes (84): Finding AB, Finding AC, Finding AE, Finding AI, Finding AL, Finding AM, Finding AP, Finding AQ (+76 more)

### Community 1 - ""STATUS.md""
Cohesion: 0.03
Nodes (222): Finding A, Finding AD, Finding AF, Finding AG, Finding AH, Finding AJ, Finding AK, Finding AN (+214 more)

### Community 2 - ""docs/plans/m1.md""
Cohesion: 0.08
Nodes (25): docs/plans/m1.md, L-13, L-14, L-15, L-16, L-17, L-18, L-19 (+17 more)

### Community 3 - ""docs/plans/m3.md""
Cohesion: 0.11
Nodes (21): docs/plans/m2.md, docs/plans/m3.md, L-20, L-28, L-34, Spec §10.5.1, Spec §11, Spec §11.3.1 (+13 more)

### Community 4 - ""CLAUDE.md""
Cohesion: 0.33
Nodes (6): Spec §10, Spec §10.6, Spec §21.2, Spec §7.4, soa-harness=specification/test-vectors/, SV-PERM-01

### Community 5 - ""CONTEXT.md""
Cohesion: 0.33
Nodes (14): Spec §19.1.1, soa-harness-impl/packages/core/test/parity/, soa-harness-impl/packages/runner/src/budget/tracker.ts, soa-harness-specification/test-vectors, SV-SIGN-01, HR-12, SV-CARD-01, SV-BOOT-01 (+6 more)

### Community 6 - ""docs/M1-EXIT-GATE.md""
Cohesion: 1.0
Nodes (2): docs/M1-EXIT-GATE.md, L-24

### Community 9 - ""CONTRIBUTING.md""
Cohesion: 0.0
Nodes (0): 

## Knowledge Gaps
- **35 isolated node(s):** `spec pin 5d3054562635… (current)`, `spec pin 782735c9c362…`, `spec pin 177f211f78a3…`, `spec pin eb5aedb2ab76…`, `spec pin aa49770890a2…` (+30 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `"docs/M1-EXIT-GATE.md"`** (2 nodes): `docs/M1-EXIT-GATE.md`, `L-24`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `"CONTRIBUTING.md"`** (2 nodes): `CONTRIBUTING.md`, `COORDINATION.md`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `docs/plans/m1.md` connect `"docs/plans/m1.md"` to `"STATUS.md"`, `"docs/plans/m3.md"`, `"CLAUDE.md"`, `"CONTEXT.md"`?**
  _High betweenness centrality (0.021) - this node is a cross-community bridge._
- **Why does `docs/plans/m3.md` connect `"docs/plans/m3.md"` to `"STATUS.md"`, `"CONTEXT.md"`?**
  _High betweenness centrality (0.017) - this node is a cross-community bridge._
- **Why does `docs/plans/m2.md` connect `"docs/plans/m3.md"` to `"STATUS.md"`, `"CONTEXT.md"`?**
  _High betweenness centrality (0.003) - this node is a cross-community bridge._
- **What connects `spec pin 5d3054562635… (current)`, `spec pin 782735c9c362…`, `spec pin 177f211f78a3…` to the rest of the system?**
  _35 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `"soa-validate.lock"` be split into smaller, more focused modules?**
  _Cohesion score 0.02 - nodes in this community are weakly interconnected._
- **Should `"STATUS.md"` be split into smaller, more focused modules?**
  _Cohesion score 0.01 - nodes in this community are weakly interconnected._
- **Should `"docs/plans/m1.md"` be split into smaller, more focused modules?**
  _Cohesion score 0.08 - nodes in this community are weakly interconnected._