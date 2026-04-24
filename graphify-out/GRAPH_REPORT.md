# Graph Report - C:\Users\wbrumbalow\Documents\Projects\soa-validate  (2026-04-24)

## Corpus Check
- 72 files · ~157,195 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 423 nodes · 712 edges · 9 communities detected
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_soa-validate.lock|"soa-validate.lock"]]
- [[_COMMUNITY_STATUS|"STATUS.md"]]
- [[_COMMUNITY_docsplansm1|"docs/plans/m1.md"]]
- [[_COMMUNITY_docsplansm3|"docs/plans/m3.md"]]
- [[_COMMUNITY_CLAUDE|"CLAUDE.md"]]
- [[_COMMUNITY_CONTEXT|"CONTEXT.md"]]
- [[_COMMUNITY_L-60|"L-60"]]
- [[_COMMUNITY_docsM1-EXIT-GATE|"docs/M1-EXIT-GATE.md"]]
- [[_COMMUNITY_CONTRIBUTING|"CONTRIBUTING.md"]]

## God Nodes (most connected - your core abstractions)
1. `docs/plans/m1.md` - 46 edges
2. `docs/plans/m3.md` - 42 edges
3. `docs/plans/m2.md` - 29 edges
4. `docs/M1-EXIT-GATE.md` - 15 edges
5. `docs/m6/credential-sweep-results.md` - 2 edges
6. `spec pin 68b34f181bcf… (current)` - 1 edges
7. `spec pin 45bd9df15227…` - 1 edges
8. `spec pin d71c83d631ae…` - 1 edges
9. `spec pin 654dc7b2698d…` - 1 edges
10. `spec pin c087a38d30d8…` - 1 edges

## Surprising Connections (you probably didn't know these)
- `docs/plans/m1.md` --cites_section--> `Spec §10.6`  [EXTRACTED]
  docs/plans/m1.md → spec-reference  _Bridges community 4 → community 2_
- `docs/M1-EXIT-GATE.md` --references_test--> `SV-PERM-01`  [EXTRACTED]
  docs/M1-EXIT-GATE.md → test-id  _Bridges community 4 → community 7_
- `docs/M1-EXIT-GATE.md` --references_test--> `SV-SIGN-01`  [EXTRACTED]
  docs/M1-EXIT-GATE.md → test-id  _Bridges community 5 → community 7_
- `docs/plans/m1.md` --references_test--> `SV-SIGN-01`  [EXTRACTED]
  docs/plans/m1.md → test-id  _Bridges community 5 → community 2_
- `docs/plans/m3.md` --references_test--> `SV-CARD-01`  [EXTRACTED]
  docs/plans/m3.md → test-id  _Bridges community 5 → community 3_

## Communities

### Community 0 - ""soa-validate.lock""
Cohesion: 0.02
Nodes (107): Finding AE, Finding AJ, Finding AL, Finding AM, Finding AP, Finding AQ, Finding AR, Finding AS (+99 more)

### Community 1 - ""STATUS.md""
Cohesion: 0.02
Nodes (238): Finding A, Finding AB, Finding AC, Finding AD, Finding AF, Finding AG, Finding AH, Finding AI (+230 more)

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
Nodes (14): Spec §19.1.1, soa-harness-impl/packages/core/test/parity/, soa-harness-impl/packages/runner/src/budget/tracker.ts, soa-harness-specification/test-vectors, HR-01, SV-BOOT-01, SV-SESS-01, HR-04 (+6 more)

### Community 6 - ""L-60""
Cohesion: 0.67
Nodes (3): docs/m6/credential-sweep-results.md, L-60, soa-harness=specification/scripts/filter-trufflehog.py

### Community 7 - ""docs/M1-EXIT-GATE.md""
Cohesion: 1.0
Nodes (2): docs/M1-EXIT-GATE.md, L-24

### Community 10 - ""CONTRIBUTING.md""
Cohesion: 0.0
Nodes (0): 

## Knowledge Gaps
- **40 isolated node(s):** `spec pin 68b34f181bcf… (current)`, `spec pin 45bd9df15227…`, `spec pin d71c83d631ae…`, `spec pin 654dc7b2698d…`, `spec pin c087a38d30d8…` (+35 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `"docs/M1-EXIT-GATE.md"`** (2 nodes): `docs/M1-EXIT-GATE.md`, `L-24`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `"CONTRIBUTING.md"`** (2 nodes): `CONTRIBUTING.md`, `COORDINATION.md`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `docs/plans/m1.md` connect `"docs/plans/m1.md"` to `"STATUS.md"`, `"docs/plans/m3.md"`, `"CLAUDE.md"`, `"CONTEXT.md"`?**
  _High betweenness centrality (0.019) - this node is a cross-community bridge._
- **Why does `docs/plans/m3.md` connect `"docs/plans/m3.md"` to `"STATUS.md"`, `"CONTEXT.md"`?**
  _High betweenness centrality (0.015) - this node is a cross-community bridge._
- **What connects `spec pin 68b34f181bcf… (current)`, `spec pin 45bd9df15227…`, `spec pin d71c83d631ae…` to the rest of the system?**
  _40 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `"soa-validate.lock"` be split into smaller, more focused modules?**
  _Cohesion score 0.02 - nodes in this community are weakly interconnected._
- **Should `"STATUS.md"` be split into smaller, more focused modules?**
  _Cohesion score 0.01 - nodes in this community are weakly interconnected._
- **Should `"docs/plans/m1.md"` be split into smaller, more focused modules?**
  _Cohesion score 0.08 - nodes in this community are weakly interconnected._
- **Should `"docs/plans/m3.md"` be split into smaller, more focused modules?**
  _Cohesion score 0.1 - nodes in this community are weakly interconnected._