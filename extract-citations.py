#!/usr/bin/env python3
"""
extract-citations.py — deterministic citation-graph extractor for the
soa-validate repo (docs + plans + status + lock-file pin tracking).

Scope per setup contract:
  DO ingest: *.md (docs/, plans/, root), CLAUDE.md, STATUS.md,
             README.md, CONTRIBUTING.md, soa-validate.lock (metadata).
  DO NOT ingest: .go (CGC handles), go.sum/go.mod, .git/, vendor/,
                 graphify-out/ (own outputs).

Extracted citation patterns:
  - Spec § references:   §N(.M)*        → link to spec_section_N_M
  - Test IDs:            SV-[A-Z]+-[0-9]+ | HR-[0-9]+ | UV-[A-Z]+-[0-9]+
  - Findings:            Finding [A-Z]{1,2}
  - L-entries:           L-[0-9]+
  - Cross-repo refs:     soa-harness-specification/... | soa-harness-impl/...
  - Spec-pin SHAs:       40-hex near "spec_commit_sha" in .lock

Produces JSON in graphify extraction schema. Merge target: refresh-graph.py.
"""
import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

# File inclusion / exclusion policy
INCLUDE_EXT = {'.md'}
EXCLUDE_DIRS = {'.git', 'graphify-out', 'vendor', 'node_modules'}
EXTRA_INGEST = {'soa-validate.lock'}  # lock file: pin-history metadata only

# Regex patterns
SECTION_RE = re.compile(r'§\s*(\d+(?:\.\d+)*)')
TESTID_SV_RE = re.compile(r'\b(SV-[A-Z]+-[A-Z0-9]+)\b')
TESTID_HR_RE = re.compile(r'\bHR-(\d+)\b')
TESTID_UV_RE = re.compile(r'\b(UV-[A-Z]+-[0-9]+)\b')
FINDING_RE = re.compile(r'\bFinding\s+([A-Z]{1,2}(?:-ext|-ext-\d+|-impl|-impl-ext)?)\b')
LENTRY_RE = re.compile(r'\bL-(\d+)\b')
CROSSREPO_RE = re.compile(
    r'\b(soa-harness[-=]specification|soa-harness-impl)/([A-Za-z0-9_./-]+)',
)
SHA_RE = re.compile(r'\b([0-9a-f]{40})\b')
HEADING_RE = re.compile(r'^(#{1,6})\s+(.+?)\s*$', re.M)


def make_node(nid, label, src, location=None, file_type='document', extra=None):
    n = {
        'id': nid,
        'label': label,
        'file_type': file_type,
        'source_file': src,
        'source_location': location,
    }
    if extra:
        n.update(extra)
    return n


def make_edge(src, tgt, relation, src_file=None, location=None, score=1.0):
    return {
        'source': src,
        'target': tgt,
        'relation': relation,
        'confidence': 'EXTRACTED',
        'confidence_score': score,
        'source_file': src_file,
        'source_location': location,
        'weight': 1.0,
    }


def file_id(rel: str) -> str:
    return 'file_' + rel.replace('/', '_').replace('\\', '_').replace('.', '_').replace(' ', '_').replace('=', '_')


def containing_heading(pos: int, headings: list) -> tuple:
    """Return (heading_text, line_number) of the heading immediately
    preceding pos, or (None, None) if no heading precedes."""
    current = (None, None)
    for off, text, line in headings:
        if off <= pos:
            current = (text, line)
        else:
            break
    return current


def parse_headings(text: str) -> list:
    out = []
    for m in HEADING_RE.finditer(text):
        out.append((m.start(), m.group(2).strip(), text[:m.start()].count('\n') + 1))
    return out


def iter_text_files(root: Path):
    """Yield every markdown file we want to ingest + the lock file."""
    for p in root.rglob('*.md'):
        if any(part in EXCLUDE_DIRS for part in p.parts):
            continue
        yield p
    lock = root / 'soa-validate.lock'
    if lock.exists():
        yield lock


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('root', nargs='?', default='.')
    ap.add_argument('--audit', action='store_true')
    ap.add_argument('-o', '--output', default='graphify-out/citations.json')
    args = ap.parse_args()

    root = Path(args.root).resolve()
    nodes: dict = {}
    edges: list = []
    test_cite_files: dict = defaultdict(set)
    finding_cite_files: dict = defaultdict(set)
    lentry_cite_files: dict = defaultdict(set)

    total_files = 0
    files_with_citations = 0

    for path in iter_text_files(root):
        total_files += 1
        rel = str(path.relative_to(root)).replace('\\', '/')

        # Root-file node
        fnid = file_id(rel)
        if fnid not in nodes:
            nodes[fnid] = make_node(fnid, rel, rel)

        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue

        headings = parse_headings(text) if rel.endswith('.md') else []

        any_citation = False

        # Spec § references
        for m in SECTION_RE.finditer(text):
            num = m.group(1)
            tgt = f'spec_section_{num.replace(".", "_")}'
            if tgt not in nodes:
                nodes[tgt] = make_node(
                    tgt, f'Spec §{num}', 'spec-reference',
                    file_type='document', extra={'citation_kind': 'spec-section'},
                )
            # Source = containing heading if md, else file-node
            line = text[:m.start()].count('\n') + 1
            edges.append(make_edge(fnid, tgt, 'cites_section', rel, f'line {line}'))
            any_citation = True

        # SV-* test IDs
        for m in TESTID_SV_RE.finditer(text):
            tid = m.group(1)
            tnid = f'test_{tid.lower().replace("-", "_")}'
            if tnid not in nodes:
                nodes[tnid] = make_node(tnid, tid, 'test-id', file_type='document', extra={'citation_kind': 'test-id'})
            test_cite_files[tid].add(rel)
            line = text[:m.start()].count('\n') + 1
            edges.append(make_edge(fnid, tnid, 'references_test', rel, f'line {line}'))
            any_citation = True

        # HR-* test IDs
        for m in TESTID_HR_RE.finditer(text):
            num = m.group(1)
            tid = f'HR-{num.zfill(2)}'
            tnid = f'test_hr_{num.zfill(2)}'
            if tnid not in nodes:
                nodes[tnid] = make_node(tnid, tid, 'test-id', file_type='document', extra={'citation_kind': 'test-id'})
            test_cite_files[tid].add(rel)
            line = text[:m.start()].count('\n') + 1
            edges.append(make_edge(fnid, tnid, 'references_test', rel, f'line {line}'))
            any_citation = True

        # UV-* test IDs (UI profile)
        for m in TESTID_UV_RE.finditer(text):
            tid = m.group(1)
            tnid = f'test_{tid.lower().replace("-", "_")}'
            if tnid not in nodes:
                nodes[tnid] = make_node(tnid, tid, 'test-id', file_type='document', extra={'citation_kind': 'test-id'})
            test_cite_files[tid].add(rel)
            line = text[:m.start()].count('\n') + 1
            edges.append(make_edge(fnid, tnid, 'references_test', rel, f'line {line}'))
            any_citation = True

        # Findings
        for m in FINDING_RE.finditer(text):
            letter = m.group(1)
            fid = f'finding_{letter.lower().replace("-", "_")}'
            if fid not in nodes:
                nodes[fid] = make_node(
                    fid, f'Finding {letter}', 'finding-ledger',
                    file_type='document', extra={'citation_kind': 'finding'},
                )
            finding_cite_files[letter].add(rel)
            line = text[:m.start()].count('\n') + 1
            edges.append(make_edge(fnid, fid, 'references_finding', rel, f'line {line}'))
            any_citation = True

        # L-entries
        for m in LENTRY_RE.finditer(text):
            num = m.group(1)
            lid = f'l_{num.zfill(2)}'
            if lid not in nodes:
                nodes[lid] = make_node(
                    lid, f'L-{num}', 'spec-lentry',
                    file_type='document', extra={'citation_kind': 'spec-lentry'},
                )
            lentry_cite_files[num].add(rel)
            line = text[:m.start()].count('\n') + 1
            edges.append(make_edge(fnid, lid, 'references_lentry', rel, f'line {line}'))
            any_citation = True

        # Cross-repo file refs
        for m in CROSSREPO_RE.finditer(text):
            other_repo = m.group(1)
            rel_in_other = m.group(2)
            xid = f'xrepo_{other_repo.replace("-", "_").replace("=", "_")}_{rel_in_other.replace("/", "_").replace(".", "_").replace("-", "_")}'
            xlabel = f'{other_repo}/{rel_in_other}'
            if xid not in nodes:
                nodes[xid] = make_node(
                    xid, xlabel, 'cross-repo',
                    file_type='document',
                    extra={'citation_kind': 'cross-repo', 'repo': other_repo, 'path': rel_in_other},
                )
            line = text[:m.start()].count('\n') + 1
            edges.append(make_edge(fnid, xid, 'references_external_file', rel, f'line {line}'))
            any_citation = True

        # Spec-pin SHA references: track 40-hex patterns NEAR pin tokens
        # (only meaningful for soa-validate.lock)
        if path.name == 'soa-validate.lock':
            try:
                lock_json = json.loads(text)
            except json.JSONDecodeError:
                lock_json = None
            if isinstance(lock_json, dict):
                current_sha = lock_json.get('spec_commit_sha')
                if isinstance(current_sha, str) and SHA_RE.fullmatch(current_sha):
                    pin_id = f'spec_pin_{current_sha}'
                    nodes[pin_id] = make_node(
                        pin_id,
                        f'spec pin {current_sha[:12]}… (current)',
                        rel,
                        file_type='document',
                        extra={'sha': current_sha, 'status': 'current'},
                    )
                    edges.append(make_edge(fnid, pin_id, 'pins', rel))
                    any_citation = True
                for entry in lock_json.get('pin_history', []):
                    sha = entry.get('bumped_to') or entry.get('sha')
                    if isinstance(sha, str) and SHA_RE.fullmatch(sha):
                        pin_id = f'spec_pin_{sha}'
                        if pin_id not in nodes:
                            nodes[pin_id] = make_node(
                                pin_id,
                                f'spec pin {sha[:12]}…',
                                rel,
                                file_type='document',
                                extra={'sha': sha, 'status': 'historical'},
                            )
                        edges.append(make_edge(fnid, pin_id, 'pin_history', rel))

        if any_citation:
            files_with_citations += 1

    out = {
        'nodes': list(nodes.values()),
        'edges': edges,
        'hyperedges': [],
        'input_tokens': 0,
        'output_tokens': 0,
    }
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding='utf-8')
    print(f'Wrote {len(nodes)} nodes, {len(edges)} edges to {args.output}')
    print(f'  total files ingested: {total_files}')
    print(f'  files with ≥1 citation: {files_with_citations}')
    print(f'  distinct SV/HR/UV test IDs referenced: {len(test_cite_files)}')
    print(f'  distinct Findings referenced: {len(finding_cite_files)}')
    print(f'  distinct L-entries referenced: {len(lentry_cite_files)}')

    if args.audit:
        print('\n=== Integrity audit ===')
        print(f'Test IDs referenced: {len(test_cite_files)}')
        for tid in sorted(test_cite_files)[:20]:
            print(f'  {tid}  cited from {len(test_cite_files[tid])} file(s)')


if __name__ == '__main__':
    main()
