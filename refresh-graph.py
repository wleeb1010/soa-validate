#!/usr/bin/env python3
"""
refresh-graph.py — rebuild graphify-out/ for soa-validate (docs + citations only).

Scope: this repo's docs + citation web. NOT code — CodeGraphContext MCP
owns the Go-source graph. Setup-contract non-goals:
  - Do NOT ingest .go files (CGC handles)
  - Do NOT ingest go.sum/go.mod (binary-ish, not prose)
  - Do NOT cross-ingest the spec repo (separate MCP via citations only)

Pipeline:
  1. Citation extractor (fresh, deterministic, no LLM) on *.md + lock
  2. Load any cached semantic extractions (optional; from prior /graphify)
  3. Merge via graphify.build.build([...])
  4. Cluster + analyze
  5. Regenerate graph.json + graph.html + GRAPH_REPORT.md

Invoked by git post-commit hook; safe to run manually.
Falls back gracefully if graphify isn't installed or no semantic cache exists.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

os.environ.setdefault("PYTHONIOENCODING", "utf-8")

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "graphify-out"
CACHE = OUT / "cache"
CITATIONS = OUT / "citations.json"


def load_citations() -> dict:
    script = ROOT / "extract-citations.py"
    if not script.exists():
        return {"nodes": [], "edges": [], "hyperedges": []}
    subprocess.run(
        [sys.executable, str(script), str(ROOT), "-o", str(CITATIONS)],
        check=True,
    )
    return json.loads(CITATIONS.read_text(encoding="utf-8"))


def load_semantic_cache() -> dict:
    """Load only cache entries whose hash matches a current file in the tree.

    Stale entries (from files that were edited, renamed, or deleted since
    the last `/graphify .` run) are silently skipped so they don't
    contaminate the merged graph.
    """
    merged = {"nodes": [], "edges": [], "hyperedges": [], "stats": {"live": 0, "stale": 0, "uncovered": []}}
    if not CACHE.exists():
        return merged

    try:
        from graphify.cache import file_hash
    except ImportError:
        return merged

    # We only semantically cache prose files. Go files go through CGC.
    current_hashes: dict[str, str] = {}
    for pat in ("*.md", "*.lock"):
        for p in ROOT.rglob(pat):
            if OUT in p.parents:
                continue
            if any(part in {".git", "graphify-out", "vendor", "node_modules"} for part in p.parts):
                continue
            try:
                h = file_hash(p, ROOT)
                current_hashes[h] = str(p.relative_to(ROOT))
            except OSError:
                pass

    seen_node_ids: set[str] = set()
    covered_files: set[str] = set()
    live, stale, pruned = 0, 0, 0
    prune = os.environ.get("REFRESH_GRAPH_PRUNE", "1") != "0"
    for entry in CACHE.glob("*.json"):
        if entry.stem not in current_hashes:
            stale += 1
            if prune:
                try:
                    entry.unlink()
                    pruned += 1
                except OSError:
                    pass
            continue
        live += 1
        covered_files.add(current_hashes[entry.stem])
        try:
            d = json.loads(entry.read_text(encoding="utf-8"))
        except Exception:
            continue
        for n in d.get("nodes", []):
            nid = n.get("id")
            if nid and nid not in seen_node_ids:
                seen_node_ids.add(nid)
                merged["nodes"].append(n)
        merged["edges"].extend(d.get("edges", []))
        merged["hyperedges"].extend(d.get("hyperedges", []))

    uncovered = sorted(set(current_hashes.values()) - covered_files)
    uncovered = [f for f in uncovered if not f.startswith(".") and f not in {
        "extract-citations.py", "refresh-graph.py"
    }]
    merged["stats"] = {"live": live, "stale": stale, "pruned": pruned, "uncovered": uncovered}
    return merged


def main() -> int:
    try:
        import graphify  # noqa: F401
    except ImportError:
        print("[refresh-graph] graphify not installed — skipping", file=sys.stderr)
        return 0

    from graphify.analyze import god_nodes, suggest_questions, surprising_connections
    from graphify.build import build
    from graphify.cluster import cluster, score_all
    from graphify.export import to_html, to_json
    from graphify.report import generate

    OUT.mkdir(parents=True, exist_ok=True)

    # NO AST extraction for this repo — CGC owns the Go-source graph.
    ast = {"nodes": [], "edges": [], "hyperedges": []}
    semantic = load_semantic_cache()
    citations = load_citations()

    stats = semantic.get("stats", {})
    stale_n = stats.get("stale", 0)
    pruned_n = stats.get("pruned", 0)
    stale_desc = f"stale={stale_n}"
    if pruned_n:
        stale_desc += f" (pruned {pruned_n} from disk)"
    print(
        f"[refresh-graph] sources: "
        f"semantic-cache {len(semantic['nodes'])}n/{len(semantic['edges'])}e "
        f"(live={stats.get('live',0)}, {stale_desc}), "
        f"citations {len(citations['nodes'])}n/{len(citations['edges'])}e"
    )

    uncovered = stats.get("uncovered", [])
    flag_path = OUT / ".needs-semantic-update"
    if uncovered:
        flag_path.write_text("\n".join(uncovered), encoding="utf-8")
        banner = "=" * 72
        print(banner)
        print(f"[refresh-graph] ACTION NEEDED: {len(uncovered)} file(s) have no semantic coverage.")
        for f in uncovered[:10]:
            print(f"    - {f}")
        if len(uncovered) > 10:
            print(f"    ...and {len(uncovered) - 10} more")
        print("")
        print("  To refresh: run `/graphify --update` in your next Claude Code session.")
        print(banner)
    elif flag_path.exists():
        try:
            flag_path.unlink()
        except OSError:
            pass

    G = build([ast, semantic, citations])

    # Cluster on the non-test-ID subgraph; test-IDs are leaf-heavy.
    test_ids = {n for n, d in G.nodes(data=True) if str(n).startswith("test_")}
    G_core = G.subgraph(set(G.nodes()) - test_ids).copy()
    communities = cluster(G_core)
    cohesion = score_all(G_core, communities)

    node_to_comm = {nid: cid for cid, members in communities.items() for nid in members}
    for tid in test_ids:
        neighbors = G.neighbors(tid) if not G.is_directed() else (src for src, _ in G.in_edges(tid))
        for src in neighbors:
            cid = node_to_comm.get(src)
            if cid is not None:
                communities[cid].append(tid)
                node_to_comm[tid] = cid
                break

    # Collapse zero-degree singletons into "Unreferenced" community.
    isolated_cid = max(communities.keys(), default=-1) + 1
    isolated_members = []
    for cid in list(communities.keys()):
        members = communities[cid]
        if len(members) == 1 and G.degree(members[0]) == 0:
            isolated_members.append(members[0])
            del communities[cid]
    if isolated_members:
        communities[isolated_cid] = isolated_members
        cohesion[isolated_cid] = 0.0

    gods = god_nodes(G)
    surprises = surprising_connections(G, communities)

    labels_path = OUT / "community-labels.json"
    anchor_labels: dict[str, str] = {}
    if labels_path.exists():
        try:
            anchor_labels = json.loads(labels_path.read_text(encoding="utf-8"))
        except Exception:
            anchor_labels = {}

    def anchor_of(members: list) -> str:
        return max(members, key=lambda n: (G.degree(n), -len(n)))

    labels: dict = {}
    for cid, members in communities.items():
        a = anchor_of(members)
        if a in anchor_labels:
            labels[cid] = anchor_labels[a]
        else:
            anchor_label = G.nodes[a].get("label", a) if a in G.nodes else a
            labels[cid] = f'"{anchor_label[:60]}"'

    questions = suggest_questions(G, communities, labels)

    try:
        from graphify.detect import detect
        detection = detect(ROOT)
    except Exception:
        detection = {"files": {}}

    tokens = {"input": 0, "output": 0}

    report = generate(
        G, communities, cohesion, labels, gods, surprises,
        detection, tokens, str(ROOT), suggested_questions=questions,
    )
    (OUT / "GRAPH_REPORT.md").write_text(report, encoding="utf-8")
    to_json(G, communities, str(OUT / "graph.json"))

    n = G.number_of_nodes()
    e = G.number_of_edges()
    if n <= 5000:
        to_html(G, communities, str(OUT / "graph.html"), community_labels=labels)
        print(f"[refresh-graph] wrote graph.json + graph.html + GRAPH_REPORT.md ({n}n/{e}e, {len(communities)} communities)")
    else:
        print(f"[refresh-graph] {n} nodes exceeds viz limit; skipped graph.html")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
