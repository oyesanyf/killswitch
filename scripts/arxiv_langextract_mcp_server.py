#!/usr/bin/env python3
"""
arxiv_langextract_mcp_server.py
======================================================================================
arXiv Research Discovery, Multi-Factor Article Ranking, Google LangExtract Source Grounding,
and Paper2Code Production Rust & Cedar Synthesis MCP Server for Antigravity IDE,
OshoosiClaw, KillSwitch, and AgentOctopus.
"""

from __future__ import annotations

import importlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, List, Optional

# Ensure all logging goes strictly to stderr so MCP stdio JSON-RPC on stdout is never polluted
logging.basicConfig(stream=sys.stderr, level=logging.WARNING, force=True)
for _logger_name in ("arxiv", "httpx", "httpcore", "urllib3", "langextract"):
    logging.getLogger(_logger_name).setLevel(logging.WARNING)

# Ensure scripts directory is importable
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from mcp.server.mcpserver import MCPServer
try:
    import langextract as lx
except ImportError:
    lx = None  # type: ignore
try:
    import arxiv
except ImportError:
    arxiv = None  # type: ignore

from arxiv_langextract_feed import (
    BREAKOUT_SIGNATURES,
    CODEBASE_IMPLEMENTED_PAPERS,
    DEFENSE_COUNTERMEASURE_SIGNATURES,
    LOCAL_CONTAINMENT_MAPPINGS,
    MATH_FORMULATION_SIGNATURES,
    RIGOR_KEYWORDS,
    audit_defense_coverage_multi_target,
    compute_article_rank,
    extract_grounded_breakouts,
    fetch_paper_by_id,
    generate_interactive_html,
    ingest_into_killswitch,
    normalize_arxiv_id,
    search_and_rank_articles,
    search_breakout_papers,
)
import arxiv_paper2code_generator


def synthesize_production_rust_and_cedar(paper: dict, extractions: list) -> dict:
    importlib.reload(arxiv_paper2code_generator)
    return arxiv_paper2code_generator.synthesize_production_rust_and_cedar(paper, extractions)

server = MCPServer("arxiv-langextract")

# Re-enforce stderr WARNING logging after MCPServer initialization
logging.basicConfig(stream=sys.stderr, level=logging.WARNING, force=True)
for _logger_name in ("arxiv", "httpx", "httpcore", "urllib3", "langextract", "mcp"):
    logging.getLogger(_logger_name).setLevel(logging.WARNING)


# =============================================================================
# Tool 1: langextract_status
# =============================================================================

@server.tool()
async def langextract_status() -> str:
    """
    Check the health and configuration status of the arXiv + Google LangExtract + Paper2Code MCP server.
    Returns installed versions, ranking factor weights, active breakout signature classes,
    Paper2Code Rust & Cedar synthesis capabilities, and supported target systems.
    """
    return json.dumps({
        "server": "arxiv-langextract",
        "status": "operational",
        "paper2code_rust_and_cedar_synthesis": "enabled",
        "python_version": sys.version.split()[0],
        "langextract_version": getattr(lx, "__version__", "1.7.1"),
        "arxiv_version": getattr(arxiv, "__version__", "4.0.2"),
        "ranking_factors": {
            "grounded_vector_density_max": 35.0,
            "threat_severity_tier_max": 30.0,
            "empirical_rigor_max": 20.0,
            "temporal_recency_max": 15.0,
            "novelty_delta_max": 15.0,
            "code_repo_priority_bonus": 20.0,
            "total_max_score": 100.0,
        },
        "priority_tiers": {
            "TIER-1 CRITICAL": ">= 80.0",
            "TIER-2 HIGH": "60.0 - 79.9",
            "TIER-3 MODERATE": "40.0 - 59.9",
            "TIER-4 LOW": "< 40.0",
        },
        "grounding_classes": [
            "breakout_vector",
            "mathematical_formulation",
            "defense_countermeasure",
        ],
        "codebase_implemented_papers": CODEBASE_IMPLEMENTED_PAPERS,
        "supported_target_systems": ["all", "oshoosiclaw", "killswitch", "octopus"],
    }, indent=2)


# =============================================================================
# Tool 2: search_and_rank_breakout_articles
# =============================================================================

@server.tool()
async def search_and_rank_breakout_articles(
    query: str = "LLM agent sandbox escape breakout",
    max_results: int = 5,
    min_score: float = 0.0,
    only_novel_enhancements: bool = True,
) -> str:
    """
    Search arXiv for research articles, extract source-grounded breakout vectors using Google
    LangExtract, rank the articles from highest to lowest (0-100 score), and synthesize
    production Rust defense code and Cedar policies for each ranked paper.
    """
    try:
        ranked = search_and_rank_articles(
            query=query,
            max_results=max(1, min(int(max_results), 25)),
            min_score=float(min_score),
            only_novel_enhancements=bool(only_novel_enhancements),
        )
        for item in ranked:
            item["generated_production_code"] = synthesize_production_rust_and_cedar(
                item, item.get("extractions", [])
            )
        return json.dumps({
            "query": query,
            "total_ranked": len(ranked),
            "only_novel_enhancements": only_novel_enhancements,
            "ranked_articles": ranked,
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc), "query": query}, indent=2)


# =============================================================================
# Tool 3: extract_and_ground_article
# =============================================================================

@server.tool()
async def extract_and_ground_article(
    arxiv_id: str,
    output_html_path: str = "",
) -> str:
    """
    Fetch a specific arXiv paper by ID (e.g. '2608.15888' or '2603.02277'), run Google LangExtract
    3-class character-interval source grounding, compute its threat rank score, synthesize and
    print the full production Rust defense module + tighten-only AST guard + Cedar policies so
    you can inspect or port it directly in your IDE, and optionally generate an interactive HTML report.
    """
    try:
        clean_id = normalize_arxiv_id(arxiv_id)
        paper = fetch_paper_by_id(clean_id)
        if not paper:
            return json.dumps({"error": f"Paper not found for arXiv ID: {clean_id}"}, indent=2)

        extractions, annotated_doc = extract_grounded_breakouts(paper)
        rank_info = compute_article_rank(paper, extractions)
        paper["code_repo_url"] = rank_info.get("code_repo_url", paper.get("code_repo_url", ""))
        code_bundle = synthesize_production_rust_and_cedar(paper, extractions)

        saved_html = None
        if output_html_path.strip():
            out_path = str(Path(output_html_path).resolve())
            generate_interactive_html(annotated_doc, out_path)
            saved_html = out_path

        return json.dumps({
            "arxiv_id": paper["arxiv_id"],
            "title": paper["title"],
            "published": paper["published"],
            "authors": paper["authors"],
            "url": paper["url"],
            "pdf_url": paper["pdf_url"],
            "has_code_repo": rank_info["has_code_repo"],
            "code_repo_url": rank_info["code_repo_url"],
            "rank_score": rank_info["total_score"],
            "priority_tier": rank_info["priority_tier"],
            "is_novel_to_codebase": rank_info["is_novel_to_codebase"],
            "enhances_codebase": rank_info["enhances_codebase"],
            "novelty_delta_score": rank_info["novelty_delta_score"],
            "target_crates_enhanced": rank_info["target_crates_enhanced"],
            "score_breakdown": rank_info["breakdown"],
            "grounded_extractions": extractions,
            "interactive_html_report": saved_html,
            "generated_production_code": code_bundle,
            "printable_code_bundle_markdown": code_bundle["printable_code_bundle_markdown"],
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc), "arxiv_id": arxiv_id}, indent=2)


# =============================================================================
# Tool 4: ingest_ranked_articles_to_killswitch
# =============================================================================

@server.tool()
async def ingest_ranked_articles_to_killswitch(
    query_or_arxiv_id: str = "2603.02277",
    top_k: int = 3,
    server_url: str = "http://127.0.0.1:3030",
) -> str:
    """
    Search and rank arXiv articles (or fetch a specific arXiv ID), synthesize production Rust
    defense code and Cedar policies, and submit them to OshoosiClaw/KillSwitch (with automatic
    local Paper2Code codebase synthesis & verification fallback when the HTTP daemon is offline).
    """
    try:
        q = query_or_arxiv_id.strip()
        clean_q = normalize_arxiv_id(q)
        is_id = len(clean_q) <= 15 and "." in clean_q and " " not in clean_q and clean_q.replace(".", "").isdigit()

        if is_id:
            paper = fetch_paper_by_id(clean_q)
            if not paper:
                return json.dumps({"error": f"Paper not found for ID: {clean_q}"}, indent=2)
            exts, _ = extract_grounded_breakouts(paper)
            r_info = compute_article_rank(paper, exts)
            paper["code_repo_url"] = r_info.get("code_repo_url", paper.get("code_repo_url", ""))
            code_bundle = synthesize_production_rust_and_cedar(paper, exts)
            selected = [{
                "rank_position": 1,
                "arxiv_id": paper["arxiv_id"],
                "title": paper["title"],
                "code_repo_url": r_info.get("code_repo_url", ""),
                "rank_score": r_info["total_score"],
                "priority_tier": r_info["priority_tier"],
                "is_novel_to_codebase": r_info["is_novel_to_codebase"],
                "enhances_codebase": r_info["enhances_codebase"],
                "extractions": exts,
                "generated_production_code": code_bundle,
            }]
        else:
            ranked = search_and_rank_articles(query=q, max_results=max(top_k * 2, 5), only_novel_enhancements=True)
            selected = ranked[:max(1, int(top_k))]
            for item in selected:
                item["generated_production_code"] = synthesize_production_rust_and_cedar(
                    item, item.get("extractions", [])
                )

        all_extractions = []
        for item in selected:
            all_extractions.extend(item["extractions"])

        ingest_resp = ingest_into_killswitch(all_extractions, server_url=server_url)

        return json.dumps({
            "selected_top_articles": [
                {
                    "rank_position": a["rank_position"],
                    "arxiv_id": a["arxiv_id"],
                    "title": a["title"],
                    "code_repo_url": a.get("code_repo_url", ""),
                    "rank_score": a["rank_score"],
                    "priority_tier": a["priority_tier"],
                    "is_novel_to_codebase": a.get("is_novel_to_codebase", True),
                    "vectors_extracted": len(a["extractions"]),
                    "generated_production_code": a["generated_production_code"],
                }
                for a in selected
            ],
            "total_vectors_submitted": len(all_extractions),
            "killswitch_ingestion_result": ingest_resp,
            "printable_code_bundle_markdown": (
                selected[0]["generated_production_code"]["printable_code_bundle_markdown"]
                if selected else ""
            ),
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


# =============================================================================
# Tool 5: rank_arxiv_security_papers
# =============================================================================

@server.tool()
async def rank_arxiv_security_papers(
    query: str = "LLM agent sandbox escape breakout",
    top_k: int = 5,
    target_system: str = "all",
    only_novel_enhancements: bool = True,
) -> str:
    """
    Search arXiv, filter strictly to novel papers that enhance the codebase, run 3-class Google
    LangExtract source grounding, rank papers highest-to-lowest (0-100 score), synthesize
    production Rust and Cedar code for each paper, and return a formatted markdown table.
    """
    try:
        ranked_articles, filtered_out = search_and_rank_articles(
            query=query,
            max_results=max(1, min(int(top_k), 25)),
            min_score=0.0,
            only_novel_enhancements=bool(only_novel_enhancements),
            target_system=target_system,
            return_filtered=True,
        )

        lines = [
            "| Rank | arXiv ID | Score | Priority Tier | Title | Code Repo | Target Crates Enhanced |",
            "|:---:|:---:|:---:|:---:|:---|:---|:---|",
        ]
        for a in ranked_articles:
            a["generated_production_code"] = synthesize_production_rust_and_cedar(
                a, a.get("extractions", [])
            )
            crates_str = ", ".join(c.split()[0] for c in a.get("target_crates_enhanced", [])) or "General"
            title_trunc = a["title"][:50] + "..." if len(a["title"]) > 50 else a["title"]
            repo_str = a.get("code_repo_url") or "N/A"
            lines.append(
                f"| #{a['rank_position']} | [{a['arxiv_id']}]({a['url']}) | {a['rank_score']}/100 | "
                f"`{a['priority_tier']}` | {title_trunc} | {repo_str} | `{crates_str}` |"
            )

        markdown_table = "\n".join(lines)

        return json.dumps({
            "query": query,
            "total_ranked": len(ranked_articles),
            "target_system": target_system,
            "only_novel_enhancements": only_novel_enhancements,
            "ranked_markdown_table": markdown_table,
            "ranked_articles": ranked_articles,
            "filtered_out_already_implemented": filtered_out,
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc), "query": query}, indent=2)


# =============================================================================
# Tool 6: extract_grounded_breakout_vectors
# =============================================================================

@server.tool()
async def extract_grounded_breakout_vectors(
    arxiv_id: str,
    output_html_path: str = "",
) -> str:
    """
    Extracts 3-class source-grounded objects (BreakoutVector, MathematicalFormulation, and
    DefenseCountermeasure) with exact character intervals from an arXiv paper, synthesizes
    production Rust defense code and Cedar policies, and generates an interactive HTML report.
    """
    try:
        clean_id = normalize_arxiv_id(arxiv_id)
        paper = fetch_paper_by_id(clean_id)
        if not paper:
            return json.dumps({"error": f"Paper not found for arXiv ID: {clean_id}"}, indent=2)

        extractions, annotated_doc = extract_grounded_breakouts(paper)
        rank_info = compute_article_rank(paper, extractions)
        paper["code_repo_url"] = rank_info.get("code_repo_url", paper.get("code_repo_url", ""))
        code_bundle = synthesize_production_rust_and_cedar(paper, extractions)

        if not output_html_path.strip():
            target_dir = Path("D:/harfile/OshoosiClaw/target")
            target_dir.mkdir(parents=True, exist_ok=True)
            output_html_path = str(target_dir / f"langextract_audit_{clean_id}.html")

        out_path = generate_interactive_html(annotated_doc, output_html_path)

        breakout_vectors = [e for e in extractions if e["extraction_class"] == "breakout_vector"]
        math_formulations = [e for e in extractions if e["extraction_class"] == "mathematical_formulation"]
        defense_countermeasures = [e for e in extractions if e["extraction_class"] == "defense_countermeasure"]

        return json.dumps({
            "arxiv_id": clean_id,
            "title": paper["title"],
            "published": paper["published"],
            "url": paper["url"],
            "code_repo_url": rank_info["code_repo_url"],
            "rank_score": rank_info["total_score"],
            "priority_tier": rank_info["priority_tier"],
            "is_novel_to_codebase": rank_info["is_novel_to_codebase"],
            "enhances_codebase": rank_info["enhances_codebase"],
            "html_report_path": out_path,
            "total_grounded_spans": len(extractions),
            "breakout_vectors_count": len(breakout_vectors),
            "math_formulations_count": len(math_formulations),
            "defense_countermeasures_count": len(defense_countermeasures),
            "breakout_vectors": breakout_vectors,
            "mathematical_formulations": math_formulations,
            "defense_countermeasures": defense_countermeasures,
            "generated_production_code": code_bundle,
            "printable_code_bundle_markdown": code_bundle["printable_code_bundle_markdown"],
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc), "arxiv_id": arxiv_id}, indent=2)


# =============================================================================
# Tool 7: audit_defense_coverage
# =============================================================================

@server.tool()
async def audit_defense_coverage(
    arxiv_id: str = "2603.02277",
    targets: Optional[List[str]] = None,
) -> str:
    """
    Submits grounded extractions from an arXiv paper to active daemons (OshoosiClaw on :3030,
    KillSwitch on :3031) or performs deterministic local verification against the 7-Ring Continuous
    Reference Monitor, returning a live-probe verification, codebase enhancement gap analysis,
    and printable production Rust & Cedar code bundle.
    """
    try:
        clean_id = normalize_arxiv_id(arxiv_id)
        if targets is None:
            targets = ["oshoosiclaw", "killswitch", "octopus"]

        audit_res = audit_defense_coverage_multi_target(clean_id, targets=targets)
        paper = fetch_paper_by_id(clean_id)
        if paper:
            exts, _ = extract_grounded_breakouts(paper)
            r_info = compute_article_rank(paper, exts)
            paper["code_repo_url"] = r_info.get("code_repo_url", paper.get("code_repo_url", ""))
            code_bundle = synthesize_production_rust_and_cedar(paper, exts)
            audit_res["generated_production_code"] = code_bundle
            audit_res["printable_code_bundle_markdown"] = code_bundle["printable_code_bundle_markdown"]
        return json.dumps(audit_res, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc), "arxiv_id": arxiv_id}, indent=2)


if __name__ == "__main__":
    sys.stderr.write("Starting arXiv + Google LangExtract + Paper2Code MCP Server on stdio (7 Tools Registered)...\n")
    sys.stderr.flush()
    server.run(transport="stdio")
