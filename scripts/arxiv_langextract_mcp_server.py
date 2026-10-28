#!/usr/bin/env python3
"""
arxiv_langextract_mcp_server.py
======================================================================================
arXiv Research Discovery, Multi-Factor Article Ranking & Google LangExtract MCP Server
with Strict Novelty Gating & Codebase Enhancement Verification for Antigravity IDE,
OshoosiClaw, KillSwitch, and AgentOctopus.
"""

from __future__ import annotations

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
import langextract as lx
import arxiv

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
    Check the health and configuration status of the arXiv + Google LangExtract MCP server.
    Returns installed versions, ranking factor weights, active breakout signature classes,
    codebase-implemented paper blacklist, and supported target systems.
    """
    return json.dumps({
        "server": "arxiv-langextract",
        "status": "operational",
        "python_version": sys.version.split()[0],
        "langextract_version": getattr(lx, "__version__", "1.7.1"),
        "arxiv_version": getattr(arxiv, "__version__", "4.0.2"),
        "ranking_factors": {
            "grounded_vector_density_max": 35.0,
            "threat_severity_tier_max": 30.0,
            "empirical_rigor_max": 20.0,
            "temporal_recency_max": 15.0,
            "novelty_delta_max": 15.0,
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
    LangExtract, and rank the articles from highest to lowest (0-100 score) based on grounded
    vector density, threat severity tier, empirical rigor, recency, and codebase novelty.

    Args:
        query: Search query for arXiv (e.g., 'LLM container sandbox escape', 'agent prompt injection').
        max_results: Maximum number of candidate papers to retrieve and rank (default: 5).
        min_score: Optional minimum rank score threshold (0.0 to 100.0) to filter results.
        only_novel_enhancements: Filter out papers already implemented in the codebase (default: True).
    """
    try:
        ranked = search_and_rank_articles(
            query=query,
            max_results=max(1, min(int(max_results), 25)),
            min_score=float(min_score),
            only_novel_enhancements=bool(only_novel_enhancements),
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
    Fetch a specific arXiv paper by ID (e.g. '2603.02277'), run Google LangExtract 3-class character-interval
    source grounding, compute its threat rank score, and optionally generate an interactive HTML visualization.

    Args:
        arxiv_id: The arXiv identifier (e.g., '2603.02277' or '2509.06917').
        output_html_path: Optional file path to save the interactive LangExtract HTML visualization.
    """
    try:
        clean_id = normalize_arxiv_id(arxiv_id)
        paper = fetch_paper_by_id(clean_id)
        if not paper:
            return json.dumps({"error": f"Paper not found for arXiv ID: {clean_id}"}, indent=2)

        extractions, annotated_doc = extract_grounded_breakouts(paper)
        rank_info = compute_article_rank(paper, extractions)

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
            "rank_score": rank_info["total_score"],
            "priority_tier": rank_info["priority_tier"],
            "is_novel_to_codebase": rank_info["is_novel_to_codebase"],
            "enhances_codebase": rank_info["enhances_codebase"],
            "novelty_delta_score": rank_info["novelty_delta_score"],
            "target_crates_enhanced": rank_info["target_crates_enhanced"],
            "score_breakdown": rank_info["breakdown"],
            "grounded_extractions": extractions,
            "interactive_html_report": saved_html,
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
    Search and rank arXiv articles (or fetch a specific arXiv ID), extract the grounded breakout
    vectors from the top-K highest-ranked articles, and submit them to KillSwitch/OshoosiClaw's
    /api/research/ingest endpoint to verify containment coverage.

    Args:
        query_or_arxiv_id: Either an arXiv ID (e.g. '2603.02277') or a search query.
        top_k: Number of top-ranked papers to ingest (default: 3).
        server_url: Control server URL (default: 'http://127.0.0.1:3030').
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
            selected = [{
                "rank_position": 1,
                "arxiv_id": paper["arxiv_id"],
                "title": paper["title"],
                "rank_score": r_info["total_score"],
                "priority_tier": r_info["priority_tier"],
                "is_novel_to_codebase": r_info["is_novel_to_codebase"],
                "enhances_codebase": r_info["enhances_codebase"],
                "extractions": exts,
            }]
        else:
            ranked = search_and_rank_articles(query=q, max_results=max(top_k * 2, 5), only_novel_enhancements=True)
            selected = ranked[:max(1, int(top_k))]

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
                    "rank_score": a["rank_score"],
                    "priority_tier": a["priority_tier"],
                    "is_novel_to_codebase": a.get("is_novel_to_codebase", True),
                    "vectors_extracted": len(a["extractions"]),
                }
                for a in selected
            ],
            "total_vectors_submitted": len(all_extractions),
            "killswitch_ingestion_result": ingest_resp,
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


# =============================================================================
# Tool 5: rank_arxiv_security_papers (New Antigravity MCP Tool)
# =============================================================================

@server.tool()
async def rank_arxiv_security_papers(
    query: str = "LLM agent sandbox escape breakout",
    top_k: int = 5,
    target_system: str = "all",
    only_novel_enhancements: bool = True,
) -> str:
    """
    Search arXiv, filter strictly to novel papers that enhance the codebase (filtering out
    already implemented works like arXiv:2610.09167), run 3-class Google LangExtract source
    grounding, rank papers highest-to-lowest (0-100 score), and return a formatted markdown table.

    Args:
        query: Search query for arXiv (default: 'LLM agent sandbox escape breakout').
        top_k: Number of highest-ranked novel papers to return (default: 5).
        target_system: Filter enhancements by system ('all', 'oshoosiclaw', 'killswitch', 'octopus').
        only_novel_enhancements: Strict novelty filter rejecting already-implemented papers (default: True).
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

        # Build Markdown summary table
        lines = [
            "| Rank | arXiv ID | Score | Priority Tier | Title | Target Crates Enhanced | Grounded Vectors |",
            "|:---:|:---:|:---:|:---:|:---|:---|:---:|",
        ]
        for a in ranked_articles:
            crates_str = ", ".join(c.split()[0] for c in a.get("target_crates_enhanced", [])) or "General"
            title_trunc = a["title"][:55] + "..." if len(a["title"]) > 55 else a["title"]
            lines.append(
                f"| #{a['rank_position']} | [{a['arxiv_id']}]({a['url']}) | {a['rank_score']}/100 | "
                f"`{a['priority_tier']}` | {title_trunc} | `{crates_str}` | {a['grounded_vector_count']} |"
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
# Tool 6: extract_grounded_breakout_vectors (New Antigravity MCP Tool)
# =============================================================================

@server.tool()
async def extract_grounded_breakout_vectors(
    arxiv_id: str,
    output_html_path: str = "",
) -> str:
    """
    Extracts 3-class source-grounded objects (BreakoutVector, MathematicalFormulation, and
    DefenseCountermeasure) with exact character intervals from an arXiv paper, and generates
    an interactive Google LangExtract HTML audit report.

    Args:
        arxiv_id: The arXiv identifier (e.g., '2603.02277').
        output_html_path: File path for interactive HTML visualization. If omitted, defaults to
                          'D:/harfile/OshoosiClaw/target/langextract_audit_<arxiv_id>.html'.
    """
    try:
        clean_id = normalize_arxiv_id(arxiv_id)
        paper = fetch_paper_by_id(clean_id)
        if not paper:
            return json.dumps({"error": f"Paper not found for arXiv ID: {clean_id}"}, indent=2)

        extractions, annotated_doc = extract_grounded_breakouts(paper)
        rank_info = compute_article_rank(paper, extractions)

        # Determine output HTML path
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
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc), "arxiv_id": arxiv_id}, indent=2)


# =============================================================================
# Tool 7: audit_defense_coverage (New Antigravity MCP Tool)
# =============================================================================

@server.tool()
async def audit_defense_coverage(
    arxiv_id: str = "2603.02277",
    targets: Optional[List[str]] = None,
) -> str:
    """
    Submits grounded extractions from an arXiv paper to active daemons (OshoosiClaw on :3030,
    KillSwitch on :3031) or performs deterministic local verification against the 7-Ring Continuous
    Reference Monitor, returning a live-probe verification and codebase enhancement gap analysis.

    Args:
        arxiv_id: arXiv identifier to evaluate (default: '2603.02277').
        targets: Target systems to audit (default: ['oshoosiclaw', 'killswitch', 'octopus']).
    """
    try:
        clean_id = normalize_arxiv_id(arxiv_id)
        if targets is None:
            targets = ["oshoosiclaw", "killswitch", "octopus"]

        audit_res = audit_defense_coverage_multi_target(clean_id, targets=targets)
        return json.dumps(audit_res, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc), "arxiv_id": arxiv_id}, indent=2)


if __name__ == "__main__":
    sys.stderr.write("Starting arXiv + Google LangExtract MCP Server on stdio (7 Tools Registered)...\n")
    sys.stderr.flush()
    server.run(transport="stdio")
