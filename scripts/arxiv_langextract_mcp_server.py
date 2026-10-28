#!/usr/bin/env python3
"""
arXiv Research Discovery, Multi-Factor Article Ranking & Google LangExtract MCP Server
======================================================================================
Integrates arXiv research discovery, 4-factor breakout threat ranking, Google LangExtract
source-grounding, and KillSwitch containment verification directly into Google Antigravity IDE.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

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
    RIGOR_KEYWORDS,
    compute_article_rank,
    extract_grounded_breakouts,
    fetch_paper_by_id,
    generate_interactive_html,
    ingest_into_killswitch,
    search_and_rank_articles,
)

server = MCPServer("arxiv-langextract")

# Re-enforce stderr WARNING logging after MCPServer initialization
logging.basicConfig(stream=sys.stderr, level=logging.WARNING, force=True)
for _logger_name in ("arxiv", "httpx", "httpcore", "urllib3", "langextract", "mcp"):
    logging.getLogger(_logger_name).setLevel(logging.WARNING)


@server.tool()
async def langextract_status() -> str:
    """
    Check the health and configuration status of the arXiv + Google LangExtract MCP server.
    Returns installed versions, ranking factor weights, and active breakout signature classes.
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
            "total_max_score": 100.0,
        },
        "priority_tiers": {
            "TIER-1 CRITICAL": ">= 80.0",
            "TIER-2 HIGH": "60.0 - 79.9",
            "TIER-3 MODERATE": "40.0 - 59.9",
            "TIER-4 LOW": "< 40.0",
        },
        "supported_breakout_classes": [sig["vector"] for sig in BREAKOUT_SIGNATURES],
    }, indent=2)


@server.tool()
async def search_and_rank_breakout_articles(
    query: str = "LLM agent sandbox escape breakout",
    max_results: int = 5,
    min_score: float = 0.0,
) -> str:
    """
    Search arXiv for research articles, extract source-grounded breakout vectors using Google
    LangExtract, and rank the articles from highest to lowest (0-100 score) based on grounded
    vector density, threat severity tier, empirical rigor, and recency.

    Args:
        query: Search query for arXiv (e.g., 'LLM container sandbox escape', 'agent prompt injection').
        max_results: Maximum number of candidate papers to retrieve and rank (default: 5).
        min_score: Optional minimum rank score threshold (0.0 to 100.0) to filter results.
    """
    try:
        ranked = search_and_rank_articles(
            query=query,
            max_results=max(1, min(int(max_results), 25)),
            min_score=float(min_score),
        )
        return json.dumps({
            "query": query,
            "total_ranked": len(ranked),
            "ranked_articles": ranked,
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc), "query": query}, indent=2)


@server.tool()
async def extract_and_ground_article(
    arxiv_id: str,
    output_html_path: str = "",
) -> str:
    """
    Fetch a specific arXiv paper by ID (e.g. '2603.02277'), run Google LangExtract character-interval
    source grounding, compute its 4-factor threat rank score, and optionally generate a self-contained
    interactive HTML visualization report.

    Args:
        arxiv_id: The arXiv identifier (e.g., '2603.02277' or '2509.06917').
        output_html_path: Optional file path to save the interactive LangExtract HTML visualization.
    """
    try:
        clean_id = arxiv_id.strip().replace("arXiv:", "").replace("arxiv:", "")
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
            "score_breakdown": rank_info["breakdown"],
            "grounded_extractions": extractions,
            "interactive_html_report": saved_html,
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc), "arxiv_id": arxiv_id}, indent=2)


@server.tool()
async def ingest_ranked_articles_to_killswitch(
    query_or_arxiv_id: str = "2603.02277",
    top_k: int = 3,
    server_url: str = "http://127.0.0.1:3030",
) -> str:
    """
    Search and rank arXiv articles (or fetch a specific arXiv ID), extract the grounded breakout
    vectors from the top-K highest-ranked articles, and submit them to KillSwitch's
    /api/research/ingest endpoint to verify containment coverage.

    Args:
        query_or_arxiv_id: Either an arXiv ID (e.g. '2603.02277') or a search query.
        top_k: Number of top-ranked papers to ingest into KillSwitch (default: 3).
        server_url: KillSwitch control server URL (default: 'http://127.0.0.1:3030').
    """
    try:
        q = query_or_arxiv_id.strip()
        # Check if input looks like an arXiv ID (e.g. 2603.02277)
        is_id = len(q) <= 15 and "." in q and " " not in q and q.split(".")[0].isdigit()

        if is_id:
            paper = fetch_paper_by_id(q)
            if not paper:
                return json.dumps({"error": f"Paper not found for ID: {q}"}, indent=2)
            exts, _ = extract_grounded_breakouts(paper)
            r_info = compute_article_rank(paper, exts)
            selected = [{
                "rank_position": 1,
                "arxiv_id": paper["arxiv_id"],
                "title": paper["title"],
                "rank_score": r_info["total_score"],
                "priority_tier": r_info["priority_tier"],
                "extractions": exts,
            }]
        else:
            ranked = search_and_rank_articles(query=q, max_results=max(top_k * 2, 5))
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
                    "vectors_extracted": len(a["extractions"]),
                }
                for a in selected
            ],
            "total_vectors_submitted": len(all_extractions),
            "killswitch_ingestion_result": ingest_resp,
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)


if __name__ == "__main__":
    sys.stderr.write("Starting arXiv + Google LangExtract MCP Server on stdio...\n")
    sys.stderr.flush()
    server.run(transport="stdio")
