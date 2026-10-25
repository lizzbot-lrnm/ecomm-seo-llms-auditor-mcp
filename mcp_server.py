"""
Model Context Protocol (MCP) Server for `ecomm-seo-llms-auditor-mcp`.
Supports FastMCP / MCPServer over stdio and streamable-http transports with 0 LLM tokens.
"""

from __future__ import annotations

import argparse
from typing import Any, Dict

try:
    from mcp.server.mcpserver import MCPServer as _MCPServerClass
except ImportError:
    from mcp.server.fastmcp import FastMCP as _MCPServerClass  # type: ignore

from seo_llms_engine import (
    analyze_shopify_products_json,
    audit_ai_robots_txt,
    audit_store_url,
    validate_jsonld_html,
    validate_or_generate_llms_txt,
)

mcp = _MCPServerClass("ecomm-seo-llms-auditor-mcp")


@mcp.tool()
def audit_store_seo_and_llms_txt(
    url: str = "https://www.allbirds.com",
    max_links: int = 25,
    generate_remediation_pack: bool = True,
) -> Dict[str, Any]:
    """
    Complete 0-token deterministic E-Commerce & Shopify Technical SEO, Schema.org Product/Offer
    JSON-LD, AI Crawler (`robots.txt`), Broken-Link, and `/llms.txt` readiness audit.
    """
    return audit_store_url(
        url=url,
        max_links=max_links,
        generate_remediation_pack=generate_remediation_pack,
    )


@mcp.tool()
def validate_ecommerce_product_jsonld(html_text: str, page_url: str = "https://example.com") -> Dict[str, Any]:
    """
    Validate `<script type="application/ld+json">` blocks in HTML against Google Merchant Center
    Product & Offer requirements and generate a corrected JSON-LD snippet.
    """
    return validate_jsonld_html(html_text=html_text, page_url=page_url)


@mcp.tool()
def audit_ai_crawler_robots_txt(robots_txt: str, base_url: str = "https://example.com") -> Dict[str, Any]:
    """
    Parse `robots.txt` for GPTBot, OAI-SearchBot, ChatGPT-User, ClaudeBot, PerplexityBot,
    Google-Extended, CCBot, Amazonbot, and Googlebot permissions and compute an AI discoverability score.
    """
    return audit_ai_robots_txt(robots_txt=robots_txt, base_url=base_url)


@mcp.tool()
def inspect_shopify_products_feed(products_json: str, store_url: str = "https://example.com") -> Dict[str, Any]:
    """
    Inspect a Shopify `/products.json` payload for SKU/variant coverage, missing image alt text,
    and synthesize canonical Schema.org/Product JSON-LD.
    """
    return analyze_shopify_products_json(payload=products_json, store_url=store_url)


@mcp.tool()
def synthesize_store_llms_txt(
    store_url: str = "https://example.com",
    brand_title: str = "Example Store",
    meta_description: str = "Official product catalog and structured shopping feed.",
) -> Dict[str, Any]:
    """
    Deterministically generate a standards-compliant `/llms.txt` markdown file for an e-commerce store.
    """
    return validate_or_generate_llms_txt(
        existing_llms_txt=None,
        status_code=404,
        store_url=store_url,
        brand_title=brand_title,
        meta_description=meta_description,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run E-Commerce SEO & llms.txt Auditor MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="MCP transport protocol (default: stdio)",
    )
    args = parser.parse_args()
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
