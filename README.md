# E-Commerce & Shopify JSON-LD Schema, Broken-Link & `llms.txt` Readiness Auditor MCP (`ecomm-seo-llms-auditor-mcp`)

Deterministic, **0-LLM-token** (`$0.00` compute burn) technical SEO, structured data, AI search discoverability, and `/llms.txt` readiness auditor for global Shopify, WooCommerce, Magento, Next.js, and DTC e-commerce stores.

## Live Public Web Grader & MCP Endpoint
- **Interactive Free Store Grader:** `https://parish.technoplusit.co.uk/seo-audit`
- **REST JSON API:** `https://parish.technoplusit.co.uk/api/seo-audit?domain=allbirds.com`
- **Streamable HTTP MCP Endpoint:** `https://parish.technoplusit.co.uk/mcp`

## Core Deterministic Capabilities
1. **Google Merchant Center `Schema.org/Product` & `Offer` JSON-LD Validator**:
   - Extracts all `<script type="application/ld+json">` blocks.
   - Detects malformed JSON syntax (trailing commas, unescaped control characters) and reports `JSON_LD_PARSE_ERROR` with exact `line` and `column` offsets without crashing.
   - Validates required Google Merchant Center fields (`name`, `image`, `description`, `sku`/`gtin`/`mpn`, `brand`, `offers.price`, `offers.priceCurrency`, `offers.availability`) and emits a ready-to-paste corrected JSON-LD snippet.
2. **AI Crawler `robots.txt` Permission Matrix (`ai_discoverability_score`)**:
   - Parses `User-agent:` rules for `GPTBot`, `OAI-SearchBot`, `ChatGPT-User`, `ClaudeBot`, `PerplexityBot`, `Google-Extended`, `CCBot`, `Amazonbot`, and `Googlebot` + `Sitemap:` directives.
3. **Shopify Native `/products.json?limit=5` Feed Probe**:
   - Deterministically detects `platform="shopify"`, checks variant/SKU/price completeness, counts missing product image `alt` attributes, and synthesizes canonical `Schema.org/Product` JSON-LD directly from `/products.json`.
4. **`/llms.txt` Validator & Auto-Generator**:
   - Validates `/llms.txt`, `/.well-known/agent.json`, and `/.well-known/mcp.json`, or synthesizes a standards-compliant `/llms.txt` markdown file from store metadata, navigation/sitemap links, and top products.
5. **Concurrent Broken-Link & Redirect-Chain Scanner (SSRF-Hardened)**:
   - Classifies `200 OK`, `301 -> 302 -> 200` redirect chains (flagging `>2` hops), and `404`/`410`/`5xx` dead links while enforcing strict RFC1918/loopback/link-local SSRF blocking and Worf 0-token static quarantine on all fetched responses.

## Apify Pay-Per-Event (`PAY_PER_EVENT`) Pricing
| Event Name | Unit Price (USD) | Price per 1,000 Events | Description |
| :--- | :---: | :---: | :--- |
| `actor-start` | `$0.005` | `$5.00 / 1,000` | Container initialization & schema validation |
| `url-audited` | `$0.003` | `$3.00 / 1,000` | Complete 0-100 JSON-LD, AI crawler, Shopify & link audit per URL |
| `remediation-pack-generated` | `$0.010` | `$10.00 / 1,000` | Auto-generated `/llms.txt` + corrected `Product` JSON-LD + CSV link fix table |
