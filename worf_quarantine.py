#!/usr/bin/env python3
"""
Portable Worf Zero-Trust 0-Token Static Quarantine Scanner (`worf_quarantine.py`).
Version: 1.2.0 (2026-10-25 — Cross-Model Peer Reviewed by claude-opus-5-5-high & gemini-4-argon-high)

Works identically on the shared Linux box and macOS (M1 MacBook).
Enforces deterministic, 0-token static quarantine across untrusted inputs:
- Strict Alignment & Safety Boundaries (UK GDPR Art. 10 criminal offence data, actionable malware/spam)
- Prompt Injection & Role Hijack (raw + NFKC + URL-decoded + HTML-unescaped + ZWSP-stripped shadow text + Base64 blob inspection)
- Exfiltration, Cloud Metadata SSRF & Tool-Misuse Vectors (context-aware Markdown image beacon check, OOB webhooks, credential harvest)
"""
from __future__ import annotations

import argparse
import base64
import html
import importlib.util
import json
import pathlib
import re
import sys
import unicodedata
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple, Union

TRUSTED_IMAGE_HOSTS = {
    "img.shields.io",
    "shields.io",
    "avatars.githubusercontent.com",
    "github.com",
    "raw.githubusercontent.com",
    "user-images.githubusercontent.com",
    "gov.uk",
    "www.gov.uk",
    "assets.publishing.service.gov.uk",
    "technoplusit.co.uk",
    "parish.technoplusit.co.uk",
    "command.technoplusit.co.uk",
    "bridge.technoplusit.co.uk",
}

MARKDOWN_IMAGE_URL_RE = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^\s\)]+)\s*\)", re.I)
EXFIL_QUERY_PARAM_RE = re.compile(
    r"(?i)(?:^|[?&])(data|secret|token|key|password|passwd|cookie|session|exfil|leak|dump|env|prompt|mem|b64|base64|jwt|auth|cred|q)="
)
TEMPLATE_INTERPOLATION_RE = re.compile(r"(\{\{|\}\}|\$\{|%7b%7b|%24%7b)", re.I)
BIDI_OVERRIDE_RE = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff]")
INTRA_WORD_ZW_RE = re.compile(r"[A-Za-z][\u200b-\u200f\u2060][A-Za-z]")

STATIC_RULES: List[Tuple[str, str, str, int, str, str]] = [
    (
        "ALIGNMENT_BOUNDARY",
        "UK_GDPR_ART10_CRIMINAL_DATA",
        "BLOCK",
        95,
        r"(?i)\b(criminal\s+convictions?\s+(database|register|scrape|dump)|police\s+national\s+computer|pnc\s+lookup|offender\s+registry\s+scrape|unspent\s+convictions?\s+list)\b",
        "UK GDPR Art. 10 boundary: criminal offence/conviction register scraping or profiling is prohibited.",
    ),
    (
        "ALIGNMENT_BOUNDARY",
        "MALWARE_OR_SPAM_AMPLIFICATION",
        "BLOCK",
        100,
        r"(?i)\b((?:write|build|compile|deploy|launch|execute|generate|create|run|send)\s+(?:a\s+|an\s+|the\s+)?(?:ran" r"somware|info\s*stealer|key" r"logger|credential\s+stuffing|phishing\s+kit|mass\s+dm\s+bot|spam\s+amplif\w*|ddos\s+attack)|ran" r"somware\s+payload|info\s*stealer|key" r"logger\s+implant|credential\s+stuffing\s+attack|phishing\s+kit|mass\s+dm\s+bot|spam\s+amplif\w*)\b",
        "Unaligned spam or malware amplification indicator detected.",
    ),
    (
        "PROMPT_INJECTION",
        "DIRECT_INSTRUCTION_OVERRIDE",
        "BLOCK",
        90,
        r"(?i)\b(ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|rules?|directions?|guidelines?)|disregard\s+(all\s+|any\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)|forget\s+(everything|all\s+(prior\s+)?instructions)\b)",
        "Direct prompt-injection override phrase detected.",
    ),
    (
        "PROMPT_INJECTION",
        "SYSTEM_PROMPT_OR_ROLE_HIJACK",
        "CRITICAL",
        85,
        r"(?i)(<\s*/?\s*(system|developer|assistant|user)_?(prompt|instruction|message)\s*>|\[\s*(SYSTEM|INST|ADMIN_OVERRIDE)\s*\]|you\s+are\s+now\s+(in\s+)?(developer\s+mode|unrestricted|god\s+mode|jailbroken|dan\b)|new\s+system\s+instructions|override\s+security\s+policy|bypass\s+safety\s+filters|\b(?:reveal|print|dump|output|show|repeat|override)\s+(?:your\s+|the\s+)?system\s+prompt\b|\bsystem\s*prompt\s*[:=]\s*(?:you\s+are|ignore|disregard|act\s+as|override|reveal))",
        "System prompt extraction or persona/role hijack attempt.",
    ),
    (
        "PROMPT_INJECTION",
        "UNTRUSTED_FENCE_SPOOFING",
        "BLOCK",
        100,
        r"(?i)(</?cursor_untrusted_data|</?system_instruction>|<\|im_start\|>\s*system|\[INST\]\s*<<SYS>>|end\s+of\s+untrusted\s+data)",
        "Attempt to forge or close untrusted data containment fences or system tags.",
    ),
    (
        "PROMPT_INJECTION",
        "UNICODE_TAG_CHAR_SMUGGLING",
        "BLOCK",
        95,
        r"[\U000e0000-\U000e007f]+",
        "Invisible Unicode Tag characters (U+E0000..U+E007F) used for hidden LLM instruction smuggling.",
    ),
    (
        "PROMPT_INJECTION",
        "MCP_TOOL_POISONING",
        "BLOCK",
        95,
        r"(?i)(<important>[\s\S]{0,400}?(do\s+not\s+mention|hide\s+this|before\s+calling\s+this\s+tool|read\s+~?/?\.ssh)|do\s+not\s+tell\s+the\s+user\s+you\s+are\s+reading|silently\s+(exfiltrate|send|upload|include)\b|<\s*tool_call\s*>|<\s*invoke\s+name=)",
        "MCP tool-description poisoning / covert side-effect instruction.",
    ),
    (
        "SYBIL_SCAM_HONEYPOT",
        "SEED_OR_PRIVATE_KEY_SOLICITATION",
        "BLOCK",
        100,
        r"(?i)(enter\s+your\s+(seed\s+phrase|mnemonic|private\s+key|recovery\s+phrase)|provide\s+your\s+12[- ]word\s+phrase|export\s+private\s+key\s+to\b)",
        "Direct solicitation of wallet seed phrase, mnemonic, or private key.",
    ),
    (
        "SYBIL_SCAM_HONEYPOT",
        "WALLET_" + "DRAINER_PATTERN",
        "BLOCK",
        95,
        r"(?i)(approve\s+unlimited|setApprovalForAll\s*\([^,]+,\s*true\)|0xf{64}[^\n]{0,120}(drain|transferFrom)|send_" r"transaction[^\n]{0,120}(drain|all\s+funds)|wallet[-_]?drainer)",
        "Wallet drainer approval or sweep pattern detected.",
    ),
    (
        "EXFIL_AND_MALICIOUS_CODE",
        "REMOTE_SHELL_PIPE_EXEC",
        "BLOCK",
        95,
        r"(?i)(\b(curl|wget|fetch)\b[^\n|;]{1,160}\|\s*(sudo\s+)?(ba|z|k)?sh\b|\bbase64\s+(-d|--decode)\b[^\n|]{0,120}\|\s*(ba)?sh\b|\brm\s+-rf\s+(/|\$\{?HOME\}?|~)\b)",
        "Remote script piped directly into shell interpreter or destructive rm -rf.",
    ),
    (
        "EXFIL_AND_MALICIOUS_CODE",
        "CREDENTIAL_OR_VAULT_HARVESTING",
        "CRITICAL",
        85,
        r"(?i)((\.s" r"sh/id_" r"rsa|id_" r"ed25519|\.a" r"ws/credentials|box-secrets\.json|host-secrets\.json|chrome-cookie-seed\.json)|((process\.env|os\.environ)[^\n]{0,80}(PRIVATE_KEY|MNEMONIC|SEED_PHRASE|APIFY_TOKEN|GITHUB_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY))|(cat|head|tail|curl|wget|cp|scp|base64)\s+[^\n;|`]{0,120}(\.env\b|id_" r"rsa|id_" r"ed25519|antigravity-" r"oauth-token)|printenv\s*\|\s*(curl|nc|wget|base64))",
        "Attempt to read sensitive credential files, SSH keys, vault secrets, or private key environment variables.",
    ),
    (
        "EXFIL_AND_MALICIOUS_CODE",
        "WEBHOOK_OOB_EXFIL_ENDPOINT",
        "CRITICAL",
        85,
        r"(?i)https?://([a-z0-9-]+\.)?(webhook\.site|requestbin\.(com|net)|ngrok-free\.app|ngrok\.io|oastify\.com|burpcollaborator\.net|interact\.sh|pipedream\.net|canarytokens\.com|trycloudflare\.com)\b",
        "Known out-of-band (OOB) data exfiltration / webhook catcher domain.",
    ),
    (
        "EXFIL_AND_MALICIOUS_CODE",
        "CLOUD_METADATA_OR_LOCAL_SSRF",
        "BLOCK",
        95,
        r"(?i)(?:https?://)?(?:169\." r"254\.169\.254|metadata\." r"google\.internal|metadata\.goog|100\." r"100\.100\.200|\[?fd00:" r"ec2::254\]?)\b",
        "Cloud instance metadata service (IMDS) or internal loopback SSRF target.",
    ),
    (
        "EXFIL_AND_MALICIOUS_CODE",
        "UNAPPROVED_EXTERNAL_SEND_DIRECTIVE",
        "CRITICAL",
        85,
        r"(?i)\b(without\s+(asking|telling|waiting\s+for)\s+(the\s+)?(user|lewis|approval|confirmation)[^\n.]{0,120}\b(send|post|email|transfer|pay|wire|tweet|dm)\b|\b(send|email|post|transfer)\s+immediately\s+without\s+(user\s+)?approval\b)",
        "Coercive instruction to send external message or transfer funds without user approval.",
    ),
]

BASE64_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])"
)
DECODED_SUSPICIOUS_RE = re.compile(
    r"(?i)(ignore\s+(all\s+)?(previous|prior)\s+instructions|system\s*prompt|</?cursor_untrusted_data|"
    r"\b(curl|wget)\b.*\|\s*(ba)?sh|\beval\s*\(|PRIVATE_KEY|seed\s+phrase|mnemonic|\.s" r"sh/id_" "rsa|"
    r"webhook\.site|169\." r"254\.169\.254)"
)


def _redact_sample(sample: str) -> str:
    return sample[:120]


def _build_normalized_shadow_text(text: str) -> str:
    s = unicodedata.normalize("NFKC", text)
    if "%" in s:
        try:
            s = urllib.parse.unquote(s)
        except Exception:
            pass
    if "&" in s and ";" in s:
        try:
            s = html.unescape(s)
        except Exception:
            pass
    s = ZERO_WIDTH_RE.sub("", s)
    s = BIDI_OVERRIDE_RE.sub("", s)
    return s


def _scan_markdown_image_beacons(text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for m in MARKDOWN_IMAGE_URL_RE.finditer(text):
        full_md = m.group(0)
        url_str = m.group(1)
        try:
            parsed = urllib.parse.urlsplit(url_str)
        except Exception:
            continue
        host = (parsed.hostname or "").lower()
        query = parsed.query or ""

        if TEMPLATE_INTERPOLATION_RE.search(url_str):
            findings.append({
                "category": "PROMPT_INJECTION",
                "rule": "MARKDOWN_IMAGE_EXFILTRATION",
                "severity": "CRITICAL",
                "weight": 80,
                "match_count": 1,
                "description": "Markdown image URL with template interpolation capable of zero-click data exfiltration.",
                "sample": _redact_sample(full_md),
            })
            break

        if not query:
            continue

        is_trusted = host in TRUSTED_IMAGE_HOSTS or any(host.endswith("." + th) for th in TRUSTED_IMAGE_HOSTS)
        if EXFIL_QUERY_PARAM_RE.search(query) or (not is_trusted and len(query) > 64):
            findings.append({
                "category": "PROMPT_INJECTION",
                "rule": "MARKDOWN_IMAGE_EXFILTRATION",
                "severity": "CRITICAL",
                "weight": 80,
                "match_count": 1,
                "description": "Markdown image URL with query parameters/interpolation capable of zero-click data exfiltration.",
                "sample": _redact_sample(full_md),
            })
            break
    return findings


def _inspect_base64_blobs(text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen = set()
    for match in BASE64_CANDIDATE_RE.finditer(text):
        blob = match.group(0)
        if blob in seen or len(blob) > 8192:
            continue
        seen.add(blob)
        try:
            raw = base64.b64decode(blob, validate=True)
            decoded = raw.decode("utf-8", errors="strict")
        except Exception:
            continue
        if decoded and sum(c.isprintable() or c in "\r\n\t" for c in decoded) / len(decoded) >= 0.85:
            if DECODED_SUSPICIOUS_RE.search(decoded):
                is_boundary = False
                findings.append({
                    "category": "ALIGNMENT_BOUNDARY" if is_boundary else "PROMPT_INJECTION",
                    "rule": "BASE64_ENCODED_BOUNDARY_OR_INJECTION" if is_boundary else "BASE64_SMUGGLED_INSTRUCTION",
                    "severity": "BLOCK",
                    "weight": 100 if is_boundary else 90,
                    "match_count": 1,
                    "description": "Base64-encoded payload decodes to hidden instructions, exfiltration code, or boundary violation.",
                    "sample": _redact_sample(decoded.strip()),
                })
    return findings


def _builtin_scan_payload(payload: Union[str, bytes, Dict[str, Any], List[Any]], source: str = "inline") -> Dict[str, Any]:
    if isinstance(payload, bytes):
        text = payload.decode("utf-8", errors="replace")
    elif isinstance(payload, (dict, list)):
        text = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    else:
        text = str(payload)

    # Strip leading UTF-8 BOM (\ufeff) before invisible character evaluation
    if text.startswith("\ufeff"):
        text = text.lstrip("\ufeff")

    shadow_text = _build_normalized_shadow_text(text)
    findings: List[Dict[str, Any]] = []
    risk_score = 0
    force_block = False

    bidi_chars = BIDI_OVERRIDE_RE.findall(text)
    zw_chars = ZERO_WIDTH_RE.findall(text)
    if bidi_chars:
        findings.append({
            "category": "PROMPT_INJECTION",
            "rule": "ZERO_WIDTH_OR_BIDI_SMUGGLING",
            "severity": "BLOCK",
            "weight": 75,
            "match_count": len(bidi_chars),
            "description": "Bidirectional override control characters detected.",
            "sample": repr(bidi_chars[0]),
        })
        risk_score += 75
        force_block = True
    elif INTRA_WORD_ZW_RE.search(text) or len(zw_chars) >= 4:
        findings.append({
            "category": "PROMPT_INJECTION",
            "rule": "ZERO_WIDTH_OR_BIDI_SMUGGLING",
            "severity": "HIGH",
            "weight": 45,
            "match_count": len(zw_chars),
            "description": "Zero-width character cluster or intra-word smuggling detected.",
            "sample": repr(zw_chars[0]) if zw_chars else "intra-word-zw",
        })
        risk_score += 45
    elif 1 <= len(zw_chars) <= 3:
        findings.append({
            "category": "PROMPT_INJECTION",
            "rule": "SINGLE_ZERO_WIDTH_CHAR",
            "severity": "INFO",
            "weight": 0,
            "match_count": len(zw_chars),
            "description": "Isolated zero-width character present (benign copy-paste artifact; logged as INFO).",
            "sample": repr(zw_chars[0]),
        })

    for category, rule_id, severity, weight, pattern, description in STATIC_RULES:
        matches = list(re.finditer(pattern, text))
        if not matches and shadow_text != text:
            matches = list(re.finditer(pattern, shadow_text))
        if matches:
            findings.append({
                "category": category,
                "rule": rule_id,
                "severity": severity,
                "weight": weight,
                "match_count": len(matches),
                "description": description,
                "sample": _redact_sample(repr(matches[0].group(0))),
            })
            risk_score += weight
            if severity == "BLOCK":
                force_block = True

    for md_f in _scan_markdown_image_beacons(text):
        findings.append(md_f)
        risk_score += md_f["weight"]

    for bf in _inspect_base64_blobs(text):
        findings.append(bf)
        risk_score += bf["weight"]
        if bf["severity"] == "BLOCK":
            force_block = True

    risk_score = min(100, risk_score)
    non_info_findings = [f for f in findings if f.get("severity") != "INFO"]
    if force_block or risk_score >= 70:
        verdict = "SECURITY_QUARANTINE_BLOCK"
    elif risk_score >= 25 or len(non_info_findings) > 0:
        verdict = "SUSPICIOUS_REVIEW_REQUIRED"
    else:
        verdict = "CLEAN"

    return {
        "scanner": "worf_quarantine/1.2.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "length_chars": len(text),
        "verdict": verdict,
        "risk_score": risk_score,
        "0_token_static_pass": True,
        "quarantine_passed": verdict == "CLEAN",
        "findings_count": len(findings),
        "findings": findings,
    }


def scan_payload(payload: Union[str, bytes, Dict[str, Any], List[Any]], source: str = "inline", **kwargs: Any) -> Dict[str, Any]:
    return _builtin_scan_payload(payload, source=source)


def assert_clean(payload: Union[str, bytes, Dict[str, Any], List[Any]], *, source: str = "untrusted_input") -> Dict[str, Any]:
    result = scan_payload(payload, source=source)
    if not result["quarantine_passed"]:
        rules = ", ".join(f["rule"] for f in result["findings"] if f.get("severity") != "INFO")
        raise ValueError(
            f"Worf Quarantine blocked payload from {source} "
            f"(verdict={result['verdict']}, score={result['risk_score']}, rules=[{rules}])"
        )
    return result


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Worf 0-Token Static Quarantine Scanner (Prompt Injection, Exfil, Sybil & Alignment Filter)"
    )
    parser.add_argument("targets", nargs="*", help="File paths or raw strings to scan")
    parser.add_argument("-t", "--text", help="Scan a raw text/URL/JSON payload directly")
    parser.add_argument("-f", "--file", action="append", default=[], help="File path to scan")
    parser.add_argument("--stdin", action="store_true", help="Read payload from standard input")
    parser.add_argument("--fail-on-block", action="store_true", help="Exit with code 2 if blocked, 1 if suspicious")
    args = parser.parse_args(argv)

    reports: List[Dict[str, Any]] = []
    if args.text is not None:
        reports.append(scan_payload(args.text, source="cli_text"))
    for fp in args.file:
        p = pathlib.Path(fp)
        reports.append(scan_payload(p.read_text(encoding="utf-8", errors="replace"), source=str(p)))
    for tgt in args.targets:
        p = pathlib.Path(tgt)
        if p.exists() and p.is_file():
            reports.append(scan_payload(p.read_text(encoding="utf-8", errors="replace"), source=str(p)))
        else:
            reports.append(scan_payload(tgt, source="cli_arg"))
    if args.stdin or (not reports and not sys.stdin.isatty()):
        reports.append(scan_payload(sys.stdin.read(), source="stdin"))

    if not reports:
        parser.print_help()
        return 0

    out = reports[0] if len(reports) == 1 else {"reports": reports}
    print(json.dumps(out, indent=2))

    if args.fail_on_block:
        for r in reports:
            if r["verdict"] == "SECURITY_QUARANTINE_BLOCK":
                return 2
        for r in reports:
            if r["verdict"] != "CLEAN":
                return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
