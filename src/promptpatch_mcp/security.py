from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from typing import Any


SEVERITY_SCORE = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SECURITY_MODES = {"block", "warn", "off"}
BLOCKING_SEVERITY = "high"
_CONTEXT_CHARS = 72


@dataclass(frozen=True)
class SecurityRule:
    id: str
    category: str
    severity: str
    message: str
    pattern: re.Pattern[str]
    redacts_match: bool = False
    defensive_downgrade: bool = False


_DEFENSIVE_CONTEXT_RE = re.compile(
    r"\b("
    r"never|do not|don't|dont|must not|should not|refuse|reject|block|prevent|detect|"
    r"flag|warn|guard against|protect against|mitigate|avoid"
    r")\b",
    re.IGNORECASE,
)


RULES: tuple[SecurityRule, ...] = (
    SecurityRule(
        id="secret.private_key",
        category="secret",
        severity="critical",
        message="Private key material appears to be embedded in the prompt.",
        pattern=re.compile(
            r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----",
            re.IGNORECASE,
        ),
        redacts_match=True,
    ),
    SecurityRule(
        id="secret.openai_key",
        category="secret",
        severity="critical",
        message="Possible OpenAI API key found.",
        pattern=re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        redacts_match=True,
    ),
    SecurityRule(
        id="secret.anthropic_key",
        category="secret",
        severity="critical",
        message="Possible Anthropic API key found.",
        pattern=re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        redacts_match=True,
    ),
    SecurityRule(
        id="secret.aws_access_key",
        category="secret",
        severity="critical",
        message="Possible AWS access key found.",
        pattern=re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
        redacts_match=True,
    ),
    SecurityRule(
        id="secret.google_api_key",
        category="secret",
        severity="critical",
        message="Possible Google API key found.",
        pattern=re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        redacts_match=True,
    ),
    SecurityRule(
        id="secret.github_token",
        category="secret",
        severity="critical",
        message="Possible GitHub token found.",
        pattern=re.compile(r"\bgh[oprsu]_[A-Za-z0-9_]{20,}\b"),
        redacts_match=True,
    ),
    SecurityRule(
        id="secret.slack_token",
        category="secret",
        severity="critical",
        message="Possible Slack token found.",
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
        redacts_match=True,
    ),
    SecurityRule(
        id="secret.generic_assignment",
        category="secret",
        severity="high",
        message="Possible hardcoded credential assignment found.",
        pattern=re.compile(
            r"\b(api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)\b"
            r"\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{16,}['\"]?",
            re.IGNORECASE,
        ),
        redacts_match=True,
    ),
    SecurityRule(
        id="injection.ignore_previous",
        category="prompt_injection",
        severity="high",
        message="Instruction attempts to override or ignore prior instructions.",
        pattern=re.compile(
            r"\b(ignore|disregard|forget|override)\b.{0,40}\b"
            r"(previous|prior|above|earlier|system|developer)\b.{0,30}\b"
            r"(instruction|instructions|rules|message|messages|prompt)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        defensive_downgrade=True,
    ),
    SecurityRule(
        id="injection.reveal_hidden_prompt",
        category="prompt_injection",
        severity="high",
        message="Instruction asks to reveal hidden/system/developer prompts.",
        pattern=re.compile(
            r"\b(reveal|print|show|dump|leak|expose)\b.{0,60}\b"
            r"(system|developer|hidden|internal)\b.{0,30}\b"
            r"(prompt|message|instruction|instructions|policy|policies)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        defensive_downgrade=True,
    ),
    SecurityRule(
        id="injection.tool_abuse",
        category="tool_abuse",
        severity="high",
        message="Instruction pressures the model to use tools without checks or approval.",
        pattern=re.compile(
            r"\b(call|invoke|use|run)\b.{0,40}\b(tool|function|mcp|command)\b"
            r".{0,80}\b(without|skip|bypass|no)\b.{0,30}\b"
            r"(confirmation|approval|permission|asking|checks?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        defensive_downgrade=True,
    ),
    SecurityRule(
        id="exfiltration.secrets",
        category="exfiltration",
        severity="critical",
        message="Instruction appears to exfiltrate secrets, tokens, or credentials.",
        pattern=re.compile(
            r"\b(send|upload|post|exfiltrate|leak|steal|copy)\b.{0,80}\b"
            r"(secret|secrets|token|tokens|credential|credentials|api key|password|env)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        defensive_downgrade=True,
    ),
    SecurityRule(
        id="exfiltration.system_prompt",
        category="exfiltration",
        severity="high",
        message="Instruction appears to extract system or developer instructions.",
        pattern=re.compile(
            r"\b(extract|copy|send|upload|post)\b.{0,80}\b"
            r"(system prompt|developer message|hidden instruction|internal policy)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        defensive_downgrade=True,
    ),
    SecurityRule(
        id="payload.encoded_followup",
        category="prompt_injection",
        severity="high",
        message="Instruction asks the model to decode and follow hidden instructions.",
        pattern=re.compile(
            r"\b(base64|hex|rot13|encoded|decode)\b.{0,80}\b"
            r"(follow|obey|execute|run|instructions?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        defensive_downgrade=True,
    ),
    SecurityRule(
        id="command.destructive",
        category="dangerous_action",
        severity="critical",
        message="Instruction includes a destructive shell command pattern.",
        pattern=re.compile(
            r"\b(rm\s+-rf\s+/|sudo\s+rm\s+-rf|mkfs\b|chmod\s+-R\s+777\s+/|"
            r"dd\s+if=.*\bof=/dev/)",
            re.IGNORECASE,
        ),
        defensive_downgrade=True,
    ),
    SecurityRule(
        id="coercion.stealth",
        category="prompt_injection",
        severity="medium",
        message="Instruction asks for stealthy behavior or hiding actions from the user.",
        pattern=re.compile(
            r"\b(secretly|silently|covertly|without the user knowing|do not tell the user)\b",
            re.IGNORECASE,
        ),
        defensive_downgrade=True,
    ),
)


def default_security_mode() -> str:
    raw_mode = os.environ.get("PROMPTPATCH_SECURITY_MODE")
    if raw_mode is None or raw_mode == "":
        return "block"
    return validate_security_mode(raw_mode)


def validate_security_mode(value: str | None) -> str:
    if value is None or value == "":
        return default_security_mode()
    if not isinstance(value, str):
        raise ValueError("security_mode must be one of: block, warn, off")
    mode = value.strip().lower()
    if mode not in SECURITY_MODES:
        raise ValueError("security_mode must be one of: block, warn, off")
    return mode


def scan_prompt_content(content: str, *, mode: str | None = None) -> dict[str, Any]:
    security_mode = validate_security_mode(mode)
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    if security_mode == "off":
        return {
            "enabled": False,
            "mode": security_mode,
            "blocked": False,
            "would_block": False,
            "content_sha256": content_hash,
            "max_severity": "info",
            "finding_count": 0,
            "findings": [],
            "advice": ["Security scanning was disabled for this operation."],
        }

    findings = _find_security_issues(content)
    max_severity = _max_severity(findings)
    would_block = _severity_at_least(max_severity, BLOCKING_SEVERITY)
    blocked = security_mode == "block" and would_block
    return {
        "enabled": True,
        "mode": security_mode,
        "blocked": blocked,
        "would_block": would_block,
        "content_sha256": content_hash,
        "max_severity": max_severity,
        "finding_count": len(findings),
        "findings": findings,
        "advice": _advice(findings, blocked),
    }


def compact_security_report(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "enabled": report["enabled"],
        "mode": report["mode"],
        "blocked": report["blocked"],
        "would_block": report["would_block"],
        "content_sha256": report["content_sha256"],
        "max_severity": report["max_severity"],
        "finding_count": report["finding_count"],
        "rule_ids": [finding["rule_id"] for finding in report["findings"]],
        "categories": sorted({finding["category"] for finding in report["findings"]}),
    }


def _find_security_issues(content: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for rule in RULES:
        for match in rule.pattern.finditer(content):
            severity = rule.severity
            if rule.defensive_downgrade and _has_defensive_context(content, match.start()):
                severity = "low"
            findings.append(
                {
                    "rule_id": rule.id,
                    "category": rule.category,
                    "severity": severity,
                    "message": rule.message,
                    "span": {"start": match.start(), "end": match.end()},
                    "snippet": _safe_snippet(content, match.start(), match.end(), rule.redacts_match),
                }
            )
    return sorted(
        findings,
        key=lambda item: (
            -SEVERITY_SCORE[item["severity"]],
            item["span"]["start"],
            item["rule_id"],
        ),
    )


def _has_defensive_context(content: str, start: int) -> bool:
    before = content[max(0, start - _CONTEXT_CHARS) : start]
    return bool(_DEFENSIVE_CONTEXT_RE.search(before))


def _safe_snippet(content: str, start: int, end: int, redact: bool) -> str:
    left = max(0, start - _CONTEXT_CHARS)
    right = min(len(content), end + _CONTEXT_CHARS)
    if not redact:
        return content[left:right].replace("\n", "\\n")
    snippet = content[left:start] + _redaction(end - start) + content[end:right]
    return snippet.replace("\n", "\\n")


def _redaction(length: int) -> str:
    return "[REDACTED:" + str(max(length, 0)) + "_chars]"


def _max_severity(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "info"
    return max(findings, key=lambda item: SEVERITY_SCORE[item["severity"]])["severity"]


def _severity_at_least(value: str, threshold: str) -> bool:
    return SEVERITY_SCORE[value] >= SEVERITY_SCORE[threshold]


def _advice(findings: list[dict[str, Any]], blocked: bool) -> list[str]:
    if not findings:
        return ["No prompt-injection, exfiltration, dangerous-action, or secret patterns found."]

    categories = {finding["category"] for finding in findings}
    advice = []
    if "secret" in categories:
        advice.append("Remove secrets from prompts and use environment variables or a secret manager.")
    if "prompt_injection" in categories:
        advice.append("Separate untrusted user content from system/developer instructions.")
    if "exfiltration" in categories:
        advice.append("Remove instructions that request hidden prompts, credentials, or private data.")
    if "tool_abuse" in categories or "dangerous_action" in categories:
        advice.append("Require explicit user approval and least-privilege tool access for risky actions.")
    if blocked:
        advice.append("Use security_mode='warn' only if you intentionally want to store this for testing.")
    return advice
