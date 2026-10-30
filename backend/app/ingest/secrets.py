"""Built-in secret detection and redaction.

Used twice:
1. As a scanner (findings with masked values) — always available, even without Gitleaks.
2. As a redaction filter on every piece of repository text before it is sent to Claude.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

REDACTED = "[REDACTED_SECRET]"


@dataclass(frozen=True)
class SecretRule:
    id: str
    title: str
    pattern: re.Pattern[str]
    group: int = 0  # which regex group holds the secret value
    severity: str = "high"


RULES: list[SecretRule] = [
    SecretRule("aws-access-key-id", "AWS access key ID", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 1),
    SecretRule(
        "aws-secret-access-key",
        "AWS secret access key",
        re.compile(r"(?i)aws.{0,20}?(?:secret|private).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]"),
        1,
        "critical",
    ),
    SecretRule("anthropic-api-key", "Anthropic API key", re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})"), 1, "critical"),
    SecretRule("openai-api-key", "OpenAI-style API key", re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9]{32,})\b"), 1, "critical"),
    SecretRule("github-token", "GitHub token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,})\b"), 1, "critical"),
    SecretRule("slack-token", "Slack token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), 1),
    SecretRule("stripe-key", "Stripe secret key", re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{16,})\b"), 1, "critical"),
    SecretRule("google-api-key", "Google API key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), 1),
    SecretRule(
        "private-key",
        "Private key block",
        re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----)"),
        1,
        "critical",
    ),
    SecretRule(
        "jwt",
        "JSON Web Token",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        1,
        "medium",
    ),
    SecretRule(
        "url-credentials",
        "Credentials embedded in URL",
        re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@'\"]+:([^\s@'\"]{4,})@[^\s'\"]+"),
        1,
    ),
    SecretRule(
        "hardcoded-password",
        "Hard-coded password or secret assignment",
        re.compile(
            r"""(?ix)
            \b[\w.]*(?:password|passwd|pwd|secret|api_?key|access_?token|auth_?token|client_?secret|private_?key)[\w]*
            \s*[:=]\s*
            ['"]([^'"\s]{6,})['"]"""
        ),
        1,
        "high",
    ),
]

# Values that look like secrets but are obviously placeholders.
_PLACEHOLDER = re.compile(
    r"(?i)^(?:x+|\*+|changeme|change_me|your[_-].*|<.*>|\$\{.*\}|\{\{.*\}\}|placeholder|example|dummy|test|none|null|password|secret|os\.environ.*|getenv.*)$"
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())


@dataclass
class SecretMatch:
    rule_id: str
    title: str
    severity: str
    line: int
    start: int
    end: int
    value: str

    @property
    def masked(self) -> str:
        return mask(self.value)


def mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * min(len(value) - 4, 12)


def find_secrets(text: str) -> list[SecretMatch]:
    matches: list[SecretMatch] = []
    seen: set[tuple[int, int]] = set()
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            value = m.group(rule.group)
            start, end = m.start(rule.group), m.end(rule.group)
            if (start, end) in seen:
                continue
            if rule.id == "hardcoded-password":
                if _PLACEHOLDER.match(value) or shannon_entropy(value) < 2.5:
                    continue
            seen.add((start, end))
            line = text.count("\n", 0, start) + 1
            matches.append(SecretMatch(rule.id, rule.title, rule.severity, line, start, end, value))
    return sorted(matches, key=lambda s: s.start)


def redact(text: str) -> tuple[str, int]:
    """Replace secret values with a marker. Returns (redacted_text, count)."""
    found = find_secrets(text)
    if not found:
        return text, 0
    out, pos = [], 0
    for s in found:
        if s.start < pos:
            continue
        out.append(text[pos : s.start])
        out.append(REDACTED)
        pos = s.end
    out.append(text[pos:])
    return "".join(out), len(found)
