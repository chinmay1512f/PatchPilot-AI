"""Attack Path Analysis — part of Agent 5 (Verification & Security), not a separate agent.

Claude looks at the security findings the scanners actually reported and asks: could an attacker
combine several of them? Guardrails:
- Only tool-detected findings are offered (likely false positives and lint are left out).
- Every step must reference one of those findings; steps that cite unknown findings are dropped, and a
  path needs at least two valid steps on two different findings — otherwise it is not a chain.
- File, line, severity and scanner of each step come from the finding (tool evidence), never the model.
- Exploitation is described conceptually; no exploit code, payloads or commands.
- The deterministic risk score does not use any of this.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

from ..core.models import (
    AttackPath,
    AttackPathReport,
    AttackStep,
    Confidence,
    EntryPoint,
    SecurityFinding,
    SecurityReport,
    Severity,
    new_id,
)
from ..ingest.indexer import RepoIndex
from ..llm.client import LLMError, untrusted
from ..tools.diffing import enclosing_function
from .base import PLAIN_LANGUAGE, AgentContext, facts_brief

SYSTEM = """You are the attack-path part of the Verification & Security agent, doing defensive threat
modelling for the owner of this repository. You get the security findings that real scanners
reported, each with its code. Work out whether an attacker could COMBINE several of them into a
path from an entry point to a serious impact, and which findings are the most dangerous entry points.

Rules:
- Use only the findings listed, referenced by their exact finding_id. Each path needs at least two
  steps that use different findings. Do not invent vulnerabilities, files or endpoints.
- Be realistic about who the attacker is (e.g. unauthenticated internet user, logged-in user, anyone
  who can read the repository, a local user) and state the preconditions that must hold.
- Describe each step conceptually: what the attacker does and what they gain. Never write exploit
  code, payloads, shell commands or step-by-step attack instructions.
- For each path name the single fix that breaks the chain most cheaply.
- Rank up to 5 entry points: findings an attacker would most likely start from, and why.
- At most 3 paths, most dangerous first. If no realistic chain exists, return no paths and explain why
  in no_chain_reason. Quality over quantity."""
SYSTEM += "\n\n" + PLAIN_LANGUAGE


class StepDraft(BaseModel):
    finding_id: str
    action: str
    gains: str


class PathDraft(BaseModel):
    title: str
    attacker: str
    entry_point: str
    steps: list[StepDraft]
    impact: str
    severity: Literal["critical", "high", "medium", "low"]
    likelihood: Literal["low", "medium", "high"]
    confidence: Literal["high", "medium", "low"]
    preconditions: list[str] = Field(default_factory=list)
    break_the_chain: str


class EntryDraft(BaseModel):
    finding_id: str
    reason: str


class AttackPathDraft(BaseModel):
    paths: list[PathDraft]
    entry_points: list[EntryDraft]
    summary: str
    no_chain_reason: str = ""


def eligible(report: SecurityReport, limit: int) -> list[SecurityFinding]:
    """Tool findings worth chaining: no lint, nothing triage judged a likely false positive."""
    order = list(Severity)
    keep = [f for f in report.findings if f.category != "lint"
            and not (f.ai_assessment and f.ai_assessment.verdict == "likely_false_positive")]
    return sorted(keep, key=lambda f: (order.index(f.severity), f.file_path or ""))[:limit]


def _block(f: SecurityFinding, index: RepoIndex) -> str:
    where = f"{f.file_path}:{f.line}" if f.file_path and f.line else (f.file_path or "-")
    fn = ""
    src = index.resolve(f.file_path) if f.file_path else None
    if src and src.text and f.line and f.file_path.endswith(".py"):
        fn = enclosing_function(src.text, f.line) or ""
    code = index.excerpt(f.file_path, f.line, f.line, context=3) if src and f.line else f.snippet
    head = (f"finding_id={f.id} severity={f.severity} category={f.category} scanner={f.scanner} rule={f.rule_id}\n"
            f"location={where}{' in ' + fn + '()' if fn else ''}\ntitle={f.title}\ndescription={f.description[:400]}")
    return head + "\n" + untrusted(f.file_path or "finding", code or "(no source excerpt)")


def analyse(ctx: AgentContext, report: SecurityReport, index: RepoIndex) -> AttackPathReport:
    if not ctx.settings.attack_paths_enabled:
        return AttackPathReport(status="unavailable", summary="Attack path analysis is turned off in the configuration.")
    pool = eligible(report, ctx.settings.attack_paths_max_findings)
    if len(pool) < 2:
        return AttackPathReport(status="not_needed", findings_considered=len(pool),
                                summary="Fewer than two security findings to combine, so there is no attack chain to analyse.")
    ok, why = ctx.llm.available()
    if not ok:
        return AttackPathReport(status="unavailable", findings_considered=len(pool), summary=why)
    ctx.log("verification", f"attack path analysis started ({len(pool)} findings)")
    prompt = (f"Project facts:\n{facts_brief(index)}\n\nSecurity findings reported by the scanners:\n\n"
              + "\n\n".join(_block(f, index) for f in pool))
    try:
        draft = ctx.llm.structured(agent="verification", system=SYSTEM, messages=prompt, output_model=AttackPathDraft, effort="medium")
    except LLMError as e:
        return AttackPathReport(status=f"failed: {e}", findings_considered=len(pool))
    result = validate(draft, pool)
    ctx.log("verification", f"attack path analysis: {len(result.paths)} path(s), {len(result.entry_points)} entry point(s)"
            + (f"; dropped: {'; '.join(result.dropped)}" if result.dropped else ""))
    return result


_ID_RE = re.compile(r"\b(sec_[a-f0-9]{6,})\b")


def _humanise(text: str, by_id: dict[str, SecurityFinding]) -> str:
    """Replace internal finding ids the model may have echoed with the finding's location."""
    def loc(m: re.Match) -> str:
        f = by_id.get(m.group(1))
        return (f"{f.file_path}:{f.line}" if f.line else f.file_path) if f and f.file_path else "a reported finding"
    text = re.sub(r"\s*\(\s*(sec_[a-f0-9]{6,})\s*\)", lambda m: f" ({loc(m)})", text)
    return _ID_RE.sub(loc, text)


def validate(draft: AttackPathDraft, pool: list[SecurityFinding]) -> AttackPathReport:
    """Keep only what is backed by real findings; copy location/severity from the tool data."""
    by_id = {f.id: f for f in pool}
    h = lambda t: _humanise(t, by_id)  # noqa: E731
    for p in draft.paths:
        p.title, p.attacker, p.entry_point, p.impact, p.break_the_chain = map(h, (p.title, p.attacker, p.entry_point, p.impact, p.break_the_chain))
        p.preconditions = [h(c) for c in p.preconditions]
        for s in p.steps:
            s.action, s.gains = h(s.action), h(s.gains)
    for e in draft.entry_points:
        e.reason = h(e.reason)
    draft.summary, draft.no_chain_reason = h(draft.summary), h(draft.no_chain_reason)
    order = list(Severity)
    out = AttackPathReport(status="completed", findings_considered=len(pool), summary=draft.summary)
    for p in draft.paths[:3]:
        steps, unknown = [], 0
        for s in p.steps[:6]:
            f = by_id.get(s.finding_id)
            if f is None:
                unknown += 1
                continue
            steps.append(AttackStep(finding_id=f.id, title=f.title, scanner=f.scanner, file_path=f.file_path, line=f.line,
                                    severity=f.severity, action=s.action, gains=s.gains))
        if unknown:
            out.dropped.append(f"“{p.title}”: {unknown} step(s) cited findings that do not exist")
        if len(steps) < 2 or len({s.finding_id for s in steps}) < 2:
            out.dropped.append(f"“{p.title}”: removed — fewer than two real findings, so it is not a chain")
            continue
        worst = min((s.severity for s in steps), key=order.index)
        sev = Severity(p.severity)
        out.paths.append(AttackPath(
            id=new_id("path"), title=p.title, attacker=p.attacker, entry_point=p.entry_point, steps=steps, impact=p.impact,
            # a chain can be worse than its parts, but never rated below its worst real finding
            severity=min(sev, worst, key=order.index), likelihood=p.likelihood, confidence=Confidence(p.confidence),
            preconditions=p.preconditions[:5], break_the_chain=p.break_the_chain,
        ))
    seen: set[str] = set()
    for e in draft.entry_points:
        f = by_id.get(e.finding_id)
        if f is None or f.id in seen or len(out.entry_points) >= 5:
            continue
        seen.add(f.id)
        out.entry_points.append(EntryPoint(rank=len(out.entry_points) + 1, finding_id=f.id, title=f.title, file_path=f.file_path,
                                           line=f.line, severity=f.severity, reason=e.reason))
    if not out.paths:
        out.summary = draft.no_chain_reason or draft.summary or "No realistic chain of the detected findings was identified."
    return out
