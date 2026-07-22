"""Risk analysis: turn raw engine findings into an executive risk assessment
and a prioritized remediation roadmap.

The model is intentionally transparent (weighted, explainable) rather than a
black box: each open issue contributes severity_weight x category_weight to a
raw risk figure, which is mapped through a saturating curve to a 0-100 index.
"""

from __future__ import annotations

import math

import re

from . import cve
from .models import (
    CategoryRisk,
    CVEMatch,
    Finding,
    RemediationItem,
    RiskAnalysis,
    ScamVerdict,
    ScanResult,
)

SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 10.0,
    "high": 6.0,
    "medium": 3.0,
    "low": 1.0,
    "info": 0.0,
}

# Category multipliers: an exposed secret or open database (disclosure/surface)
# is worse than a missing low-value header, even at similar severity.
CATEGORY_WEIGHT: dict[str, float] = {
    "transport": 1.2,
    "headers": 1.0,
    "dns": 0.9,
    "cookies": 1.0,
    "content": 1.0,
    "disclosure": 1.3,
    "surface": 1.4,
    "intel": 1.5,
    "scam": 1.6,
}

CATEGORY_LABELS: dict[str, str] = {
    "transport": "Transport & TLS",
    "headers": "Response Headers",
    "dns": "DNS & Email",
    "cookies": "Cookies",
    "content": "Content Integrity",
    "disclosure": "Info Disclosure",
    "surface": "Attack Surface",
    "intel": "Threat Intelligence",
    "scam": "Scam & Phishing",
}

# Rough remediation effort by category (config change vs. infra work).
EFFORT_BY_CATEGORY: dict[str, str] = {
    "headers": "Quick",
    "cookies": "Quick",
    "dns": "Quick",
    "transport": "Moderate",
    "content": "Moderate",
    "disclosure": "Involved",
    "surface": "Involved",
    "intel": "Involved",
    "scam": "Quick",
}

SEVERITY_RANK: dict[str, int] = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 4}

# Curve constant: larger = more forgiving. Calibrated so a single critical
# issue (e.g. an exposed .env) lands in "High" (~56), two criticals reach
# "Critical" (~80), and a header-only site sits in "Medium/High".
_SATURATION = 16.0


def _is_open(f: Finding) -> bool:
    return f.status in ("fail", "warn")


def _weight(f: Finding) -> float:
    sev = SEVERITY_WEIGHT.get(f.severity, 0.0)
    cat = CATEGORY_WEIGHT.get(f.category, 1.0)
    dampen = 0.5 if f.status == "warn" else 1.0
    return sev * cat * dampen


def _risk_level(index: int, critical: int, high: int) -> str:
    """Map the risk index to a level, tempered by severity composition.

    We refuse to label a target "Critical" purely on accumulated config hygiene:
    that word is reserved for a genuinely critical finding or an overwhelming
    pile of highs. This keeps the assessment credible rather than alarmist.
    """
    if index >= 75:
        base = "Critical"
    elif index >= 50:
        base = "High"
    elif index >= 25:
        base = "Medium"
    elif index >= 10:
        base = "Low"
    else:
        base = "Minimal"

    if base == "Critical" and critical == 0 and high < 4:
        return "High"
    return base


def _effort(f: Finding) -> str:
    return EFFORT_BY_CATEGORY.get(f.category, "Moderate")


def _priority(f: Finding) -> str:
    rank = SEVERITY_RANK.get(f.severity, 4)
    if f.status == "warn":
        rank = min(4, rank + 1)
    return f"P{rank}"


def analyze(scan: ScanResult, extra_cves: list[CVEMatch] | None = None) -> RiskAnalysis:
    findings = scan.findings
    open_issues = [f for f in findings if _is_open(f)]

    # --- severity tally ------------------------------------------------------
    fails = [f for f in findings if f.status == "fail"]
    critical = sum(1 for f in fails if f.severity == "critical")
    high = sum(1 for f in fails if f.severity == "high")
    medium = sum(1 for f in fails if f.severity == "medium")
    low = sum(1 for f in fails if f.severity == "low")

    # --- CVE correlation -----------------------------------------------------
    # `extra_cves` carries live advisories fetched by the async layer (OSV.dev);
    # correlate merges them with the curated database.
    cve_matches = cve.correlate(findings, extra=extra_cves)

    # --- risk index ----------------------------------------------------------
    # Known-vulnerable software is a strong, concrete risk signal, so it adds to
    # the raw figure alongside the open findings.
    raw = sum(_weight(f) for f in open_issues)
    raw += sum(SEVERITY_WEIGHT.get(m.severity, 0.0) * 1.6 for m in cve_matches)
    risk_index = round(100 * (1 - math.exp(-raw / _SATURATION)))
    risk_index = max(0, min(100, risk_index))
    # A critical CVE should never read as low risk.
    cve_critical = any(m.severity == "critical" for m in cve_matches)
    level = _risk_level(risk_index, critical + (1 if cve_critical else 0), high)

    # --- per-category risk ---------------------------------------------------
    cat_raw: dict[str, float] = {}
    cat_open: dict[str, int] = {}
    for f in open_issues:
        cat_raw[f.category] = cat_raw.get(f.category, 0.0) + _weight(f)
        cat_open[f.category] = cat_open.get(f.category, 0) + 1
    category_risk = [
        CategoryRisk(
            category=cat,
            label=CATEGORY_LABELS.get(cat, cat.title()),
            risk=max(0, min(100, round(100 * (1 - math.exp(-raw_c / (_SATURATION / 2)))))),
            open_issues=cat_open.get(cat, 0),
        )
        for cat, raw_c in sorted(cat_raw.items(), key=lambda kv: kv[1], reverse=True)
    ]

    # --- remediation roadmap -------------------------------------------------
    remediation = _build_remediation(open_issues) + _cve_remediation(cve_matches)
    remediation.sort(key=lambda it: (int(it.priority[1]), -it.points_lost))

    # --- scam / phishing verdict --------------------------------------------
    scam = _scam_verdict(findings)

    # --- narrative -----------------------------------------------------------
    strengths = _strengths(findings)
    headline, summary = _narrative(scan, level, critical, high, medium, remediation, strengths)
    # A scam verdict is the most important thing a person can be told — lead with it.
    if scam is not None and scam.is_scam:
        headline = scam.headline
        summary.insert(0, scam.advice)
    if cve_matches:
        names = ", ".join(f"{m.product} {m.version}" for m in cve_matches[:3])
        summary.insert(
            0,
            f"{len(cve_matches)} outdated component(s) with known CVEs detected: {names}.",
        )

    return RiskAnalysis(
        target=scan.target or scan.host,
        grade=scan.grade,
        score=scan.score,
        risk_index=risk_index,
        risk_level=level,
        headline=headline,
        summary=summary,
        strengths=strengths,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        category_risk=category_risk,
        cve_matches=cve_matches,
        remediation=remediation,
        scam=scam,
    )


_SCAM_LEVELS: dict[str, int] = {"SAFE": 0, "LOW RISK": 1, "SUSPICIOUS": 2, "DANGEROUS": 3}
_SCAM_ADVICE: dict[int, str] = {
    0: "No scam indicators were found, but always double-check the address bar before entering sensitive details.",
    1: "A minor red flag was found. Nothing conclusive — proceed carefully, verify the company independently, and never send crypto or share a seed phrase.",
    2: "Several scam red flags were found (naming, age, content, or hosting). Do not enter passwords, payments, or wallet details unless you are certain this site is legitimate.",
    3: "Strong signs of a phishing, investment, or crypto-draining scam. Do NOT log in, pay, invest, or connect a wallet. Leave the site and report it.",
}
_BRAND_RE = re.compile(r"impersonating ([A-Z][\w.&/ -]+?)(?:\.| but| —|,|$)")


def _scam_verdict(findings: list[Finding]) -> ScamVerdict | None:
    """Distill the engine's phishing-module findings into one consumer verdict.

    Returns None when the phishing module did not run (e.g. an older engine), so
    older scans keep working unchanged.

    Multi-signal corroboration (domain age, blocklists, lexical naming, hosting,
    content playbooks) is performed in the Go engine; the brain preserves the
    engine's verdict and surfaces every open signal as a plain-English reason.
    """
    phish = [f for f in findings if f.module == "phishing" or f.id.startswith("phishing.")]
    if not phish:
        return None

    verdict_f = next((f for f in phish if f.id == "phishing.verdict"), None)

    # Prefer the engine's explicit label ("Scam verdict: DANGEROUS"); fall back to
    # the finding's severity if the format ever drifts.
    label = "SAFE"
    if verdict_f is not None:
        _, _, tail = verdict_f.title.partition(":")
        tail = tail.strip().upper()
        if tail in _SCAM_LEVELS:
            label = tail
        else:
            label = {
                "critical": "DANGEROUS",
                "high": "SUSPICIOUS",
                "low": "LOW RISK",
            }.get(verdict_f.severity, "SAFE")
    level = _SCAM_LEVELS.get(label, 0)

    headline = verdict_f.detail if verdict_f is not None else f"Scam assessment: {label}."

    # Supporting reasons: every open (fail/warn) phishing signal except the
    # verdict headline itself. Prefer evidence when present (more specific).
    reasons: list[str] = []
    for f in phish:
        if f.status not in ("fail", "warn") or f.id == "phishing.verdict":
            continue
        text = (f.evidence or "").strip() or (f.detail or "").strip()
        if text and text not in reasons:
            reasons.append(text)

    brand: str | None = None
    imp = next((f for f in phish if f.id == "phishing.impersonation"), None)
    if imp is not None and imp.status == "fail":
        m = _BRAND_RE.search(imp.detail)
        if m:
            brand = m.group(1).strip()

    # Cross-check: critical blocklist / seed harvest findings must never render
    # as anything softer than DANGEROUS even if the verdict label drifts.
    hard = {
        f.id
        for f in phish
        if f.status == "fail" and f.severity == "critical"
        and f.id in ("phishing.reputation", "phishing.harvesting")
    }
    if hard and level < 3:
        label, level = "DANGEROUS", 3
        if verdict_f is not None and verdict_f.detail:
            headline = verdict_f.detail

    return ScamVerdict(
        verdict=label,
        level=level,
        is_scam=level >= 2,
        brand=brand,
        headline=headline,
        reasons=reasons[:8],
        advice=_SCAM_ADVICE.get(level, _SCAM_ADVICE[0]),
    )


def _build_remediation(open_issues: list[Finding]) -> list[RemediationItem]:
    items = [
        RemediationItem(
            priority=_priority(f),
            severity=f.severity,
            category=f.category,
            title=f.title,
            detail=f.detail,
            fix=f.fix,
            reference=f.reference,
            effort=_effort(f),
            points_lost=max(0, f.maxPoints - f.points),
        )
        for f in open_issues
    ]
    items.sort(key=lambda it: (int(it.priority[1]), -it.points_lost))
    return items


def _cve_remediation(matches: list[CVEMatch]) -> list[RemediationItem]:
    prio = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P4"}
    out: list[RemediationItem] = []
    for m in matches:
        cves = ", ".join(m.cves)
        out.append(
            RemediationItem(
                priority=prio.get(m.severity, "P3"),
                severity=m.severity,
                category="software",
                title=f"Upgrade {m.product} to {m.fixed_in}+",
                detail=f"Detected {m.product} {m.version}. {m.summary} ({cves})",
                fix=f"Update {m.product} to {m.fixed_in} or later.",
                reference=None,
                effort="Involved",
                points_lost=0,
            )
        )
    return out


def _strengths(findings: list[Finding]) -> list[str]:
    strong = [
        f.title
        for f in findings
        if f.status == "pass" and f.maxPoints >= 8
    ]
    # De-duplicate while preserving order, cap for readability.
    seen: set[str] = set()
    out: list[str] = []
    for t in strong:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out[:8]


def _narrative(
    scan: ScanResult,
    level: str,
    critical: int,
    high: int,
    medium: int,
    remediation: list[RemediationItem],
    strengths: list[str],
) -> tuple[str, list[str]]:
    target = scan.target or scan.host or "the target"
    headline = f"{target} scores {scan.grade or '—'} with {level.lower()} overall risk."

    summary: list[str] = []
    if critical:
        summary.append(
            f"{critical} critical issue{'s' if critical != 1 else ''} demand immediate attention — "
            "these are directly exploitable or leak sensitive data."
        )
    if high:
        summary.append(
            f"{high} high-severity weakness{'es' if high != 1 else ''} meaningfully raise the risk of compromise."
        )
    if not critical and not high:
        if medium:
            summary.append(
                f"No critical or high issues, but {medium} medium-severity item{'s' if medium != 1 else ''} should be addressed."
            )
        else:
            summary.append("No critical or high issues were found — a solid baseline posture.")

    top = remediation[:3]
    if top:
        names = ", ".join(t.title for t in top)
        summary.append(f"Top priorities: {names}.")

    if strengths:
        summary.append(f"Working well: {', '.join(strengths[:4])}.")

    return headline, summary
