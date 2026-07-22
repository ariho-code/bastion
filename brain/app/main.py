"""Bastionscan analysis brain — risk intelligence, AI insights, and continuous learning.

Entrypoints:
  * POST /v1/analyze  — bring your own engine ScanResult
  * POST /v1/assess   — drive engine + analyze + AI + record learning
  * POST /v1/feedback — operator labels (FP/TP) that retrain soft weights
  * GET  /v1/history  — recent scans for enterprise dashboards
  * GET  /v1/learning — feedback stats + finding weights
  * POST /v1/ai/insight — AI-only enrichment
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from . import cve, engine_client, osv
from .ai.client import get_client
from .ai.insights import enrich_with_ai
from .ai.learning import get_store
from .analyzer import analyze
from .config import config
from .models import (
    AIInsights,
    AssessRequest,
    AssessResponse,
    FeedbackRequest,
    InsightRequest,
    RiskAnalysis,
    ScanResult,
)

app = FastAPI(
    title="Bastionscan Brain",
    version=config.version,
    description="Risk intelligence, AI insights, and continuous learning for Bastionscan.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.allowed_origins,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict[str, object]:
    engine_ok = False
    try:
        await engine_client.health()
        engine_ok = True
    except Exception:  # noqa: BLE001
        engine_ok = False
    ai = get_client()
    store = get_store()
    return {
        "status": "ok",
        "service": "bastionscan-brain",
        "version": config.version,
        "engine_reachable": engine_ok,
        "ai": {
            "enabled": ai.enabled,
            "provider": ai.provider,
            "model": ai.model,
        },
        "learning": {
            "dir": str(store.root),
            "feedback": store.feedback_stats().get("total", 0),
        },
    }


@app.get("/v1/verify")
async def verify_endpoint(target: str) -> dict[str, object]:
    try:
        return await engine_client.verify(target)
    except engine_client.EngineError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc


@app.post("/v1/analyze", response_model=RiskAnalysis)
async def analyze_endpoint(scan: ScanResult) -> RiskAnalysis:
    live = await osv.enrich(cve.detect(scan.findings))
    weights = get_store().finding_weights()
    return analyze(scan, extra_cves=live, learning_weights=weights)


@app.post("/v1/assess", response_model=AssessResponse)
async def assess_endpoint(req: AssessRequest) -> AssessResponse:
    try:
        raw = await engine_client.scan(req.target, req.profile, req.verified, scope=req.scope)
    except engine_client.EngineError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc

    scan_result = ScanResult.model_validate(raw)
    live = await osv.enrich(cve.detect(scan_result.findings))
    store = get_store()
    analysis = analyze(scan_result, extra_cves=live, learning_weights=store.finding_weights())

    vertical = "general"
    if req.scope and isinstance(req.scope, dict):
        vertical = str(req.scope.get("vertical") or "general").lower()

    ai_block: AIInsights | None = None
    if req.ai and config.ai_on_assess:
        raw_ai = await enrich_with_ai(scan_result, analysis, vertical=vertical)
        if raw_ai:
            ai_block = AIInsights.model_validate(raw_ai)
            # Lead narrative with AI summary when available.
            if ai_block.summary and ai_block.source == "llm":
                analysis.summary = [ai_block.summary, *analysis.summary][:8]
            if ai_block.vertical_advice:
                analysis.summary.append(ai_block.vertical_advice)

    analysis.ai = ai_block

    findings_payload = [f.model_dump() for f in scan_result.findings]
    scan_id = store.record_scan(
        target=analysis.target,
        profile=req.profile,
        vertical=vertical,
        grade=analysis.grade,
        score=analysis.score,
        risk_index=analysis.risk_index,
        risk_level=analysis.risk_level,
        findings=findings_payload,
        verified=bool(raw.get("verified")),
        tenant=req.tenant or "default",
        ai_summary=ai_block.summary if ai_block else None,
    )
    analysis.scan_id = scan_id

    return AssessResponse(scan=raw, analysis=analysis)


@app.post("/v1/feedback")
async def feedback_endpoint(req: FeedbackRequest) -> dict[str, object]:
    """Human-in-the-loop learning: label findings so the brain recalibrates."""
    store = get_store()
    try:
        row = store.record_feedback(
            finding_id=req.finding_id,
            label=req.label,
            target=req.target,
            note=req.note,
            scan_id=req.scan_id,
            tenant=req.tenant or "default",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "feedback": row, "weights": store.finding_weights()}


@app.get("/v1/history")
async def history_endpoint(
    tenant: str = Query("default"),
    limit: int = Query(40, ge=1, le=200),
) -> dict[str, object]:
    store = get_store()
    rows = store.list_scans(tenant=tenant, limit=limit)
    return {"count": len(rows), "scans": rows}


@app.get("/v1/learning")
async def learning_endpoint() -> dict[str, object]:
    store = get_store()
    stats = store.feedback_stats()
    return {
        "stats": stats,
        "lessons": store.few_shot_lessons(15),
        "ai": {
            "provider": get_client().provider,
            "model": get_client().model,
            "enabled": get_client().enabled,
        },
    }


@app.post("/v1/ai/insight")
async def ai_insight_endpoint(req: InsightRequest) -> dict[str, object]:
    """AI enrichment without a full re-scan (dashboard refresh / training view)."""
    from .models import Finding

    findings = [Finding.model_validate(f) for f in req.findings]
    scan = ScanResult(
        target=req.target,
        host=req.target,
        findings=findings,
        grade=str(req.analysis.get("grade") or ""),
        score=int(req.analysis.get("score") or 0),
    )
    analysis = analyze(scan, learning_weights=get_store().finding_weights())
    raw_ai = await enrich_with_ai(scan, analysis, vertical=req.vertical or "general")
    return {"analysis": analysis.model_dump(), "ai": raw_ai}
