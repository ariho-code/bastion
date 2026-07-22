"""Bastionscan analysis brain — a FastAPI service that turns raw scan findings
into executive risk intelligence and a prioritized remediation roadmap.

Two entrypoints:
  * POST /v1/analyze — bring your own engine ScanResult, get an analysis.
  * POST /v1/assess  — give a target, the brain drives the engine then analyzes.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from . import cve, engine_client, osv
from .analyzer import analyze
from .config import config
from .models import AssessRequest, AssessResponse, RiskAnalysis, ScanResult

app = FastAPI(
    title="Bastionscan Brain",
    version=config.version,
    description="Risk intelligence and remediation prioritization for Bastionscan scans.",
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
    except Exception:  # noqa: BLE001 - health must never raise
        engine_ok = False
    return {
        "status": "ok",
        "service": "bastionscan-brain",
        "version": config.version,
        "engine_reachable": engine_ok,
    }


@app.get("/v1/verify")
async def verify_endpoint(target: str) -> dict[str, object]:
    """Return the DNS TXT record that unlocks Active-tier scans for a domain."""
    try:
        return await engine_client.verify(target)
    except engine_client.EngineError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc


@app.post("/v1/analyze", response_model=RiskAnalysis)
async def analyze_endpoint(scan: ScanResult) -> RiskAnalysis:
    """Analyze a ScanResult produced by the engine."""
    live = await osv.enrich(cve.detect(scan.findings))
    return analyze(scan, extra_cves=live)


@app.post("/v1/assess", response_model=AssessResponse)
async def assess_endpoint(req: AssessRequest) -> AssessResponse:
    """Drive the engine for `target`, then return the scan plus its analysis."""
    try:
        raw = await engine_client.scan(req.target, req.profile, req.verified, scope=req.scope)
    except engine_client.EngineError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc

    scan_result = ScanResult.model_validate(raw)
    live = await osv.enrich(cve.detect(scan_result.findings))
    analysis = analyze(scan_result, extra_cves=live)
    return AssessResponse(scan=raw, analysis=analysis)
