"""
backend/main.py — Production FastAPI Application.
Track 1: Agents That Act on Connected Data (FalkorDB Hackathon)

Endpoints:
  - GET  /api/health            : Database status (live vs mock_fallback) & MCP tool count
  - GET  /api/alerts            : List all seeded security alerts (ALT001 to ALT006)
  - GET  /api/alerts/{id}       : Retrieve specific alert context
  - POST /api/investigate       : Autonomous multi-hop investigation loop (Agent Brain)
  - POST /api/what-if           : Read-only counterfactual "What-If" simulation
  - GET  /api/graph             : Cytoscape.js graph elements for SOC dashboard visualizer
  - POST /api/governance/action : Human-in-the-loop action approval/rejection
  - GET  /api/audit-log         : Append-only governance audit log
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root and backend are in sys.path
_ROOT = Path(__file__).resolve().parent.parent
_BACKEND = Path(__file__).resolve().parent
for _p in [str(_ROOT), str(_BACKEND)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from backend.agent import InvestigationAgent
from backend.graph_client import get_graph_client
from backend.report_generator import (
    generate_cytoscape_elements,
    generate_markdown_report,
)
from backend.risk_engine import compute_risk_from_graph, simulate_counterfactual
from backend.schemas import (
    ActionDecisionPayload,
    ActionProposalPayload,
    AlertSummary,
    GraphVisualization,
    HealthResponse,
    InvestigationReport,
    InvestigationRequestPayload,
    WhatIfRequestPayload,
    WhatIfResponse,
)

# Logging configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("backend.main")

# Initialize FastAPI App
app = FastAPI(
    title="GraphGuard AI — FalkorDB Autonomous Security Agent",
    description="Explainable Autonomous Security Investigation Agent powered by FalkorDB and Model Context Protocol.",
    version="1.0.0",
)

# Enable CORS for React/Vite Dashboard
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def normalize_vercel_api_path(request, call_next):
    # Normalize paths rewritten by Vercel serverless function runners
    path = request.scope.get("path", "")
    for prefix in ["/api/index.py/", "/api/index.py", "/api/index/"]:
        if path.startswith(prefix):
            remainder = path[len(prefix):]
            if not remainder.startswith("/"):
                remainder = "/" + remainder
            request.scope["path"] = "/api" + remainder
            break
    curr_path = request.scope.get("path", "")
    known_api_roots = ("/health", "/alerts", "/investigate", "/what-if", "/graph", "/governance", "/audit-log")
    if any(curr_path.startswith(prefix) for prefix in known_api_roots):
        request.scope["path"] = "/api" + curr_path
    return await call_next(request)




# In-Memory Cache for Recent Investigations & Audit Log
INVESTIGATION_CACHE: Dict[str, InvestigationReport] = {}
AUDIT_LOG_FILE = Path("/tmp/audit_log.json") if os.environ.get("VERCEL") else Path("audit_log.json")
_SEED_AUDIT_LOG = Path(__file__).resolve().parent.parent / "audit_log.json"


def _get_audit_entries() -> List[Dict[str, Any]]:
    for candidate in [AUDIT_LOG_FILE, _SEED_AUDIT_LOG]:
        if candidate.exists():
            try:
                return json.loads(candidate.read_text(encoding="utf-8"))
            except Exception:
                pass
    return []


def _record_audit_entry(entry: Dict[str, Any]) -> None:
    try:
        entries = _get_audit_entries()
        entries.append(entry)
        AUDIT_LOG_FILE.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    except Exception as exc:
        logger.warning("Could not write audit log: %s", exc)


# ==============================================================================
# 1. HEALTH & METRICS
# ==============================================================================

@app.get("/api/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Returns database health, active mode (live vs mock_fallback), and MCP status."""
    db = get_graph_client()
    db_health = db.get_health()
    return HealthResponse(
        status="healthy",
        service="falkordb-investigation-brain",
        database=db_health,
        mcp_tools_count=8,
        environment=os.getenv("ENVIRONMENT", "development"),
    )


# ==============================================================================
# 2. ALERTS API
# ==============================================================================

@app.get("/api/alerts", response_model=List[AlertSummary])
def list_alerts() -> List[AlertSummary]:
    """Retrieves all security alerts loaded in the FalkorDB knowledge graph."""
    db = get_graph_client()
    rows = db.query("MATCH (a:Alert) RETURN a")
    summaries: List[AlertSummary] = []
    for r in rows:
        al = r.get("a", {})
        if al:
            summaries.append(AlertSummary(
                alert_id=al.get("alert_id", "UNKNOWN"),
                title=al.get("title", "Untitled Alert"),
                severity=al.get("severity", "medium"),
                status=al.get("status", "open"),
                created_at=al.get("created_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
                description=al.get("description", ""),
            ))
    # Sort critical first
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(summaries, key=lambda x: sev_order.get(x.severity.lower(), 4))


@app.get("/api/alerts/{alert_id}")
def get_alert_detail(alert_id: str) -> Dict[str, Any]:
    try:
        from backend.mcp_server.tools import get_investigation_context
    except ImportError:
        from mcp_server.tools import get_investigation_context
    res = get_investigation_context(alert_id)
    if res.get("status") != "success":
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return res


# ==============================================================================
# 3. AUTONOMOUS INVESTIGATION
# ==============================================================================

@app.post("/api/investigate", response_model=InvestigationReport)
async def investigate_alert(request: InvestigationRequestPayload) -> InvestigationReport:
    """
    Main Autonomous Agent Trigger.
    Chooses MCP tools, traverses multiple hops, evaluates evidence,
    and returns a comprehensive explainable report with Cytoscape graph elements.
    """
    agent = InvestigationAgent(
        max_hops=request.max_hops,
        max_tool_calls=min(request.query_budget, request.max_tool_calls),
    )
    report = await agent.run_investigation_async(request)

    # Cache report
    INVESTIGATION_CACHE[report.investigation_id] = report

    # Append to governance audit trail
    _record_audit_entry({
        "event": "INVESTIGATION_COMPLETED",
        "investigation_id": report.investigation_id,
        "alert_id": report.alert_id,
        "risk_score": report.risk_score,
        "risk_label": report.risk_label,
        "policy_action": report.policy_action.value,
        "elapsed_seconds": report.elapsed_seconds,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    return report


@app.get("/api/investigate/{investigation_id}", response_model=InvestigationReport)
def get_investigation(investigation_id: str) -> InvestigationReport:
    """Retrieves a previously cached investigation report."""
    report = INVESTIGATION_CACHE.get(investigation_id)
    if not report:
        raise HTTPException(status_code=404, detail="Investigation ID not found.")
    return report


@app.get("/api/investigate/{investigation_id}/markdown", response_class=PlainTextResponse)
def get_investigation_markdown(investigation_id: str) -> str:
    """Returns the full Markdown audit report for analyst review or ticket export."""
    report = INVESTIGATION_CACHE.get(investigation_id)
    if not report:
        raise HTTPException(status_code=404, detail="Investigation ID not found.")
    return generate_markdown_report(report)


# ==============================================================================
# 4. COUNTERFACTUAL ("WHAT-IF") SIMULATION
# ==============================================================================

@app.post("/api/what-if", response_model=WhatIfResponse)
def run_counterfactual_simulation(payload: WhatIfRequestPayload) -> WhatIfResponse:
    """
    Simulates removing a specific risk signal (e.g. 'tor_or_vpn', 'no_mfa')
    without mutating the underlying FalkorDB graph.
    """
    target_alert = payload.alert_id or "ALT001"
    if payload.investigation_id and payload.investigation_id in INVESTIGATION_CACHE:
        target_alert = INVESTIGATION_CACHE[payload.investigation_id].alert_id

    # Compute baseline risk
    original_risk = compute_risk_from_graph(target_alert)

    # Run simulation
    sim_result = simulate_counterfactual(original_risk, payload.remove_factor)
    return sim_result


# ==============================================================================
# 5. GRAPH VISUALIZATION (CYTOSCAPE.JS)
# ==============================================================================

@app.get("/api/graph", response_model=GraphVisualization)
def get_graph_data(alert_id: Optional[str] = Query(default=None)) -> GraphVisualization:
    """
    Returns graph nodes and edges formatted for the Cytoscape.js frontend canvas.
    If alert_id is provided, focuses on the incident sub-graph.
    """
    target = alert_id or "ALT001"
    return generate_cytoscape_elements(target)


# ==============================================================================
# 6. HUMAN-IN-THE-LOOP GOVERNANCE
# ==============================================================================

@app.post("/api/governance/action")
def decide_governance_action(decision: ActionDecisionPayload) -> Dict[str, Any]:
    """Approves or rejects a proposed response action."""
    entry = {
        "event": f"ACTION_{decision.decision}",
        "action_id": decision.action_id,
        "analyst": decision.analyst_name,
        "comment": decision.comment,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    _record_audit_entry(entry)
    return {
        "status": "success",
        "action_id": decision.action_id,
        "decision": decision.decision,
        "recorded_at": entry["timestamp"],
    }


@app.get("/api/audit-log")
def get_audit_log() -> List[Dict[str, Any]]:
    """Returns the complete append-only audit trail."""
    return _get_audit_entries()


# ==============================================================================
# 7. STATIC FRONTEND SPA SERVING (Vite dist)
# ==============================================================================

DIST_DIR = _ROOT / "frontend" / "dist"
if (DIST_DIR / "index.html").exists():
    if (DIST_DIR / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(DIST_DIR / "assets")), name="assets")

    @app.get("/")
    async def serve_index():
        return FileResponse(DIST_DIR / "index.html")

    @app.get("/{full_path:path}")
    async def serve_spa_fallback(full_path: str):
        if full_path.startswith("api") or full_path in ("docs", "openapi.json", "redoc"):
            raise HTTPException(status_code=404, detail="Not Found")
        file_path = DIST_DIR / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(DIST_DIR / "index.html")
else:
    @app.get("/")
    def root_status():
        return {
            "status": "online",
            "service": "GraphGuard AI — FalkorDB Autonomous Agent",
            "docs": "/docs",
            "endpoints": ["/api/health", "/api/alerts", "/api/investigate", "/api/graph", "/api/what-if"],
        }



# ==============================================================================
# CLI RUNNER
# ==============================================================================

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    logger.info("Starting GraphGuard FastAPI Server on port %d...", port)
    uvicorn.run("backend.main:app", host="0.0.0.0", port=port, reload=True)
