import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent
_BACKEND = _ROOT / "backend"
for _p in [str(_BACKEND), str(_ROOT)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from backend.agent import InvestigationAgent
from backend.schemas import InvestigationRequestPayload
from backend.risk_engine import compute_risk_from_graph, simulate_counterfactual
from backend.report_generator import generate_markdown_report, generate_cytoscape_elements
from fastapi.testclient import TestClient
from backend.main import app

def test_full_pipeline():
    print("\n" + "=" * 76)
    print("  GRAPHGUARD BACKEND INTEGRATION TEST SUITE")
    print("=" * 76)

    # 1. Autonomous Agent Test
    print("\n[1] Testing Autonomous InvestigationAgent (Multi-hop tool selection)...")
    agent = InvestigationAgent(max_hops=3, max_tool_calls=15)
    req = InvestigationRequestPayload(alert_id="ALT001")
    report = agent.run_investigation(req)
    print(f"    Investigation ID : {report.investigation_id}")
    print(f"    Risk Score       : {report.risk_score} [{report.risk_label}] -> {report.policy_action.value}")
    print(f"    Verified Facts   : {len(report.verified_facts)}")
    print(f"    Multi-Hop Paths  : {len(report.graph_paths)}")
    print(f"    Tool Call Count  : {len(report.tool_history)}")
    print(f"    Verdict          : {report.verdict[:80]}...")

    # 2. Risk Engine & Counterfactual Test
    print("\n[2] Testing Deterministic 8-Factor Risk Engine & What-If Simulation...")
    risk = compute_risk_from_graph("ALT001")
    print(f"    Baseline Risk    : {risk.score} [{risk.label}] -> {risk.policy_action.value}")
    for f in risk.factors:
        if f.contribution > 0:
            print(f"      • {f.name:<20}: contrib={f.contribution:.4f} ({f.explanation})")

    what_if = simulate_counterfactual(risk, "tor_or_vpn")
    print(f"    What-If (Remove tor_or_vpn):")
    print(f"      Score : {what_if.original_score} -> {what_if.simulated_score}")
    print(f"      Action: {what_if.original_action} -> {what_if.simulated_action}")
    print(f"      Impact: {what_if.explanation}")

    # 3. Report Generator & Visualization Test
    print("\n[3] Testing Report Generator & Cytoscape Data...")
    md = generate_markdown_report(report)
    print(f"    Markdown Report  : Generated {len(md)} characters successfully.")
    cy = generate_cytoscape_elements("ALT001")
    print(f"    Cytoscape Graph  : {len(cy.nodes)} nodes, {len(cy.edges)} edges formatted.")

    # 4. FastAPI Endpoints Test
    print("\n[4] Testing FastAPI Endpoints (TestClient)...")
    client = TestClient(app)
    h = client.get("/api/health")
    print(f"    GET /api/health           : {h.status_code} (status={h.json().get('status')})")
    
    alerts = client.get("/api/alerts")
    print(f"    GET /api/alerts           : {alerts.status_code} ({len(alerts.json())} alerts listed)")

    inv = client.post("/api/investigate", json={"alert_id": "ALT001"})
    print(f"    POST /api/investigate     : {inv.status_code} (verdict received)")

    wf = client.post("/api/what-if", json={"alert_id": "ALT001", "remove_factor": "no_mfa"})
    print(f"    POST /api/what-if         : {wf.status_code} (delta={wf.json().get('delta_score')})")

    g = client.get("/api/graph?alert_id=ALT001")
    print(f"    GET /api/graph            : {g.status_code} ({len(g.json().get('nodes', []))} nodes)")

    # 5. Dedicated Adaptive Multi-Hop & Budget Tests
    print("\n[5] Testing Adaptive Multi-Hop Expansion (3 -> 5 -> 8) & Budget Guards...")
    agent_adaptive = InvestigationAgent(max_hops=8, max_tool_calls=25)

    # Test 5A: Full adaptive expansion on high-risk alert ALT001
    rep_full = agent_adaptive.run_investigation(InvestigationRequestPayload(
        alert_id="ALT001",
        adaptive_hops_enabled=True,
        initial_hops=3,
        intermediate_hops=5,
        deep_hops=8,
        max_hops=8,
        query_budget=20,
    ))
    print(f"    [5A] Full Adaptive Run (ALT001):")
    print(f"         Final Hops Reached    : {rep_full.hops_explored}")
    print(f"         Stages Recorded       : {len(rep_full.adaptive_hop_stages)}")
    for s in rep_full.adaptive_hop_stages:
        print(f"           Stage {s.stage}: {s.hops} hops | {s.evidence_sufficiency:<15} | Paths={s.paths_found:<2} | Frontier={s.frontier_entities[:2]}")
    assert rep_full.hops_explored == 8, f"Expected 8 hops, got {rep_full.hops_explored}"
    assert len(rep_full.adaptive_hop_stages) == 3, f"Expected 3 stages, got {len(rep_full.adaptive_hop_stages)}"
    assert rep_full.adaptive_hop_stages[0].evidence_sufficiency == "INSUFFICIENT"
    assert rep_full.adaptive_hop_stages[1].evidence_sufficiency == "TRAIL_CONTINUES"
    assert rep_full.adaptive_hop_stages[2].evidence_sufficiency == "SUFFICIENT"

    # Test 5B: Early stop on benign routine alert ALT002 (should stop at initial 3 hops)
    rep_benign = agent_adaptive.run_investigation(InvestigationRequestPayload(
        alert_id="ALT002",
        adaptive_hops_enabled=True,
        initial_hops=3,
        intermediate_hops=5,
        deep_hops=8,
        max_hops=8,
    ))
    print(f"\n    [5B] Benign Activity Early Stop (ALT002):")
    print(f"         Final Hops Reached    : {rep_benign.hops_explored}")
    print(f"         Stages Recorded       : {len(rep_benign.adaptive_hop_stages)}")
    print(f"         Stage 1 Sufficiency   : {rep_benign.adaptive_hop_stages[0].evidence_sufficiency}")
    assert rep_benign.hops_explored == 3, f"Expected 3 hops, got {rep_benign.hops_explored}"
    assert len(rep_benign.adaptive_hop_stages) == 1, f"Expected 1 stage, got {len(rep_benign.adaptive_hop_stages)}"
    assert rep_benign.adaptive_hop_stages[0].evidence_sufficiency == "SUFFICIENT"

    # Test 5C: Configured max_hops boundary enforcement (max_hops=5)
    rep_capped = agent_adaptive.run_investigation(InvestigationRequestPayload(
        alert_id="ALT001",
        adaptive_hops_enabled=True,
        initial_hops=3,
        intermediate_hops=5,
        deep_hops=8,
        max_hops=5,
    ))
    print(f"\n    [5C] Max Hops Boundary Capped at 5 (ALT001):")
    print(f"         Final Hops Reached    : {rep_capped.hops_explored}")
    print(f"         Stages Recorded       : {len(rep_capped.adaptive_hop_stages)}")
    assert rep_capped.hops_explored == 5, f"Expected 5 hops max, got {rep_capped.hops_explored}"
    assert len(rep_capped.adaptive_hop_stages) == 2, f"Expected 2 stages, got {len(rep_capped.adaptive_hop_stages)}"

    # Test 5D: Query budget exhaustion guard (query_budget=4)
    rep_budget = agent_adaptive.run_investigation(InvestigationRequestPayload(
        alert_id="ALT001",
        query_budget=4,
        max_tool_calls=4,
    ))
    print(f"\n    [5D] Query Budget Limit Guard (Budget=4):")
    print(f"         Budget Limit          : {rep_budget.query_budget_total}")
    print(f"         Tool Calls Used       : {rep_budget.query_budget_used}")
    print(f"         Budget Exhausted Flag : {rep_budget.query_budget_exhausted}")
    print(f"         Stop Reason           : {rep_budget.stop_reason}")
    assert rep_budget.query_budget_used == 4, f"Expected 4 tool calls, got {rep_budget.query_budget_used}"
    assert rep_budget.query_budget_exhausted is True, "Expected query_budget_exhausted to be True"

    print("\n" + "=" * 76)
    print("  ALL BACKEND MODULES & ADAPTIVE HOP EXPANSIONS VERIFIED AND OPERATIONAL!")
    print("=" * 76 + "\n")

if __name__ == "__main__":
    test_full_pipeline()
