"""
tests/test_investigation.py — Verification of Autonomous Multi-Hop Investigation Agent & Brain.
Track 1: Agents That Act on Connected Data (FalkorDB Hackathon)

Verifies:
  1. Autonomous tool dispatch & cognitive planning loop.
  2. Adaptive Multi-Hop traversal (3 -> 5 -> 8 hops).
  3. Evidence sufficiency evaluation (INSUFFICIENT -> TRAIL_CONTINUES -> SUFFICIENT).
  4. Early stopping on routine benign activity (ALT002).
  5. Configured max_hops boundary enforcement.
  6. Query budget limit enforcement & exhaustion guard.
  7. Deterministic 8-factor risk scoring engine & counterfactual What-If simulation.
  8. Natural language verdict & Cytoscape graph generation.
"""
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


def test_adaptive_multi_hop_investigation():
    agent = InvestigationAgent(max_hops=8, max_tool_calls=25)
    req = InvestigationRequestPayload(
        alert_id="ALT001",
        adaptive_hops_enabled=True,
        initial_hops=3,
        intermediate_hops=5,
        deep_hops=8,
        max_hops=8,
        query_budget=20,
    )
    report = agent.run_investigation(req)

    assert report.investigation_id.startswith("inv-")
    assert report.risk_score >= 0.70, f"Expected critical score >= 0.70, got {report.risk_score}"
    assert report.risk_label == "CRITICAL"
    assert report.policy_action.value == "ESCALATE"
    assert report.hops_explored == 8, f"Expected 8 hops reached, got {report.hops_explored}"
    assert len(report.adaptive_hop_stages) == 3, f"Expected 3 expansion stages, got {len(report.adaptive_hop_stages)}"

    # Stage evaluations
    assert report.adaptive_hop_stages[0].evidence_sufficiency == "INSUFFICIENT"
    assert report.adaptive_hop_stages[1].evidence_sufficiency == "TRAIL_CONTINUES"
    assert report.adaptive_hop_stages[2].evidence_sufficiency == "SUFFICIENT"

    print(f"  [PASS] Full Adaptive Multi-Hop Investigation passed: {report.hops_explored} hops across {len(report.adaptive_hop_stages)} stages.")


def test_benign_early_stop():
    agent = InvestigationAgent(max_hops=8, max_tool_calls=20)
    req = InvestigationRequestPayload(
        alert_id="ALT002",
        adaptive_hops_enabled=True,
        initial_hops=3,
        intermediate_hops=5,
        deep_hops=8,
    )
    report = agent.run_investigation(req)

    assert report.hops_explored == 3, f"Expected benign alert to stop at 3 hops, got {report.hops_explored}"
    assert len(report.adaptive_hop_stages) == 1
    assert report.adaptive_hop_stages[0].evidence_sufficiency == "SUFFICIENT"
    assert report.risk_score < 0.35
    print("  [PASS] Benign activity early stopping verified (stopped at 3 hops).")


def test_max_hops_ceiling_guard():
    agent = InvestigationAgent(max_hops=5, max_tool_calls=20)
    req = InvestigationRequestPayload(
        alert_id="ALT001",
        adaptive_hops_enabled=True,
        initial_hops=3,
        intermediate_hops=5,
        deep_hops=8,
        max_hops=5,
    )
    report = agent.run_investigation(req)

    assert report.hops_explored == 5, f"Expected max 5 hops, got {report.hops_explored}"
    assert len(report.adaptive_hop_stages) == 2
    print("  [PASS] Configured max_hops ceiling enforced at 5 hops.")


def test_query_budget_guard():
    agent = InvestigationAgent(max_hops=8, max_tool_calls=4)
    req = InvestigationRequestPayload(
        alert_id="ALT001",
        query_budget=4,
        max_tool_calls=4,
    )
    report = agent.run_investigation(req)

    assert report.query_budget_used == 4
    assert report.query_budget_exhausted is True
    assert "Query budget limit reached" in report.stop_reason
    print("  [PASS] Query budget guard verified (stopped safely at exactly 4 tool calls).")


def test_risk_engine_and_counterfactual():
    risk = compute_risk_from_graph("ALT001")
    assert risk.score >= 0.70
    assert risk.label == "CRITICAL"

    # Simulate counterfactual removal of tor_or_vpn factor
    what_if = simulate_counterfactual(risk, "tor_or_vpn")
    assert what_if.simulated_score < what_if.original_score
    assert what_if.delta_score < 0
    print(f"  [PASS] Risk Engine & What-If simulation verified: {what_if.original_score} -> {what_if.simulated_score} (delta: {what_if.delta_score}).")


def test_report_generation():
    agent = InvestigationAgent(max_hops=8, max_tool_calls=20)
    report = agent.run_investigation(InvestigationRequestPayload(alert_id="ALT001"))
    
    md = generate_markdown_report(report)
    assert "# 🛡️ Security Investigation Report" in md
    assert "## 3. Adaptive Graph Traversal & Query Budget" in md
    assert "Adaptive Hop Expansion Stages" in md
    
    cy = generate_cytoscape_elements("ALT001")
    assert len(cy.nodes) >= 5
    assert len(cy.edges) >= 4
    print(f"  [PASS] Explainable Markdown & Cytoscape graph verified ({len(md)} chars markdown, {len(cy.nodes)} nodes).")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  PHASE 5: INVESTIGATION AGENT TEST SUITE")
    print("=" * 60)
    test_adaptive_multi_hop_investigation()
    test_benign_early_stop()
    test_max_hops_ceiling_guard()
    test_query_budget_guard()
    test_risk_engine_and_counterfactual()
    test_report_generation()
    print("=" * 60)
    print("  ALL INVESTIGATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 60 + "\n")
