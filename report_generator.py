"""
backend/report_generator.py — Explainable Findings & Visualization Generator.
Track 1: Agents That Act on Connected Data (FalkorDB Hackathon)

Transforms raw investigation data into:
  1. Executive summaries and explainable natural language verdicts.
  2. Full Markdown audit reports with Mermaid attack-path sequence diagrams and KaTeX risk formulas.
  3. Interactive Cytoscape.js graph elements (color-coded, labeled, badged).
  4. Chronological investigation timelines.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_BACKEND_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _BACKEND_DIR.parent
for _p in [str(_BACKEND_DIR), str(_PROJECT_ROOT)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from backend.graph_client import get_graph_client
from backend.schemas import (
    CytoscapeEdge,
    CytoscapeEdgeData,
    CytoscapeNode,
    CytoscapeNodeData,
    GraphVisualization,
    InvestigationReport,
)

# Entity Color Map for SOC Graph Visualization
NODE_COLORS: Dict[str, str] = {
    "User":        "#3B82F6",  # Bright Blue
    "IPAddress":   "#8B5CF6",  # Violet / Purple
    "Device":      "#F97316",  # Orange
    "Server":      "#10B981",  # Emerald Green
    "LoginEvent":  "#06B6D4",  # Cyan
    "Alert":       "#EF4444",  # Crimson Red
    "Evidence":    "#EAB308",  # Amber / Yellow
    "Department":  "#64748B",  # Slate
    "Role":        "#6B7280",  # Gray
    "Permission":  "#A855F7",  # Purple
    "Application": "#EC4899",  # Pink
    "Organization": "#475569", # Dark Slate
}

NODE_SHAPES: Dict[str, str] = {
    "User":        "ellipse",
    "IPAddress":   "round-rectangle",
    "Device":      "rectangle",
    "Server":      "barrel",
    "LoginEvent":  "diamond",
    "Alert":       "hexagon",
    "Evidence":    "tag",
    "Application": "cut-rectangle",
    "Department":  "round-diamond",
    "Organization": "octagon",
}


def generate_executive_verdict(report: InvestigationReport) -> str:
    """Generates a concise, analyst-grade natural language verdict."""
    score_pct = int(report.risk_score * 100)
    top_factors = [f.name.replace("_", " ").title() for f in report.risk_factors if f.contribution > 0][:2]
    factor_str = f" due to {', '.join(top_factors)}" if top_factors else ""

    if report.risk_score >= 0.70:
        return (
            f"CRITICAL THREAT CONFIRMED ({score_pct}% risk score{factor_str}). "
            f"Evidence verified against FalkorDB graph establishes unauthorized lateral movement "
            f"toward sensitive production database assets. Immediate {report.policy_action.value} is required."
        )
    elif report.risk_score >= 0.55:
        return (
            f"ELEVATED RISK INCIDENT ({score_pct}% risk score{factor_str}). "
            f"Anomalous telemetry and unmanaged endpoint indicators were confirmed. "
            f"Recommended policy action is {report.policy_action.value} pending human analyst approval."
        )
    elif report.risk_score >= 0.35:
        return (
            f"BORDERLINE SUSPICIOUS ACTIVITY ({score_pct}% risk score{factor_str}). "
            f"Telemetry exhibits moderate deviation from behavioral baseline. "
            f"Recommended action is {report.policy_action.value}."
        )
    else:
        return (
            f"BENIGN / ROUTINE ACTIVITY VERIFIED ({score_pct}% risk score). "
            f"Activity is consistent with approved baseline behavior, valid credentials, "
            f"and managed infrastructure. Status is {report.policy_action.value}."
        )


def generate_markdown_report(report: InvestigationReport) -> str:
    """Generates an extensive, GitHub-flavored markdown report with provenance and diagrams."""
    md = []
    md.append(f"# 🛡️ Security Investigation Report: `{report.alert_id}`")
    md.append(f"**Investigation ID:** `{report.investigation_id}` | **Status:** `{report.status.value}` | **Confidence:** `{int(report.confidence * 100)}%`\n")

    md.append("## 1. Executive Verdict")
    md.append(f"> **{report.verdict}**\n")

    md.append("## 2. Quantitative Risk Assessment")
    md.append(f"- **Final Risk Score:** `{report.risk_score:.4f}` ({report.risk_label})")
    md.append(f"- **Recommended Policy Action:** `{report.policy_action.value}`")
    md.append(f"- **Primary Target:** `{report.target_entity}`\n")

    md.append(r"### Risk Factor Breakdown ($\sum w_i = 1.0$)")
    md.append("| Factor | Raw Value | Weight | Contribution | Explanation |")
    md.append("|---|---|---|---|---|")
    for f in report.risk_factors:
        raw = json.dumps(f.raw_value) if isinstance(f.raw_value, dict) else str(f.raw_value)
        md.append(f"| `{f.name}` | `{raw}` | `{f.weight:.2f}` | **`{f.contribution:.4f}`** | {f.explanation} |")
    md.append("")

    md.append("## 3. Adaptive Graph Traversal & Query Budget")
    md.append(f"- **Final Traversal Depth:** `{report.hops_explored}` hops")
    md.append(f"- **Query Budget Consumption:** `{report.query_budget_used}` / `{report.query_budget_total}` tool calls (Budget Exhausted: `{report.query_budget_exhausted}`)")
    if report.adaptive_hop_stages:
        md.append("\n### Adaptive Hop Expansion Stages (3 -> 5 -> 8)")
        md.append("| Stage | Depth | Sufficiency Verdict | Paths Discovered | Frontier Nodes | Investigation Rationale |")
        md.append("|---|---|---|---|---|---|")
        for s in report.adaptive_hop_stages:
            verdict_badge = f"`{s.evidence_sufficiency}`"
            frontier_str = ", ".join(f"`{f}`" for f in s.frontier_entities[:3]) if s.frontier_entities else "None"
            md.append(f"| {s.stage} | **{s.hops} hops** | {verdict_badge} | `{s.paths_found}` | {frontier_str} | {s.reason} |")
    md.append("")

    if report.graph_paths:
        md.append(f"## 4. Discovered Multi-Hop Attack Traversal Paths ({len(report.graph_paths)} Unique Chains)")
        md.append("```mermaid")
        md.append("flowchart LR")
        for i, p in enumerate(report.graph_paths[:5], 1):
            nodes = [n.strip() for n in p.split(" -[:") if n.strip()]
            for j in range(len(nodes) - 1):
                clean_src = nodes[j].split("]-> ")[0].replace(":", "_").replace(".", "_").replace("-", "_")
                clean_dst = nodes[j + 1].split("]-> ")[-1].replace(":", "_").replace(".", "_").replace("-", "_")
                md.append(f'    {clean_src}["{nodes[j]}"] --> {clean_dst}["{nodes[j+1]}"]')
        md.append("```\n")

    md.append(f"## 5. Verified Graph Evidence Ledger ({len(report.verified_facts)} Facts)")
    md.append("| # | Provenance Tier | Verified Claim | Graph Sources |")
    md.append("|---|---|---|---|")
    for idx, fact in enumerate(report.verified_facts, 1):
        sources = ", ".join(f"`{s}`" for s in fact.graph_entities) if fact.graph_entities else "`FalkorDB`"
        md.append(f"| {idx} | `{fact.provenance_type.value}` | {fact.description} | {sources} |")
    md.append("")

    if report.hypotheses_evaluated:
        md.append("## 6. Working Hypotheses Validation")
        for h, status in report.hypotheses_evaluated.items():
            icon = "✅" if status == "CONFIRMED" else ("❌" if status == "REFUTED" else "⏳")
            md.append(f"- {icon} **[{status}]** {h}")
        md.append("")

    if report.alternative_explanations:
        md.append("## 7. Alternative Explanations & Blind Spots")
        for alt in report.alternative_explanations:
            md.append(f"- 💡 {alt}")
        md.append("")

    if report.confidence_limitations:
        md.append("## 8. Confidence Limitations")
        for lim in report.confidence_limitations:
            md.append(f"- ⚠️ {lim}")
        md.append("")

    md.append("## 9. Autonomous Tool Audit Trail")
    md.append(f"Total MCP Tool Calls: `{len(report.tool_history)}` | Stop Reason: `{report.stop_reason}`\n")
    md.append("| Step | Tool Name | Latency | Status | Summary |")
    md.append("|---|---|---|---|---|")
    for th in report.tool_history:
        md.append(f"| {th.step} | `{th.tool_name}` | `{th.execution_time_ms}ms` | `{th.result_status}` | {th.summary} |")

    return "\n".join(md)


def generate_cytoscape_elements(alert_id: str, client: Optional[Any] = None) -> GraphVisualization:
    """
    Extracts relevant nodes and edges from FalkorDB connected to the alert
    and packages them for Cytoscape.js rendering.
    """
    db = client or get_graph_client()
    aid = alert_id.strip()

    nodes_dict: Dict[str, CytoscapeNode] = {}
    edges_list: List[CytoscapeEdge] = []

    def add_node(node_id: str, label: str, name: str, props: Dict[str, Any], badge: Optional[str] = None):
        if node_id not in nodes_dict:
            color = NODE_COLORS.get(label, "#94A3B8")
            shape = NODE_SHAPES.get(label, "ellipse")
            nodes_dict[node_id] = CytoscapeNode(
                data=CytoscapeNodeData(
                    id=node_id,
                    label=label,
                    name=name,
                    type=label,
                    color=color,
                    shape=shape,
                    badge=badge,
                    properties=props,
                )
            )

    # 1. Add Alert Node
    alert_rows = db.query("MATCH (a:Alert {alert_id: $aid}) RETURN a", {"aid": aid})
    if alert_rows:
        al = alert_rows[0].get("a", {})
        add_node(f"Alert:{aid}", "Alert", al.get("title", aid), al, badge=al.get("severity", "").upper())

    # 2. Add 1st-hop and 2nd-hop connected nodes & edges
    conns = db.query("""
    MATCH (a:Alert {alert_id: $aid})-[r]->(t)
    RETURN type(r) AS rel, labels(t) AS labels, t
    """, {"aid": aid})

    for c in conns:
        t = c.get("t", {})
        labels = c.get("labels", [])
        lbl = labels[0] if labels else t.get("label", "Entity")
        id_field = {
            "User": "user_id", "IPAddress": "ip_id", "Device": "device_id",
            "Server": "server_id", "LoginEvent": "event_id", "Evidence": "evidence_id",
        }.get(lbl, "id")
        tid = t.get(id_field, t.get("address", t.get("hostname", t.get("username", "t"))))
        t_key = f"{lbl}:{tid}"
        name = t.get("username", t.get("address", t.get("hostname", t.get("description", tid))))

        add_node(t_key, lbl, str(name)[:30], t)
        edges_list.append(CytoscapeEdge(
            data=CytoscapeEdgeData(
                id=f"Alert:{aid}->{t_key}",
                source=f"Alert:{aid}",
                target=t_key,
                label=c.get("rel", "CONNECTED_TO"),
                color="#EF4444",
                properties={"rel": c.get("rel")},
            )
        ))

        # 2nd hop from User or LoginEvent
        if lbl in ("User", "LoginEvent"):
            sub_conns = db.query(f"""
            MATCH (n:{lbl} {{{id_field}: $val}})-[r2]->(m)
            RETURN type(r2) AS rel, labels(m) AS labels, m
            """, {"val": tid})
            for sc in sub_conns:
                m = sc.get("m", {})
                m_labels = sc.get("labels", [])
                m_lbl = m_labels[0] if m_labels else m.get("label", "Entity")
                m_id_field = {
                    "User": "user_id", "IPAddress": "ip_id", "Device": "device_id",
                    "Server": "server_id", "LoginEvent": "event_id",
                }.get(m_lbl, "id")
                mid = m.get(m_id_field, m.get("address", m.get("hostname", "m")))
                m_key = f"{m_lbl}:{mid}"
                m_name = m.get("hostname", m.get("address", m.get("username", mid)))

                add_node(m_key, m_lbl, str(m_name)[:30], m)
                edges_list.append(CytoscapeEdge(
                    data=CytoscapeEdgeData(
                        id=f"{t_key}->{m_key}",
                        source=t_key,
                        target=m_key,
                        label=sc.get("rel", "CONNECTED_TO"),
                        color="#6366F1",
                        properties={"rel": sc.get("rel")},
                    )
                ))

    return GraphVisualization(
        nodes=list(nodes_dict.values()),
        edges=edges_list,
    )
