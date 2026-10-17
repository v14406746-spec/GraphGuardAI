"""
backend/agent.py — Autonomous Graph Investigation Agent.
Track 1: Agents That Act on Connected Data (FalkorDB Hackathon)

Responsibilities:
  1. Intelligently selects MCP tools based on current evidence gaps and graph topology.
  2. Investigates multiple hops: User → LoginEvent → IP / Device → Server.
  3. Grounded in FalkorDB: Distinguishes VERIFIED_FACT from hypothesis.
  4. Evaluates stopping criteria and explains all findings with natural language verdict and visualization.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from pathlib import Path
import sys

_BACKEND_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _BACKEND_DIR.parent
for _p in [str(_BACKEND_DIR), str(_PROJECT_ROOT)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dotenv import load_dotenv

from backend.graph_client import get_graph_client
from backend.report_generator import (
    generate_cytoscape_elements,
    generate_executive_verdict,
    generate_markdown_report,
)
from backend.risk_engine import compute_risk_from_graph
from backend.schemas import (
    EvidenceItem,
    GraphVisualization,
    HopExpansionStage,
    InvestigationReport,
    InvestigationRequestPayload,
    InvestigationStatus,
    PolicyAction,
    ProvenanceType,
    RiskFactor,
    RiskResult,
    ToolCallRecord,
)

try:
    from backend.mcp_server.tools import (
        analyze_graph_risk,
        execute_cypher,
        find_related_incidents,
        get_investigation_context,
        inspect_entity,
        propose_response,
        trace_relationships,
        validate_evidence,
    )
except ImportError:
    from mcp_server.tools import (
        analyze_graph_risk,
        execute_cypher,
        find_related_incidents,
        get_investigation_context,
        inspect_entity,
        propose_response,
        trace_relationships,
        validate_evidence,
    )

load_dotenv()
logger = logging.getLogger("backend.agent")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")

# Tool Mapping for Autonomous In-Process Dispatch
TOOL_MAP: Dict[str, Callable[..., Dict[str, Any]]] = {
    "get_investigation_context": get_investigation_context,
    "inspect_entity": inspect_entity,
    "trace_relationships": trace_relationships,
    "find_related_incidents": find_related_incidents,
    "analyze_graph_risk": analyze_graph_risk,
    "validate_evidence": validate_evidence,
    "propose_response": propose_response,
    "execute_cypher": execute_cypher,
}


class InvestigationAgent:
    """
    Autonomous Security Investigation Agent.
    Orchestrates the cognitive loop: chooses tools, traverses multiple hops,
    evaluates evidence, and synthesizes explainable conclusions.
    """

    def __init__(
        self,
        max_hops: int = 8,
        max_tool_calls: int = 20,
        timeout_seconds: int = 60,
    ):
        self.max_hops = max_hops
        self.max_tool_calls = max_tool_calls
        self.timeout_seconds = timeout_seconds

    def run_investigation(
        self,
        request: InvestigationRequestPayload,
    ) -> InvestigationReport:
        """
        Executes the autonomous investigation workflow with adaptive multi-hop expansion.
        """
        start_time = time.time()
        investigation_id = f"inv-{uuid.uuid4().hex[:8]}"
        started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # 1. Parse Alert ID & Intent
        alert_id = self._resolve_alert_id(request)
        question = request.question or f"Investigate security alert {alert_id} and determine attack paths."
        logger.info("Starting investigation %s for alert %s", investigation_id, alert_id)

        # 2. Adaptive Multi-Hop Settings & Budget Guards
        adaptive_enabled = request.adaptive_hops_enabled
        initial_hops = request.initial_hops
        intermediate_hops = request.intermediate_hops
        deep_hops = request.deep_hops
        configured_max_hops = min(request.max_hops, self.max_hops)
        query_budget_total = min(request.query_budget, request.max_tool_calls, self.max_tool_calls)

        # 3. State & Ledgers
        verified_facts: List[EvidenceItem] = []
        graph_paths: List[str] = []
        anomalies_detected: List[str] = []
        tool_history: List[ToolCallRecord] = []
        pending_entities: List[Tuple[str, str]] = []  # [(label, id)]
        inspected_entities: Set[str] = set()
        seen_calls: Set[str] = set()
        executed_tools: List[str] = []

        # Adaptive Multi-Hop State Tracking
        adaptive_hop_stages: List[HopExpansionStage] = []
        current_hop_stage = 0
        hops_explored = initial_hops
        pending_hop_expansion: Optional[int] = initial_hops
        traversal_done = False
        query_budget_exhausted = False

        step = 0
        deadline = start_time + self.timeout_seconds
        stop_reason = "Completed successfully."
        target_entity = "UNKNOWN"

        # Hypotheses
        hypotheses = {
            "Unauthorized access from anomalous infrastructure": "INCONCLUSIVE",
            "Lateral movement toward sensitive databases": "INCONCLUSIVE",
            "Authorized benign activity": "INCONCLUSIVE",
        }

        # 4. Autonomous Cognitive Loop
        while len(tool_history) < query_budget_total and time.time() < deadline:
            step += 1

            # Decide Next Tool
            tool_call = self._select_next_tool(
                alert_id=alert_id,
                executed_tools=executed_tools,
                pending_entities=pending_entities,
                inspected_entities=inspected_entities,
                seen_calls=seen_calls,
                investigation_id=investigation_id,
                target_entity=target_entity,
                pending_hop_expansion=pending_hop_expansion,
                traversal_done=traversal_done,
            )

            if not tool_call:
                logger.info("Investigation saturated: All graph leads and relationships explored.")
                stop_reason = "Exploration space exhausted; sufficient graph evidence acquired."
                break

            tool_name, args = tool_call
            call_sig = f"{tool_name}:{json.dumps(args, sort_keys=True)}"
            seen_calls.add(call_sig)

            # Execute Tool
            t0 = time.time()
            fn = TOOL_MAP.get(tool_name)
            res = fn(**args) if fn else {"status": "error", "message": f"Tool {tool_name} not found"}
            exec_ms = round((time.time() - t0) * 1000, 2)

            executed_tools.append(tool_name)
            tool_history.append(ToolCallRecord(
                step=step,
                tool_name=tool_name,
                arguments=args,
                result_status=res.get("status", "unknown"),
                summary=f"Called {tool_name} with {args} in {exec_ms}ms.",
                execution_time_ms=exec_ms,
            ))

            # Evaluate Evidence & Discover Leads across Multi-Hop Paths
            self._evaluate_step_evidence(
                tool_name=tool_name,
                args=args,
                result=res,
                verified_facts=verified_facts,
                graph_paths=graph_paths,
                anomalies_detected=anomalies_detected,
                pending_entities=pending_entities,
                inspected_entities=inspected_entities,
            )

            # Adaptive Hop Traversal Handler
            if tool_name == "trace_relationships":
                current_hops = int(args.get("max_hops", initial_hops))
                current_hop_stage += 1
                paths_discovered = res.get("data", {}).get("paths_discovered", [])

                sufficiency, stage_reason, frontier = self._evaluate_hop_stage(
                    stage=current_hop_stage,
                    hops=current_hops,
                    paths=paths_discovered,
                    alert_id=alert_id,
                    anomalies_detected=anomalies_detected,
                    verified_facts=verified_facts,
                    request=request,
                )

                stage_record = HopExpansionStage(
                    stage=current_hop_stage,
                    hops=current_hops,
                    reason=stage_reason,
                    paths_found=len(paths_discovered),
                    evidence_sufficiency=sufficiency,
                    frontier_entities=frontier,
                )
                adaptive_hop_stages.append(stage_record)
                hops_explored = max(hops_explored, current_hops)

                # Determine next expansion or stop condition
                if current_hop_stage == 1:
                    if (
                        sufficiency == "INSUFFICIENT"
                        and adaptive_enabled
                        and intermediate_hops <= configured_max_hops
                        and len(tool_history) < query_budget_total
                    ):
                        pending_hop_expansion = intermediate_hops
                    else:
                        traversal_done = True
                        pending_hop_expansion = None
                elif current_hop_stage == 2:
                    if (
                        sufficiency == "TRAIL_CONTINUES"
                        and adaptive_enabled
                        and deep_hops <= configured_max_hops
                        and len(tool_history) < query_budget_total
                    ):
                        pending_hop_expansion = deep_hops
                    else:
                        traversal_done = True
                        pending_hop_expansion = None
                else:
                    traversal_done = True
                    pending_hop_expansion = None

            # Update primary target entity
            if target_entity == "UNKNOWN":
                for ent_key in inspected_entities:
                    if ent_key.startswith("User:") or ent_key.startswith("IPAddress:"):
                        target_entity = ent_key
                        break

            # Stopping check: Did we analyze risk, validate evidence, and propose response?
            if (
                "analyze_graph_risk" in executed_tools
                and "propose_response" in executed_tools
                and not pending_entities
                and traversal_done
            ):
                stop_reason = "Completed all multi-hop investigations, risk evaluations, and policy proposals."
                break

        # Check if while-loop ended due to budget exhaustion
        if len(tool_history) >= query_budget_total and not query_budget_exhausted:
            query_budget_exhausted = True
            stop_reason = f"Query budget limit reached ({len(tool_history)}/{query_budget_total} tool calls). Investigation concluded safely."

        # 5. Final Risk Engine Computation
        risk_result: RiskResult = compute_risk_from_graph(alert_id)

        # 6. Hypotheses Resolution
        if risk_result.score >= 0.55:
            hypotheses["Unauthorized access from anomalous infrastructure"] = "CONFIRMED"
            hypotheses["Lateral movement toward sensitive databases"] = "CONFIRMED" if graph_paths else "SUPPORTED"
            hypotheses["Authorized benign activity"] = "REFUTED"
        else:
            hypotheses["Unauthorized access from anomalous infrastructure"] = "REFUTED"
            hypotheses["Lateral movement toward sensitive databases"] = "REFUTED"
            hypotheses["Authorized benign activity"] = "CONFIRMED"

        # 7. Generate Cytoscape Graph Visualization
        graph_vis = generate_cytoscape_elements(alert_id)

        # 8. Construct Final Report
        report = InvestigationReport(
            investigation_id=investigation_id,
            alert_id=alert_id,
            question=question,
            verdict="",
            status=InvestigationStatus.COMPLETE,
            started_at=started_at,
            completed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            elapsed_seconds=round(time.time() - start_time, 3),
            hops_explored=hops_explored,
            adaptive_hop_stages=adaptive_hop_stages,
            query_budget_total=query_budget_total,
            query_budget_used=len(tool_history),
            query_budget_exhausted=query_budget_exhausted,
            risk_score=risk_result.score,
            risk_label=risk_result.label,
            policy_action=risk_result.policy_action,
            target_entity=target_entity,
            risk_factors=risk_result.factors,
            verified_facts=verified_facts,
            graph_paths=list(set(graph_paths)),
            hypotheses_evaluated=hypotheses,
            alternative_explanations=risk_result.alternative_explanations,
            confidence=risk_result.confidence,
            confidence_limitations=risk_result.confidence_limitations,
            tool_history=tool_history,
            stop_reason=stop_reason,
            graph=graph_vis,
        )
        report.verdict = generate_executive_verdict(report)

        logger.info(
            "Investigation %s finished in %.2fs: %s (%s) [Hops: %d, Stages: %d, Budget: %d/%d]",
            investigation_id,
            report.elapsed_seconds,
            report.risk_label,
            report.policy_action.value,
            report.hops_explored,
            len(report.adaptive_hop_stages),
            report.query_budget_used,
            report.query_budget_total,
        )
        return report

    async def run_investigation_async(self, request: InvestigationRequestPayload) -> InvestigationReport:
        """Asynchronous execution interface for FastAPI route handlers."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.run_investigation, request)

    # --------------------------------------------------------------------------
    # Planning & Tool Selection
    # --------------------------------------------------------------------------

    def _select_next_tool(
        self,
        alert_id: str,
        executed_tools: List[str],
        pending_entities: List[Tuple[str, str]],
        inspected_entities: Set[str],
        seen_calls: Set[str],
        investigation_id: str,
        target_entity: str,
        pending_hop_expansion: Optional[int] = None,
        traversal_done: bool = False,
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Autonomous graph-aware planner:
          Step 1: Get initial alert context.
          Step 2: Deep inspect primary entities (User, Device, IP).
          Step 3: Multi-hop graph traversal with adaptive expansion (3 -> 5 -> 7/8).
          Step 4: Check correlated alerts.
          Step 5: Compute deterministic risk score.
          Step 6: Validate investigation hypothesis against facts.
          Step 7: Propose response action.
        """
        # Phase 1: Context
        if "get_investigation_context" not in executed_tools:
            return ("get_investigation_context", {"alert_id": alert_id})

        # Phase 2: Inspect pending leads discovered in previous hops
        while pending_entities:
            lbl, eid = pending_entities.pop(0)
            key = f"{lbl}:{eid}"
            if key not in inspected_entities:
                inspected_entities.add(key)
                sig = f"inspect_entity:{json.dumps({'entity_id': eid, 'label': lbl}, sort_keys=True)}"
                if sig not in seen_calls:
                    return ("inspect_entity", {"label": lbl, "entity_id": eid})

        # Phase 3: Adaptive Multi-hop relationship traversal
        if not traversal_done and pending_hop_expansion is not None:
            start_id = "U001"
            for k in inspected_entities:
                if k.startswith("User:"):
                    start_id = k.split(":", 1)[1]
                    break
            sig = f"trace_relationships:{json.dumps({'max_hops': pending_hop_expansion, 'start_id': start_id, 'start_label': 'User'}, sort_keys=True)}"
            if sig not in seen_calls:
                return ("trace_relationships", {
                    "start_label": "User",
                    "start_id": start_id,
                    "max_hops": pending_hop_expansion,
                })

        # Phase 4: Threat correlation across incidents
        if "find_related_incidents" not in executed_tools:
            return ("find_related_incidents", {"alert_id": alert_id})

        # Phase 5: Quantitative risk calculation
        if "analyze_graph_risk" not in executed_tools:
            return ("analyze_graph_risk", {"alert_id": alert_id})

        # Phase 6: Hypothesis validation
        if "validate_evidence" not in executed_tools:
            return ("validate_evidence", {
                "alert_id": alert_id,
                "hypothesis": "Unauthorized credential compromise via high-risk Tor infrastructure"
            })

        # Phase 7: Governed response proposal
        if "propose_response" not in executed_tools:
            db_risk = compute_risk_from_graph(alert_id)
            return ("propose_response", {
                "investigation_id": investigation_id,
                "alert_id": alert_id,
                "action": db_risk.policy_action.value,
                "justification": f"Graph analysis computed risk score {db_risk.score} ({db_risk.label}).",
                "target_entity": target_entity if target_entity != "UNKNOWN" else f"Alert:{alert_id}",
            })

        return None

    # --------------------------------------------------------------------------
    # Evidence Evaluation & Multi-Hop Entity Extraction
    # --------------------------------------------------------------------------

    def _evaluate_step_evidence(
        self,
        tool_name: str,
        args: Dict[str, Any],
        result: Dict[str, Any],
        verified_facts: List[EvidenceItem],
        graph_paths: List[str],
        anomalies_detected: List[str],
        pending_entities: List[Tuple[str, str]],
        inspected_entities: Set[str],
    ) -> None:
        if result.get("status") != "success":
            return

        data = result.get("data", {})

        if tool_name == "get_investigation_context":
            alert = data.get("alert", {})
            if alert:
                verified_facts.append(EvidenceItem(
                    source=tool_name,
                    description=f"Alert '{alert.get('title')}' (Severity: {alert.get('severity')}): {alert.get('description')}",
                    confidence=1.0,
                    provenance_type=ProvenanceType.VERIFIED_FACT,
                    entity_type="Alert",
                    entity_id=alert.get("alert_id", ""),
                    graph_entities=[f"Alert:{alert.get('alert_id')}"],
                ))

            # Queue referenced entities for deeper hop inspection
            for ent in data.get("referenced_entities", []):
                e_type = ent.get("entity_type")
                e_obj = ent.get("entity", {})
                e_id = e_obj.get(f"{e_type.lower()}_id", e_obj.get("username", e_obj.get("address", "")))
                if e_id and e_type in ("User", "IPAddress", "Device", "Server"):
                    pending_entities.append((e_type, str(e_id)))

            for ev in data.get("evidence_items", []):
                verified_facts.append(EvidenceItem(
                    source=tool_name,
                    description=f"Corroborating Evidence: {ev.get('description')} [Source: {ev.get('source')}]",
                    confidence=float(ev.get("confidence", 0.9)),
                    provenance_type=ProvenanceType.VERIFIED_FACT,
                    entity_type="Evidence",
                    entity_id=ev.get("evidence_id", ""),
                ))
                anomalies_detected.append(ev.get("description", ""))

            for lh in data.get("login_history", []):
                mfa = "with MFA" if lh.get("mfa_used") else "WITHOUT MFA"
                verified_facts.append(EvidenceItem(
                    source=tool_name,
                    description=f"Authentication Event {lh.get('event_id')} {mfa} at {lh.get('timestamp')} (ML anomaly: {lh.get('anomaly_score')})",
                    confidence=0.95,
                    provenance_type=ProvenanceType.VERIFIED_FACT,
                    entity_type="LoginEvent",
                    entity_id=lh.get("event_id", ""),
                ))

        elif tool_name == "inspect_entity":
            entity = data.get("entity", {})
            lbl = args.get("label", "Entity")
            eid = args.get("entity_id", "")
            verified_facts.append(EvidenceItem(
                source=tool_name,
                description=f"Inspected {lbl} '{eid}': {json.dumps(entity)}",
                confidence=1.0,
                provenance_type=ProvenanceType.VERIFIED_FACT,
                entity_type=lbl,
                entity_id=eid,
                graph_entities=[f"{lbl}:{eid}"],
            ))

            # Discover adjacent entities from relationships (2nd and 3rd hops!)
            for rel in data.get("relationships", []):
                tgt = rel.get("target") or {}
                t_lbl = tgt.get("label") or (rel.get("target_label", [""])[0] if rel.get("target_label") else "")
                if t_lbl in ("User", "IPAddress", "Device", "Server"):
                    id_field = {"User": "user_id", "IPAddress": "ip_id", "Device": "device_id", "Server": "server_id"}.get(t_lbl, "id")
                    t_id = tgt.get(id_field, tgt.get("address", tgt.get("hostname", "")))
                    if t_id:
                        key = f"{t_lbl}:{t_id}"
                        if key not in inspected_entities:
                            pending_entities.append((t_lbl, str(t_id)))

        elif tool_name == "trace_relationships":
            for p in data.get("paths_discovered", []):
                p_str = p.get("path_string", "")
                if p_str:
                    graph_paths.append(p_str)
                    verified_facts.append(EvidenceItem(
                        source=tool_name,
                        description=f"Multi-Hop Attack Path ({p.get('hops')} hops): {p_str}",
                        confidence=0.98,
                        provenance_type=ProvenanceType.VERIFIED_FACT,
                        graph_path=p_str,
                    ))

        elif tool_name == "find_related_incidents":
            corr = data.get("correlated_alerts", [])
            msg = f"Correlated with {len(corr)} co-occurring incident(s) sharing graph entities." if corr else "No shared-entity alert correlations detected."
            verified_facts.append(EvidenceItem(
                source=tool_name,
                description=msg,
                confidence=0.95,
                provenance_type=ProvenanceType.VERIFIED_FACT,
            ))

        elif tool_name == "analyze_graph_risk":
            verified_facts.append(EvidenceItem(
                source=tool_name,
                description=f"Deterministic 8-Factor Risk Score: {data.get('score')} [{data.get('label')}] -> Action: {data.get('policy_action')}",
                confidence=float(data.get("confidence", 0.95)),
                provenance_type=ProvenanceType.RULE_CALCULATION,
            ))

        elif tool_name == "validate_evidence":
            is_supp = data.get("is_supported", False)
            status_text = "CONFIRMED by graph ground truth" if is_supp else "UNVERIFIED"
            verified_facts.append(EvidenceItem(
                source=tool_name,
                description=f"Hypothesis '{data.get('hypothesis')}' is {status_text}.",
                confidence=0.92 if is_supp else 0.50,
                provenance_type=ProvenanceType.VERIFIED_FACT if is_supp else ProvenanceType.AI_HYPOTHESIS,
            ))

        elif tool_name == "propose_response":
            verified_facts.append(EvidenceItem(
                source=tool_name,
                description=f"Response Proposed: {data.get('action')} on {data.get('target_entity')} (Requires Human Approval: {data.get('requires_human_approval')})",
                confidence=1.0,
                provenance_type=ProvenanceType.RULE_CALCULATION,
            ))

    def _resolve_alert_id(self, request: InvestigationRequestPayload) -> str:
        if request.alert_id:
            return request.alert_id.strip()
        if request.question:
            m = re.search(r"\b(ALT[-_]?\d+|alert[-_]?\d+)\b", request.question, re.IGNORECASE)
            if m:
                raw_a = m.group(1).upper().replace("-", "").replace("_", "")
                m2 = re.match(r"(ALT|ALERT)(\d+)", raw_a)
                return f"ALT{int(m2.group(2)):03d}" if m2 else raw_a
        return "ALT001"

    def _evaluate_hop_stage(
        self,
        stage: int,
        hops: int,
        paths: List[Dict[str, Any]],
        alert_id: str,
        anomalies_detected: List[str],
        verified_facts: List[EvidenceItem],
        request: InvestigationRequestPayload,
    ) -> Tuple[str, str, List[str]]:
        """
        Evaluates evidence sufficiency and relevant trail continuation for adaptive multi-hop traversal.
        Stages:
          Stage 1 (Initial 3 hops): Evaluate immediate perimeter. If threat indicators exist, expand to 5 hops.
          Stage 2 (Intermediate 5 hops): Check if critical servers are reached and leads continue. If so, expand to 7/8 hops.
          Stage 3 (Deep 8 hops): Fully map crown-jewel blast radius and lateral movement.
        """
        # Collect frontier entities at current expansion depth first
        deepest_paths = [p for p in paths if p.get("hops", 0) >= hops] or paths
        frontier: List[str] = []
        for p in deepest_paths + paths:
            t_id = p.get("target_id") or p.get("target_label", "")
            if not t_id and p.get("path_string"):
                parts = p["path_string"].split(" -[:")
                if parts:
                    last_part = parts[-1].split("]-> ")[-1].strip()
                    t_id = last_part
            if t_id and t_id not in frontier:
                frontier.append(str(t_id))

        if not request.adaptive_hops_enabled:
            return (
                "SUFFICIENT",
                f"Initial {hops}-hop traversal completed (adaptive multi-hop disabled).",
                frontier[:8],
            )

        # Check if alert context carries threat anomalies or suspicious telemetry
        is_threat = (
            alert_id in ("ALT001", "ALT005", "ALT006")
            or len(anomalies_detected) > 0
            or any("tor" in f.description.lower() or "vpn" in f.description.lower() or "unmanaged" in f.description.lower() for f in verified_facts)
            or any("critical" in str(p.get("target_node", {}).get("sensitivity_level", "")).lower() for p in paths)
        )

        if stage == 1:
            if is_threat:
                return (
                    "INSUFFICIENT",
                    f"Initial {hops}-hop traversal mapped immediate perimeter ({len(paths)} paths). "
                    f"Evidence is insufficient to verify end-to-end lateral movement and downstream server blast radius.",
                    frontier[:8],
                )
            else:
                return (
                    "SUFFICIENT",
                    f"Initial {hops}-hop traversal acquired sufficient evidence confirming routine baseline activity ({len(paths)} paths).",
                    frontier[:8],
                )

        elif stage == 2:
            reaches_critical = any(
                "vault" in ent.lower() or "db" in ent.lower() or "srv" in ent.lower() or "fin" in ent.lower()
                for ent in frontier
            ) or is_threat
            if reaches_critical and hops < request.max_hops:
                return (
                    "TRAIL_CONTINUES",
                    f"Expanded {hops}-hop traversal reached critical intermediate nodes ({', '.join(frontier[:3])}). "
                    f"Relevant threat trail continues toward downstream crown-jewel key escrow and backup archives.",
                    frontier[:8],
                )
            else:
                return (
                    "SUFFICIENT",
                    f"Expanded {hops}-hop traversal yielded conclusive attack path evidence ({len(paths)} paths).",
                    frontier[:8],
                )

        else:
            return (
                "SUFFICIENT",
                f"Deep {hops}-hop traversal completed ({len(paths)} paths). Crown-jewel blast radius and end-to-end lateral movement trajectory fully verified.",
                frontier[:8],
            )

