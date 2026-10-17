"""
backend/schemas.py — Pydantic Schemas and API Contracts.
Track 1: Agents That Act on Connected Data (FalkorDB Hackathon)

Defines structured models for:
  - Investigation requests & execution reports
  - Tool execution traces & evidence provenance
  - 8-factor risk metrics & counterfactual "what-if" simulations
  - Cytoscape.js graph visualizer nodes & edges
  - Human-in-the-loop response governance lifecycle
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, Field


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ==============================================================================
# ENUMS
# ==============================================================================

class ProvenanceType(str, Enum):
    VERIFIED_FACT = "VERIFIED_FACT"        # Backed directly by FalkorDB graph nodes/edges
    RULE_CALCULATION = "RULE_CALCULATION"  # Output of deterministic risk policy engine
    INFERRED = "INFERRED"                  # Logical deduction from multiple graph facts
    AI_HYPOTHESIS = "AI_HYPOTHESIS"        # Proposed thesis awaiting graph validation


class PolicyAction(str, Enum):
    MONITOR = "MONITOR"
    GATHER_ADDITIONAL_EVIDENCE = "GATHER_ADDITIONAL_EVIDENCE"
    RECOMMEND_RESTRICTION = "RECOMMEND_RESTRICTION"
    ESCALATE = "ESCALATE"


class ActionStatus(str, Enum):
    PROPOSED = "PROPOSED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"


class InvestigationStatus(str, Enum):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    ERROR = "ERROR"


# ==============================================================================
# EVIDENCE & TOOL TRACE
# ==============================================================================

class EvidenceItem(BaseModel):
    evidence_id: str = Field(default_factory=lambda: f"ev-{uuid.uuid4().hex[:8]}")
    source: str
    description: str
    confidence: float = 1.0
    provenance_type: ProvenanceType = ProvenanceType.VERIFIED_FACT
    entity_type: str = ""
    entity_id: str = ""
    graph_entities: List[str] = Field(default_factory=list)
    graph_path: Optional[str] = None
    timestamp: str = Field(default_factory=_now)

    @property
    def claim(self) -> str:
        return self.description


class ToolCallRecord(BaseModel):
    call_id: str = Field(default_factory=lambda: f"call-{uuid.uuid4().hex[:6]}")
    step: int
    tool_name: str
    arguments: Dict[str, Any]
    result_status: str
    summary: str
    execution_time_ms: float = 0.0
    timestamp: str = Field(default_factory=_now)


# ==============================================================================
# RISK ENGINE MODELS
# ==============================================================================

class RiskFactor(BaseModel):
    name: str
    raw_value: Any
    weight: float
    contribution: float
    explanation: str


class RiskResult(BaseModel):
    score: float = Field(0.0, ge=0.0, le=1.0)
    label: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    policy_action: PolicyAction = PolicyAction.MONITOR
    factors: List[RiskFactor] = Field(default_factory=list)
    confidence: float = 1.0
    confidence_limitations: List[str] = Field(default_factory=list)
    alternative_explanations: List[str] = Field(default_factory=list)


class WhatIfRequestPayload(BaseModel):
    alert_id: Optional[str] = None
    investigation_id: Optional[str] = None
    remove_factor: str = Field(..., description="Factor to simulate removal of, e.g. 'tor_or_vpn', 'no_mfa'")


class WhatIfResponse(BaseModel):
    original_score: float
    original_action: str
    simulated_score: float
    simulated_action: str
    delta_score: float
    action_changed: bool
    removed_factor: str
    simulated_factors: List[RiskFactor] = Field(default_factory=list)
    explanation: str


# ==============================================================================
# GRAPH VISUALIZATION (Cytoscape.js Format)
# ==============================================================================

class CytoscapeNodeData(BaseModel):
    id: str
    label: str
    name: str
    type: str
    color: str
    shape: str = "ellipse"
    badge: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)


class CytoscapeNode(BaseModel):
    data: CytoscapeNodeData


class CytoscapeEdgeData(BaseModel):
    id: str
    source: str
    target: str
    label: str
    color: Optional[str] = None
    style: Optional[str] = "solid"
    properties: Dict[str, Any] = Field(default_factory=dict)


class CytoscapeEdge(BaseModel):
    data: CytoscapeEdgeData


class GraphVisualization(BaseModel):
    nodes: List[CytoscapeNode] = Field(default_factory=list)
    edges: List[CytoscapeEdge] = Field(default_factory=list)


# ==============================================================================
# ADAPTIVE HOP CONFIGURATION & STAGE MODELS
# ==============================================================================

class HopExpansionStage(BaseModel):
    stage: int
    hops: int
    reason: str
    paths_found: int
    evidence_sufficiency: str  # "INSUFFICIENT" | "TRAIL_CONTINUES" | "SUFFICIENT"
    frontier_entities: List[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=_now)


# ==============================================================================
# INVESTIGATION & REPORT
# ==============================================================================

class InvestigationRequestPayload(BaseModel):
    alert_id: Optional[str] = None
    question: Optional[str] = None

    # Adaptive Multi-Hop Settings
    adaptive_hops_enabled: bool = Field(default=True, description="Enable adaptive multi-hop expansion (3 -> 5 -> 7/8)")
    initial_hops: int = Field(default=3, ge=1, le=8, description="Initial traversal depth to start investigation")
    intermediate_hops: int = Field(default=5, ge=2, le=10, description="Expanded depth if evidence is insufficient")
    deep_hops: int = Field(default=8, ge=3, le=12, description="Deep depth if relevant trail continues")
    max_hops: int = Field(default=8, ge=1, le=12, description="Configured maximum traversal depth boundary")

    # Budget Guards
    query_budget: int = Field(default=20, ge=1, le=50, description="Maximum total query/tool calls budget")
    max_tool_calls: int = Field(default=20, ge=1, le=50, description="Alias for query budget")
    enable_counterfactual: bool = True


class InvestigationReport(BaseModel):
    investigation_id: str
    alert_id: str
    question: str
    verdict: str
    status: InvestigationStatus = InvestigationStatus.COMPLETE
    started_at: str
    completed_at: str
    elapsed_seconds: float = 0.0

    # Adaptive Hop Expansion
    hops_explored: int = 3
    adaptive_hop_stages: List[HopExpansionStage] = Field(default_factory=list)
    query_budget_total: int = 20
    query_budget_used: int = 0
    query_budget_exhausted: bool = False

    # Risk Metrics
    risk_score: float = 0.0
    risk_label: str = "LOW"
    policy_action: PolicyAction = PolicyAction.MONITOR
    target_entity: str = "UNKNOWN"
    risk_factors: List[RiskFactor] = Field(default_factory=list)

    # Graph Evidence
    verified_facts: List[EvidenceItem] = Field(default_factory=list)
    graph_paths: List[str] = Field(default_factory=list)
    hypotheses_evaluated: Dict[str, str] = Field(default_factory=dict)
    alternative_explanations: List[str] = Field(default_factory=list)
    confidence: float = 1.0
    confidence_limitations: List[str] = Field(default_factory=list)

    # Audit Trail
    tool_history: List[ToolCallRecord] = Field(default_factory=list)
    stop_reason: str = "Completed successfully."

    # Visualization
    graph: GraphVisualization = Field(default_factory=GraphVisualization)


# ==============================================================================
# GOVERNANCE & API CONTRACTS
# ==============================================================================

class ActionProposalPayload(BaseModel):
    investigation_id: str
    alert_id: str
    action: PolicyAction
    target_entity: str
    justification: str


class ActionDecisionPayload(BaseModel):
    action_id: str
    decision: Literal["APPROVE", "REJECT"]
    analyst_name: str = "SOC Analyst"
    comment: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    service: str
    database: Dict[str, Any]
    mcp_tools_count: int
    environment: str = "production"
    timestamp: str = Field(default_factory=_now)


class AlertSummary(BaseModel):
    alert_id: str
    title: str
    severity: str
    status: str
    created_at: str
    description: str
