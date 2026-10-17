"""
mcp_server/tools.py — Root proxy forwarding to backend.mcp_server.tools
"""
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

__all__ = [
    "analyze_graph_risk",
    "execute_cypher",
    "find_related_incidents",
    "get_investigation_context",
    "inspect_entity",
    "propose_response",
    "trace_relationships",
    "validate_evidence",
]
