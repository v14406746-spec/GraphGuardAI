/**
 * frontend/src/api.js — Centralized API Client for FalkorDB Autonomous Agent Backend.
 * Phase 4: Frontend Service Layer
 */

const API_BASE = '/api';

/**
 * Executes multi-hop autonomous investigation on an alert or account entity.
 */
export async function runInvestigation({
  alert_id,
  question,
  max_hops = 5,
  initial_hops = 3,
  intermediate_hops = 5,
  deep_hops = 8,
  adaptive_hops_enabled = true,
  query_budget = 20,
}) {
  const payload = {
    alert_id,
    question,
    max_hops: typeof max_hops === 'number' ? max_hops : 8,
    initial_hops,
    intermediate_hops,
    deep_hops,
    adaptive_hops_enabled,
    query_budget,
  };

  const res = await fetch(`${API_BASE}/investigate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Investigation failed with status ${res.status}`);
  }

  return await res.json();
}

/**
 * Retrieves database health status, active mode (live vs mock), and MCP tool counts.
 */
export async function getHealthStatus() {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error('Health check failed');
  return await res.json();
}

/**
 * Retrieves all seeded security alerts.
 */
export async function getAlerts() {
  const res = await fetch(`${API_BASE}/alerts`);
  if (!res.ok) throw new Error('Failed to retrieve alerts');
  return await res.json();
}

/**
 * Retrieves specific alert graph context.
 */
export async function getAlertDetail(alertId) {
  const res = await fetch(`${API_BASE}/alerts/${alertId}`);
  if (!res.ok) throw new Error(`Failed to retrieve alert ${alertId}`);
  return await res.json();
}

/**
 * Simulates a What-If counterfactual scenario (removing a factor).
 */
export async function simulateWhatIf(alertId, removeFactor) {
  const res = await fetch(`${API_BASE}/what-if`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      alert_id: alertId,
      remove_factor: removeFactor,
    }),
  });
  if (!res.ok) throw new Error('What-If simulation failed');
  return await res.json();
}

/**
 * Retrieves Cytoscape graph nodes and edges for visualization.
 */
export async function getGraphData(alertId) {
  const res = await fetch(`${API_BASE}/graph?alert_id=${encodeURIComponent(alertId)}`);
  if (!res.ok) throw new Error('Failed to load graph topology');
  return await res.json();
}

/**
 * Submits human-in-the-loop action approval/rejection decision.
 */
export async function submitActionDecision(actionId, decision, analystName = "SOC Analyst") {
  const res = await fetch(`${API_BASE}/governance/action`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      action_id: actionId,
      decision,
      analyst_name: analystName,
    }),
  });
  if (!res.ok) throw new Error('Failed to submit governance decision');
  return await res.json();
}

/**
 * Retrieves append-only governance audit log.
 */
export async function getAuditLog() {
  const res = await fetch(`${API_BASE}/audit-log`);
  if (!res.ok) throw new Error('Failed to load audit trail');
  return await res.json();
}

export default {
  runInvestigation,
  getHealthStatus,
  getAlerts,
  getAlertDetail,
  simulateWhatIf,
  getGraphData,
  submitActionDecision,
  getAuditLog,
};
