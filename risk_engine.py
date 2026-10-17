r"""
backend/risk_engine.py — Deterministic 8-Factor Graph Risk Scoring Engine.
Track 1: Agents That Act on Connected Data (FalkorDB Hackathon)

Features:
  - Fully transparent, weighted scoring ($\sum w_i = 1.0$).
  - Evaluates explicit signals from FalkorDB graph topology:
      • IP threat intelligence score (0.25)
      • Tor exit node / VPN usage (0.15)
      • Off-hours authentication (0.15)
      • Missing Multi-Factor Authentication (0.15)
      • Unmanaged endpoint device (0.10)
      • Machine learning telemetry anomaly score (0.10)
      • Critical/high sensitivity server access (0.05)
      • Failed authentication spike (0.05)
  - Policy action thresholds:
      $\ge 0.70$ → ESCALATE (Immediate SOC review)
      $\ge 0.55$ → RECOMMEND_RESTRICTION (Temporary access lock)
      $\ge 0.35$ → GATHER_ADDITIONAL_EVIDENCE (Telemetry request)
      $< 0.35$   → MONITOR (Benign baseline)
  - Interactive Counterfactual ("What-If") simulation engine.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_BACKEND_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _BACKEND_DIR.parent
for _p in [str(_BACKEND_DIR), str(_PROJECT_ROOT)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from backend.graph_client import get_graph_client
from backend.schemas import PolicyAction, RiskFactor, RiskResult, WhatIfResponse

logger = logging.getLogger("backend.risk_engine")

# ── Factor Weights (Sum = 1.0) ────────────────────────────────────────────────
FACTOR_WEIGHTS: Dict[str, float] = {
    "ip_reputation":      0.25,
    "tor_or_vpn":         0.15,
    "off_hours_login":    0.15,
    "no_mfa":             0.15,
    "unmanaged_device":   0.10,
    "high_anomaly_score": 0.10,
    "sensitive_server":   0.05,
    "failed_login_spike": 0.05,
}

# Policy Thresholds
THRESHOLD_ESCALATE = 0.70
THRESHOLD_RESTRICT = 0.55
THRESHOLD_GATHER   = 0.35


def determine_policy_action(score: float) -> Tuple[str, PolicyAction]:
    """Maps numerical risk score to label and governed policy action."""
    score = min(max(round(score, 4), 0.0), 1.0)
    if score >= THRESHOLD_ESCALATE:
        return "CRITICAL", PolicyAction.ESCALATE
    elif score >= THRESHOLD_RESTRICT:
        return "HIGH", PolicyAction.RECOMMEND_RESTRICTION
    elif score >= THRESHOLD_GATHER:
        return "MEDIUM", PolicyAction.GATHER_ADDITIONAL_EVIDENCE
    else:
        return "LOW", PolicyAction.MONITOR


def compute_risk(
    *,
    ip_reputation_score: float = 0.0,
    is_tor: bool = False,
    is_vpn: bool = False,
    login_hour_utc: Optional[int] = None,
    mfa_used: bool = True,
    device_is_managed: bool = True,
    anomaly_score: float = 0.0,
    server_sensitivity: str = "low",
    failed_login_count: int = 0,
) -> RiskResult:
    """
    Computes deterministic risk score from individual telemetry parameters.
    """
    factors: List[RiskFactor] = []
    confidence_limitations: List[str] = []
    alternative_explanations: List[str] = []

    # 1. IP Reputation (0.25)
    ip_score = max(0.0, min(float(ip_reputation_score), 1.0))
    ip_contrib = ip_score * FACTOR_WEIGHTS["ip_reputation"]
    factors.append(RiskFactor(
        name="ip_reputation",
        raw_value=round(ip_score, 2),
        weight=FACTOR_WEIGHTS["ip_reputation"],
        contribution=round(ip_contrib, 4),
        explanation=f"Threat-intel reputation score {ip_score:.2f} (0=clean, 1=malicious)",
    ))
    if ip_score == 0.0:
        confidence_limitations.append("IP reputation is 0.0 — may indicate lack of threat intelligence coverage.")

    # 2. Tor or VPN (0.15)
    tor_val = 1.0 if is_tor else (0.5 if is_vpn else 0.0)
    tor_contrib = tor_val * FACTOR_WEIGHTS["tor_or_vpn"]
    factors.append(RiskFactor(
        name="tor_or_vpn",
        raw_value={"is_tor": is_tor, "is_vpn": is_vpn},
        weight=FACTOR_WEIGHTS["tor_or_vpn"],
        contribution=round(tor_contrib, 4),
        explanation=f"Anonymization proxy verified: Tor={is_tor}, VPN={is_vpn}",
    ))
    if is_vpn and not is_tor:
        alternative_explanations.append("Commercial VPN usage is common for approved remote or traveling employees.")

    # 3. Off-hours login (0.15)
    if login_hour_utc is not None:
        is_off = login_hour_utc < 8 or login_hour_utc >= 18
        off_contrib = (1.0 if is_off else 0.0) * FACTOR_WEIGHTS["off_hours_login"]
        factors.append(RiskFactor(
            name="off_hours_login",
            raw_value=login_hour_utc,
            weight=FACTOR_WEIGHTS["off_hours_login"],
            contribution=round(off_contrib, 4),
            explanation=f"Authentication at {login_hour_utc}:00 UTC — {'OUTSIDE' if is_off else 'WITHIN'} standard hours (08-18 UTC)",
        ))
        if is_off:
            alternative_explanations.append("Off-hours login may correspond to on-call support rotation or cross-timezone duties.")
    else:
        confidence_limitations.append("Authentication timestamp unavailable; off-hours factor omitted.")

    # 4. No MFA (0.15)
    no_mfa = not mfa_used
    no_mfa_contrib = (1.0 if no_mfa else 0.0) * FACTOR_WEIGHTS["no_mfa"]
    factors.append(RiskFactor(
        name="no_mfa",
        raw_value=no_mfa,
        weight=FACTOR_WEIGHTS["no_mfa"],
        contribution=round(no_mfa_contrib, 4),
        explanation=f"Multi-Factor Authentication {'WAS NOT USED' if no_mfa else 'was successfully verified'}",
    ))

    # 5. Unmanaged Device (0.10)
    unmanaged = not device_is_managed
    unmanaged_contrib = (1.0 if unmanaged else 0.0) * FACTOR_WEIGHTS["unmanaged_device"]
    factors.append(RiskFactor(
        name="unmanaged_device",
        raw_value=unmanaged,
        weight=FACTOR_WEIGHTS["unmanaged_device"],
        contribution=round(unmanaged_contrib, 4),
        explanation=f"Endpoint device is {'UNMANAGED (not enrolled in MDM)' if unmanaged else 'enrolled in corporate MDM'}",
    ))

    # 6. ML Anomaly Score (0.10)
    anom_score = max(0.0, min(float(anomaly_score), 1.0))
    anom_contrib = anom_score * FACTOR_WEIGHTS["high_anomaly_score"]
    factors.append(RiskFactor(
        name="high_anomaly_score",
        raw_value=round(anom_score, 2),
        weight=FACTOR_WEIGHTS["high_anomaly_score"],
        contribution=round(anom_contrib, 4),
        explanation=f"ML baseline anomaly score: {anom_score:.2f}",
    ))

    # 7. Sensitive Server (0.05)
    sens_map = {"critical": 1.0, "high": 0.75, "medium": 0.50, "low": 0.0}
    sens_val = sens_map.get(str(server_sensitivity).lower(), 0.0)
    sens_contrib = sens_val * FACTOR_WEIGHTS["sensitive_server"]
    factors.append(RiskFactor(
        name="sensitive_server",
        raw_value=server_sensitivity,
        weight=FACTOR_WEIGHTS["sensitive_server"],
        contribution=round(sens_contrib, 4),
        explanation=f"Target backend asset has sensitivity level '{server_sensitivity}'",
    ))

    # 8. Failed Login Spike (0.05)
    fail_score = min(float(failed_login_count) / 3.0, 1.0)
    fail_contrib = fail_score * FACTOR_WEIGHTS["failed_login_spike"]
    factors.append(RiskFactor(
        name="failed_login_spike",
        raw_value=failed_login_count,
        weight=FACTOR_WEIGHTS["failed_login_spike"],
        contribution=round(fail_contrib, 4),
        explanation=f"{failed_login_count} recent failed login attempt(s) observed",
    ))

    # Total Score
    total_score = sum(f.contribution for f in factors)
    total_score = min(max(round(total_score, 4), 0.0), 1.0)
    label, policy = determine_policy_action(total_score)

    confidence = 0.95 if any(f.contribution > 0 for f in factors) else 0.40

    return RiskResult(
        score=total_score,
        label=label,
        policy_action=policy,
        factors=factors,
        confidence=confidence,
        confidence_limitations=confidence_limitations,
        alternative_explanations=alternative_explanations,
    )


def compute_risk_from_graph(alert_id: str) -> RiskResult:
    """
    Extracts explicit signals from FalkorDB connected graph and computes risk.
    """
    db = get_graph_client()
    aid = alert_id.strip()

    # Query alert & user
    alert_rows = db.query("MATCH (a:Alert {alert_id: $aid}) RETURN a", {"aid": aid})
    if not alert_rows:
        return RiskResult(score=0.0, label="LOW", policy_action=PolicyAction.MONITOR)

    # Defaults
    ip_rep = 0.0
    is_tor = False
    is_vpn = False
    login_hour = None
    mfa_used = True
    device_managed = True
    anomaly_score = 0.0
    server_sensitivity = "low"
    failed_logins = 0

    # 1. Login Event
    login_rows = db.query("""
    MATCH (a:Alert {alert_id: $aid})-[]->(u:User)-[:PERFORMED_LOGIN]->(le:LoginEvent)
    RETURN le
    """, {"aid": aid})
    for lr in login_rows:
        le = lr.get("le", {})
        if le:
            mfa_used = le.get("mfa_used", True)
            anomaly_score = float(le.get("anomaly_score", 0.0))
            ts = le.get("timestamp", "")
            if "T" in ts:
                try:
                    login_hour = int(ts.split("T")[1].split(":")[0])
                except Exception:
                    pass

    # 2. IP Address
    ip_rows = db.query("""
    MATCH (a:Alert {alert_id: $aid})-[]->(u:User)-[:PERFORMED_LOGIN]->(le:LoginEvent)-[:LOGIN_FROM_IP]->(ip:IPAddress)
    RETURN ip
    """, {"aid": aid})
    if not ip_rows:
        ip_rows = db.query("MATCH (a:Alert {alert_id: $aid})-[]->(ip:IPAddress) RETURN ip", {"aid": aid})

    for ir in ip_rows:
        ip = ir.get("ip", {})
        if ip:
            ip_rep = float(ip.get("reputation_score", 0.0))
            is_tor = bool(ip.get("is_tor", False))
            is_vpn = bool(ip.get("is_vpn", False))

    # 3. Device
    dev_rows = db.query("""
    MATCH (a:Alert {alert_id: $aid})-[]->(u:User)-[:PERFORMED_LOGIN]->(le:LoginEvent)-[:USED_DEVICE]->(d:Device)
    RETURN d
    """, {"aid": aid})
    for dr in dev_rows:
        dev = dr.get("d", {})
        if dev:
            device_managed = bool(dev.get("is_managed", True))

    # 4. Server
    srv_rows = db.query("""
    MATCH (a:Alert {alert_id: $aid})-[]->(u:User)-[:ACCESSED]->(s:Server)
    RETURN s
    """, {"aid": aid})
    for sr in srv_rows:
        srv = sr.get("s", {})
        if srv:
            server_sensitivity = srv.get("sensitivity_level", "low")

    # Compute
    return compute_risk(
        ip_reputation_score=ip_rep,
        is_tor=is_tor,
        is_vpn=is_vpn,
        login_hour_utc=login_hour,
        mfa_used=mfa_used,
        device_is_managed=device_managed,
        anomaly_score=anomaly_score,
        server_sensitivity=server_sensitivity,
        failed_login_count=failed_logins,
    )


def simulate_counterfactual(risk_result: RiskResult, remove_factor: str) -> WhatIfResponse:
    """
    Read-only "What-If" Counterfactual Simulation Engine.
    Simulates the risk score and policy action outcome if a specific factor signal were removed.
    Does not mutate the underlying FalkorDB graph.
    """
    clean_factor = remove_factor.strip().lower()

    # Create simulated factors with target factor zeroed out
    simulated_factors: List[RiskFactor] = []
    removed_found = False

    for f in risk_result.factors:
        if f.name.lower() == clean_factor:
            removed_found = True
            simulated_factors.append(RiskFactor(
                name=f.name,
                raw_value=f.raw_value,
                weight=f.weight,
                contribution=0.0,
                explanation=f"[COUNTERFACTUAL: SIMULATED AS BENIGN] {f.explanation}",
            ))
        else:
            simulated_factors.append(f)

    sim_score = sum(f.contribution for f in simulated_factors)
    sim_score = min(max(round(sim_score, 4), 0.0), 1.0)
    sim_label, sim_action = determine_policy_action(sim_score)

    delta = round(sim_score - risk_result.score, 4)
    action_changed = sim_action != risk_result.policy_action

    if action_changed:
        explanation = (
            f"Causal impact confirmed: Removing factor '{remove_factor}' reduces risk from "
            f"{risk_result.score:.2f} ({risk_result.policy_action.value}) down to {sim_score:.2f} ({sim_action.value}). "
            f"This proves '{remove_factor}' was the pivot signal driving the governance recommendation."
        )
    else:
        explanation = (
            f"Marginal impact: Removing factor '{remove_factor}' shifts score by {delta:+.2f} "
            f"(from {risk_result.score:.2f} to {sim_score:.2f}), but policy remains {sim_action.value}."
        )

    return WhatIfResponse(
        original_score=risk_result.score,
        original_action=risk_result.policy_action.value,
        simulated_score=sim_score,
        simulated_action=sim_action.value,
        delta_score=delta,
        action_changed=action_changed,
        removed_factor=remove_factor,
        simulated_factors=simulated_factors,
        explanation=explanation,
    )
