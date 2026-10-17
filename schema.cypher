// ==============================================================================
// schema.cypher — FalkorDB Schema, Indexes, and Constraints
// Track 1: Agents That Act on Connected Data (Company Security Graph)
// ==============================================================================

// ------------------------------------------------------------------------------
// 1. NODE INDEXES (FalkorDB syntax: CREATE INDEX ON :Label(property))
// ------------------------------------------------------------------------------

// Organizations & Hierarchy
CREATE INDEX ON :Organization(org_id);
CREATE INDEX ON :Department(dept_id);
CREATE INDEX ON :Role(role_id);

// Identities & Access Management
CREATE INDEX ON :User(user_id);
CREATE INDEX ON :User(username);
CREATE INDEX ON :User(email);
CREATE INDEX ON :Permission(perm_id);

// Telemetry & Authentication Events
CREATE INDEX ON :LoginEvent(event_id);
CREATE INDEX ON :LoginEvent(timestamp);
CREATE INDEX ON :LoginEvent(status);

// Network Infrastructure
CREATE INDEX ON :IPAddress(ip_id);
CREATE INDEX ON :IPAddress(address);
CREATE INDEX ON :IPAddress(country);

// Endpoints & Physical/Virtual Assets
CREATE INDEX ON :Device(device_id);
CREATE INDEX ON :Device(hostname);
CREATE INDEX ON :Device(is_managed);

// Critical Infrastructure & Servers
CREATE INDEX ON :Server(server_id);
CREATE INDEX ON :Server(hostname);
CREATE INDEX ON :Server(sensitivity_level);
CREATE INDEX ON :Application(app_id);

// SOC Alerts & Evidence Ledger
CREATE INDEX ON :Alert(alert_id);
CREATE INDEX ON :Alert(severity);
CREATE INDEX ON :Alert(status);
CREATE INDEX ON :Evidence(evidence_id);

// ------------------------------------------------------------------------------
// 2. SCHEMA DEFINITION & NODE ATTRIBUTES
// ------------------------------------------------------------------------------
// Node Labels:
//   (:Organization)   {org_id, name, domain, industry}
//   (:Department)     {dept_id, name, code}
//   (:Role)           {role_id, title, privilege_level}
//   (:User)           {user_id, username, email, department, role, risk_score, is_active}
//   (:Permission)     {perm_id, name, level, resource}
//   (:LoginEvent)     {event_id, timestamp, status, mfa_used, anomaly_score, description}
//   (:IPAddress)      {ip_id, address, country, is_vpn, is_tor, reputation_score}
//   (:Device)         {device_id, hostname, os, is_managed, last_seen}
//   (:Server)         {server_id, hostname, environment, sensitivity_level, contains_pii, port}
//   (:Application)    {app_id, name, sensitivity_level, owner}
//   (:Alert)          {alert_id, title, severity, status, created_at, description}
//   (:Evidence)       {evidence_id, type, description, confidence, source}
//
// Directed Relationship Types:
//   (:User)-[:BELONGS_TO]->(:Department)
//   (:User)-[:HAS_ROLE]->(:Role)
//   (:User)-[:HAS_PERMISSION]->(:Permission)
//   (:User)-[:PERFORMED_LOGIN]->(:LoginEvent)
//   (:User)-[:OWNS_DEVICE]->(:Device)
//   (:User)-[:ACCESSED]->(:Server)
//   (:LoginEvent)-[:LOGIN_FROM_IP]->(:IPAddress)
//   (:LoginEvent)-[:USED_DEVICE]->(:Device)
//   (:Device)-[:CONNECTED_TO]->(:Server)
//   (:Permission)-[:GRANTS_ACCESS_TO]->(:Application)
//   (:Application)-[:HOSTED_ON]->(:Server)
//   (:Alert)-[:REFERS_TO]->(:User | :IPAddress | :Device | :Server)
//   (:Alert)-[:HAS_EVIDENCE]->(:Evidence)
//   (:Evidence)-[:CORROBORATES]->(:LoginEvent | :IPAddress | :Device)
//   (:Alert)-[:CORRELATED_WITH]->(:Alert)
// ==============================================================================
