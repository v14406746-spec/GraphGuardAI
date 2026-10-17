// src/data/mockData.js — High-fidelity datasets matching the user's dashboard image and backend alerts

export const ACC_1042_DATA = {
  account_id: "ACC-1042",
  risk_score: 82,
  risk_label: "High Risk",
  total_connections: 12,
  hops_explored: 5,
  investigation_time: "12.4s",
  query: "Investigate account ACC-1042 for possible fraud",
  
  // Graph Nodes
  nodes: [
    {
      id: "ACC-1042",
      label: "ACC-1042",
      sublabel: "Account",
      type: "Account",
      risk: "High Risk",
      riskScore: 82,
      isCenter: true,
      color: "#EF4444", // Red
      badgeColor: "bg-red-500/20 text-red-400 border border-red-500/40",
      iconType: "user",
      x: 0,
      y: 0,
    },
    {
      id: "ACC-2051",
      label: "ACC-2051",
      sublabel: "Account",
      type: "Account",
      risk: "Medium",
      riskScore: 58,
      color: "#F59E0B", // Amber/Yellow
      badgeColor: "bg-amber-500/20 text-amber-300 border border-amber-500/40",
      iconType: "user",
      angle: -80,
      distance: 180,
    },
    {
      id: "ACC-3090",
      label: "ACC-3090",
      sublabel: "Account",
      type: "Account",
      risk: "Medium",
      riskScore: 62,
      color: "#10B981", // Green
      badgeColor: "bg-amber-500/20 text-amber-300 border border-amber-500/40",
      iconType: "user",
      angle: -35,
      distance: 220,
    },
    {
      id: "MER-4521",
      label: "MER-4521",
      sublabel: "Merchant",
      type: "Merchant",
      risk: "Low",
      riskScore: 28,
      color: "#A855F7", // Purple/Magenta
      badgeColor: "bg-blue-500/20 text-blue-300 border border-blue-500/40",
      iconType: "store",
      angle: 0,
      distance: 270,
    },
    {
      id: "ACC-4012",
      label: "ACC-4012",
      sublabel: "Account",
      type: "Account",
      risk: "Medium",
      riskScore: 55,
      color: "#F59E0B",
      badgeColor: "bg-amber-500/20 text-amber-300 border border-amber-500/40",
      iconType: "user",
      angle: 35,
      distance: 210,
    },
    {
      id: "DEV-9920",
      label: "DEV-9920",
      sublabel: "Device",
      type: "Device",
      risk: "Low",
      riskScore: 20,
      color: "#8B5CF6",
      badgeColor: "bg-blue-500/20 text-blue-300 border border-blue-500/40",
      iconType: "device",
      angle: 70,
      distance: 175,
    },
    {
      id: "ACC-5077",
      label: "ACC-5077",
      sublabel: "Account",
      type: "Account",
      risk: "Medium",
      riskScore: 64,
      color: "#10B981",
      badgeColor: "bg-amber-500/20 text-amber-300 border border-amber-500/40",
      iconType: "user",
      angle: 110,
      distance: 190,
    },
    {
      id: "IP-203.0.113.5",
      label: "IP-203.0.113.5",
      sublabel: "IP Address",
      type: "IP Address",
      risk: "Low",
      riskScore: 32,
      color: "#EC4899", // Pink/Rose
      badgeColor: "bg-blue-500/20 text-blue-300 border border-blue-500/40",
      iconType: "globe",
      angle: 160,
      distance: 235,
    },
    {
      id: "ACC-6018",
      label: "ACC-6018",
      sublabel: "Account",
      type: "Account",
      risk: "Medium",
      riskScore: 59,
      color: "#06B6D4", // Cyan
      badgeColor: "bg-amber-500/20 text-amber-300 border border-amber-500/40",
      iconType: "user",
      angle: -160,
      distance: 200,
    },
    {
      id: "DEV-7781",
      label: "DEV-7781",
      sublabel: "Device",
      type: "Device",
      risk: "Low",
      riskScore: 18,
      color: "#8B5CF6",
      badgeColor: "bg-blue-500/20 text-blue-300 border border-blue-500/40",
      iconType: "device",
      angle: -120,
      distance: 180,
    },
  ],

  // Graph Edges
  edges: [
    { from: "ACC-1042", to: "ACC-2051", type: "direct", label: "TRANSFER" },
    { from: "ACC-1042", to: "ACC-3090", type: "direct", label: "TRANSFER" },
    { from: "ACC-1042", to: "MER-4521", type: "indirect", label: "PAYMENT" },
    { from: "ACC-1042", to: "ACC-4012", type: "direct", label: "TRANSFER" },
    { from: "ACC-1042", to: "DEV-9920", type: "direct", label: "USED_DEVICE" },
    { from: "ACC-1042", to: "ACC-5077", type: "direct", label: "TRANSFER" },
    { from: "ACC-1042", to: "IP-203.0.113.5", type: "direct", label: "LOGIN_FROM" },
    { from: "ACC-1042", to: "ACC-6018", type: "direct", label: "TRANSFER" },
    { from: "ACC-1042", to: "DEV-7781", type: "direct", label: "USED_DEVICE" },
    { from: "ACC-2051", to: "ACC-3090", type: "indirect", label: "TRANSFER" },
    { from: "ACC-3090", to: "MER-4521", type: "indirect", label: "PAYMENT" },
  ],

  // Key Findings (Matches Image)
  keyFindings: [
    {
      id: 1,
      dotColor: "#EF4444", // Red
      title: "Multiple transactions to high-risk merchant",
      detail: "3 connections",
    },
    {
      id: 2,
      dotColor: "#F97316", // Orange
      title: "Shared device with 2 other accounts",
      detail: "2 connections",
    },
    {
      id: 3,
      dotColor: "#F59E0B", // Amber
      title: "Indirect transfers through intermediary accounts",
      detail: "4 hops",
    },
    {
      id: 4,
      dotColor: "#A855F7", // Purple ring
      title: "IP address linked to known fraud patterns",
      detail: "1 connection",
    },
  ],

  // Evidence Path Flow (Matches Image)
  evidencePath: [
    {
      id: "step-1",
      entity: "ACC-1042 (Starting Account)",
      timestamp: "2025-04-15 10:24",
      amount: "$3,500",
      color: "#10B981", // Green
      icon: "user",
    },
    {
      id: "step-2",
      entity: "ACC-2051 (Intermediary Account)",
      timestamp: "2025-04-15 14:37",
      amount: "$3,500",
      color: "#F59E0B", // Yellow/Amber
      icon: "user",
    },
    {
      id: "step-3",
      entity: "ACC-3090 (Connected Account)",
      timestamp: "2025-04-16 09:12",
      amount: "$3,500",
      color: "#10B981", // Green
      icon: "user",
    },
    {
      id: "step-4",
      entity: "MER-4521 (High Risk Merchant)",
      timestamp: "2025-04-15 11:45",
      amount: "$3,500",
      color: "#A855F7", // Purple/Magenta
      icon: "store",
    },
  ],

  // AI Agent Analysis (Matches Image)
  agentAnalysis:
    "The investigation found multiple red flags connected to account ACC-1042. The account received funds from an intermediary (ACC-2051) and continued the flow to a high-risk merchant (MER-4521). This account also shares a device with two other accounts and uses an IP address linked to known fraud patterns. The pattern suggests possible money laundering activity through a chain of accounts.",

  recommendedActions: [
    "Flag account ACC-1042 for manual review",
    "Investigate merchant MER-4521 for suspicious activity",
    "Monitor related accounts and devices for additional fraud patterns",
  ],

  // Transaction Timeline for Tab 2
  timeline: [
    { time: "2025-04-15 09:15 UTC", type: "AUTH", title: "Login from IP 203.0.113.5", status: "FLAGGED", detail: "Device DEV-7781" },
    { time: "2025-04-15 10:24 UTC", type: "INBOUND", title: "Received $3,500 from ACC-2051", status: "CONFIRMED", detail: "Intermediary transfer" },
    { time: "2025-04-15 11:45 UTC", type: "OUTBOUND", title: "Payment $3,500 to MER-4521", status: "HIGH_RISK", detail: "Offshore high-risk merchant" },
    { time: "2025-04-15 14:37 UTC", type: "AUTH", title: "Secondary login via DEV-9920", status: "ANOMALOUS", detail: "Shared device association" },
    { time: "2025-04-16 09:12 UTC", type: "HOP", title: "Funds layered through ACC-3090", status: "ESCALATED", detail: "Multi-hop structuring" },
  ],

  // Related Accounts for Tab 3
  relatedAccounts: [
    { id: "ACC-2051", name: "Intermediary Account Alpha", relation: "Direct Inflow", volume: "$18,400", risk: "Medium (58%)" },
    { id: "ACC-3090", name: "Pivot Account Beta", relation: "Downstream Layering", volume: "$32,100", risk: "Medium (62%)" },
    { id: "ACC-4012", name: "Co-signed Account Gamma", relation: "Shared Device DEV-9920", volume: "$14,500", risk: "Medium (55%)" },
    { id: "ACC-6018", name: "Affiliated Account Delta", relation: "Common IP Cluster", volume: "$9,200", risk: "Medium (59%)" },
  ],

  // Risk Indicators for Tab 4
  riskFactors: [
    { name: "IP Threat Intelligence", weight: "25%", score: "0.85", status: "HIGH", note: "Matches known proxy/botnet subnet" },
    { name: "Structuring & Smurfing Velocity", weight: "20%", score: "0.90", status: "CRITICAL", note: "Rapid in-out transfers matching layering profile" },
    { name: "High-Risk Merchant Exposure", weight: "20%", score: "0.88", status: "CRITICAL", note: "Direct flow to unlicensed offshore gateway" },
    { name: "Shared Device Fingerprint", weight: "15%", score: "0.75", status: "HIGH", note: "DEV-9920 tied to 3 distinct account IDs" },
    { name: "Multi-Hop Path Dispersal", weight: "20%", score: "0.72", status: "ELEVATED", note: "5-hop cyclic flow detected across 4 nodes" },
  ],
};

// Preset Scenarios
export const PRESETS = [
  { id: "ACC-1042", label: "ACC-1042: Money Laundering & Structuring", type: "Fraud" },
  { id: "ALT001", label: "ALT001: Alice Chen — Tor Login to Fin-DB (Adaptive 3->5->8 Hops)", type: "Security" },
  { id: "ALT005", label: "ALT005: Dan Torres — Night SysAdmin Kali Linux Vault Intrusion", type: "Security" },
  { id: "ALT002", label: "ALT002: Bob Martin — Routine Benign CI Activity (Early Stop 3 Hops)", type: "Security" },
];
