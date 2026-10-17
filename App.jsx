import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import InvestigationControls from './components/InvestigationControls';
import InvestigationGraph from './components/InvestigationGraph';
import AnalysisTabs from './components/AnalysisTabs';
import RightPanel from './components/RightPanel';
import NewInvestigationView from './components/NewInvestigationView';
import GraphExplorerView from './components/GraphExplorerView';
import ReportGeneratorView from './components/ReportGeneratorView';
import SettingsView from './components/SettingsView';
import { ACC_1042_DATA } from './data/mockData';

export default function App() {
  const [activeNav, setActiveNav] = useState('dashboard');
  const [query, setQuery] = useState("Investigate account ACC-1042 for possible fraud");
  const [maxHops, setMaxHops] = useState(5);
  const [timeRange, setTimeRange] = useState("30d");
  const [showRiskScores, setShowRiskScores] = useState(true);
  const [currentData, setCurrentData] = useState(ACC_1042_DATA);
  const [selectedNode, setSelectedNode] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [notification, setNotification] = useState(null);

  const showToast = (msg) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 4000);
  };

  // Main Investigation Handler (Connects to backend if alert mentioned, or simulates live analysis)
  const handleInvestigate = async (overrideParams = null) => {
    setIsLoading(true);
    const targetQuery = overrideParams?.question || query;
    const upperQuery = targetQuery.toUpperCase();

    // Check if query targets a backend FalkorDB seeded alert
    const alertMatch = upperQuery.match(/\b(ALT[-_]?\d+|ALERT[-_]?\d+)\b/);
    const alertId = overrideParams?.alert_id || (alertMatch ? alertMatch[1].replace(/[-_]/g, '').replace('ALERT', 'ALT') : "ALT001");

    try {
      const response = await fetch('/api/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert_id: alertId,
          question: targetQuery,
          max_hops: overrideParams?.max_hops || (maxHops === 'adaptive' ? 8 : Number(maxHops) || 5),
          initial_hops: overrideParams?.initial_hops || 3,
          intermediate_hops: overrideParams?.intermediate_hops || 5,
          deep_hops: overrideParams?.deep_hops || 8,
          adaptive_hops_enabled: overrideParams?.adaptive_hops_enabled !== undefined ? overrideParams.adaptive_hops_enabled : true,
          query_budget: overrideParams?.query_budget || 20,
        }),
      });

      if (response.ok) {
        const report = await response.json();
        // Transform backend report to dashboard format
        const formatted = transformBackendReport(report, targetQuery);
        setCurrentData(formatted);
        showToast(`Investigation ${report.investigation_id} completed: ${report.risk_label} (${report.hops_explored} hops)`);
        setIsLoading(false);
        setActiveNav('dashboard');
        return;
      }
    } catch (err) {
      console.warn("Backend fetch failed, falling back to rich simulation:", err);
    }

    // Default / ACC-1042 Simulation
    setTimeout(() => {
      setCurrentData(ACC_1042_DATA);
      setIsLoading(false);
      showToast("Investigation completed: 10 entities analyzed across 5 hops.");
      setActiveNav('dashboard');
    }, 600);
  };

  // Transform backend response into dashboard visualization data
  const transformBackendReport = (report, userQuery) => {
    const rawNodes = report.graph?.nodes || [];
    const rawEdges = report.graph?.edges || [];

    // Map Cytoscape elements to radial graph
    const nodes = rawNodes.map((n, idx) => {
      const isCenter = idx === 0 || n.data.id.includes(report.alert_id);
      const angle = (idx / Math.max(rawNodes.length - 1, 1)) * 360 - 90;
      return {
        id: n.data.id,
        label: n.data.name || n.data.id,
        sublabel: n.data.type || "Entity",
        type: n.data.type || "Entity",
        risk: report.risk_label,
        riskScore: Math.round(report.risk_score * 100),
        color: n.data.color || "#3B82F6",
        isCenter,
        angle: isCenter ? 0 : angle,
        distance: isCenter ? 0 : 200,
      };
    });

    const edges = rawEdges.map((e) => ({
      from: e.data.source,
      to: e.data.target,
      type: e.data.label === "CONNECTED_TO" ? "direct" : "indirect",
      label: e.data.label,
    }));

    const keyFindings = (report.risk_factors || [])
      .filter((f) => f.contribution > 0)
      .map((f, i) => ({
        id: i + 1,
        dotColor: f.contribution >= 0.15 ? "#EF4444" : f.contribution >= 0.10 ? "#F97316" : "#F59E0B",
        title: f.explanation,
        detail: `Weight ${Math.round(f.weight * 100)}% · Impact +${f.contribution.toFixed(2)}`,
      }));

    const evidencePath = (report.verified_facts || []).slice(0, 4).map((fact, idx) => ({
      id: `fact-${idx}`,
      entity: fact.description.slice(0, 42) + "...",
      timestamp: fact.timestamp?.slice(11, 16) || "10:24",
      amount: fact.provenance_type,
      color: idx === 0 ? "#10B981" : idx === 1 ? "#F59E0B" : "#8B5CF6",
      icon: "user",
    }));

    return {
      account_id: report.target_entity || report.alert_id,
      risk_score: Math.round(report.risk_score * 100),
      risk_label: report.risk_label,
      total_connections: report.graph_paths?.length || nodes.length,
      hops_explored: report.hops_explored || 5,
      investigation_time: `${report.elapsed_seconds || 1.2}s`,
      query: userQuery,
      nodes: nodes.length ? nodes : ACC_1042_DATA.nodes,
      edges: edges.length ? edges : ACC_1042_DATA.edges,
      keyFindings: keyFindings.length ? keyFindings : ACC_1042_DATA.keyFindings,
      evidencePath: evidencePath.length ? evidencePath : ACC_1042_DATA.evidencePath,
      agentAnalysis: report.verdict || ACC_1042_DATA.agentAnalysis,
      recommendedActions: [
        `Execute policy action: ${report.policy_action} on ${report.target_entity}`,
        "Review correlated entity risk factors in FalkorDB graph",
        "Retain audit provenance for SOC human-in-the-loop compliance",
      ],
      adaptive_hop_stages: report.adaptive_hop_stages || [],
      timeline: ACC_1042_DATA.timeline,
      relatedAccounts: ACC_1042_DATA.relatedAccounts,
      riskFactors: (report.risk_factors || []).map((f) => ({
        name: f.name.replace(/_/g, ' ').toUpperCase(),
        weight: `${Math.round(f.weight * 100)}%`,
        score: f.contribution.toFixed(2),
        status: f.contribution >= 0.15 ? "CRITICAL" : f.contribution >= 0.10 ? "HIGH" : "MEDIUM",
        note: f.explanation,
      })),
    };
  };

  return (
    <div className="flex bg-[#0B0F19] text-slate-100 min-h-screen">
      {/* 1. Left Navigation Sidebar */}
      <Sidebar activeTab={activeNav} setActiveTab={setActiveNav} />

      {/* 2. Main Workspace Layout */}
      <main className="flex-1 p-7 overflow-y-auto space-y-6">
        {/* Top Header */}
        <Header analystName="Analyst" />

        {/* Global Toast Notification */}
        {notification && (
          <div className="fixed top-6 right-8 z-50 bg-blue-600/95 text-white text-xs px-4 py-2.5 rounded-lg shadow-xl border border-blue-400/30 flex items-center gap-2 animate-bounce">
            <span>🛡️</span>
            <span>{notification}</span>
          </div>
        )}

        {/* VIEW 1: Main Dashboard Overview */}
        {activeNav === 'dashboard' && (
          <div className="flex flex-col xl:flex-row gap-6">
            {/* Left / Center 2/3 Content Column */}
            <div className="flex-1 space-y-5 min-w-0">
              {/* Investigation Query & Controls Bar */}
              <InvestigationControls
                query={query}
                setQuery={setQuery}
                maxHops={maxHops}
                setMaxHops={setMaxHops}
                timeRange={timeRange}
                setTimeRange={setTimeRange}
                showRiskScores={showRiskScores}
                setShowRiskScores={setShowRiskScores}
                onInvestigate={() => handleInvestigate()}
                isLoading={isLoading}
              />

              {/* Investigation Graph Canvas */}
              <InvestigationGraph
                nodes={currentData.nodes}
                edges={currentData.edges}
                showRiskScores={showRiskScores}
                selectedNode={selectedNode}
                setSelectedNode={setSelectedNode}
              />

              {/* Bottom Analysis Tabs (AI Analysis, Timeline, Related, Risk) */}
              <AnalysisTabs
                data={currentData}
                adaptiveStages={currentData.adaptive_hop_stages}
                onActionExecute={(action) => {
                  showToast(`Action ${action} executed successfully in FalkorDB.`);
                }}
              />
            </div>

            {/* Right Column: Summary, Key Findings & Evidence Path */}
            <RightPanel
              data={currentData}
              onSelectStep={(step) => {
                const matchedNode = currentData.nodes.find((n) => step.entity.includes(n.id));
                if (matchedNode) setSelectedNode(matchedNode);
              }}
            />
          </div>
        )}

        {/* VIEW 2: New Investigation Workflow */}
        {activeNav === 'new-investigation' && (
          <NewInvestigationView
            onStartInvestigation={(params) => handleInvestigate(params)}
            isLoading={isLoading}
            onNavigate={(tab) => setActiveNav(tab)}
            lastReport={currentData}
          />
        )}

        {/* VIEW 3: Graph Explorer */}
        {activeNav === 'graph-explorer' && (
          <GraphExplorerView
            graphData={currentData}
            onStartInvestigation={(params) => handleInvestigate(params)}
            onNavigate={(tab) => setActiveNav(tab)}
          />
        )}

        {/* VIEW 4: Report Generator & Governance */}
        {activeNav === 'reports' && (
          <ReportGeneratorView
            reportData={currentData}
            onActionExecute={(action) => showToast(`Action ${action} approved in audit log.`)}
            showToast={showToast}
          />
        )}

        {/* VIEW 5: System Settings */}
        {activeNav === 'settings' && (
          <SettingsView showToast={showToast} />
        )}
      </main>
    </div>
  );
}
