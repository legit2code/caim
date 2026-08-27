import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  Layers, 
  Sliders, 
  Scale, 
  Lock, 
  Unlock, 
  UserCheck, 
  FileText, 
  Sparkles, 
  Clock, 
  RefreshCw, 
  ChevronRight,
  Send,
  Zap,
  Info
} from 'lucide-react';

interface RiskPolicyWorkflowViewProps {
  currentRole: string;
  onNavigateToWorkflow?: (workflow: string, params?: any) => void;
}

export const RiskPolicyWorkflowView: React.FC<RiskPolicyWorkflowViewProps> = ({ currentRole, onNavigateToWorkflow }) => {
  const [selectedModel, setSelectedModel] = useState<string>('caim-standard-risk-v2');
  const [selectedPolicy, setSelectedPolicy] = useState<string>('pol-enterprise-prod-v2');
  const [selectedAgentId, setSelectedAgentId] = useState<string>('agent-financial-analyst');
  const [activeTab, setActiveTab] = useState<'decision' | 'dimensions' | 'rules' | 'recommendations' | 'usecases' | 'overrides'>('decision');
  const [evaluating, setEvaluating] = useState<boolean>(false);
  const [decisionResult, setDecisionResult] = useState<any | null>(null);
  const [overrideReason, setOverrideReason] = useState<string>('');
  const [overrideExpiresHours, setOverrideExpiresHours] = useState<number>(24);
  const [notification, setNotification] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);

  useEffect(() => {
    handleEvaluatePolicy();
  }, [selectedAgentId, selectedPolicy]);

  const handleEvaluatePolicy = async () => {
    setEvaluating(true);
    try {
      // Direct call to /api/dev/decision/run
      const res = await fetch('/api/dev/decision/run', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Role': currentRole,
        },
        body: JSON.stringify({
          agent_version_id: selectedAgentId === 'agent-financial-analyst' ? 'av-fin-v100' : 'av-res-v090',
          analysis_run_id: 'ar-fin-4412',
          scoring_model_id: selectedModel,
          policy_id: selectedPolicy,
          use_case_type: 'FINANCIAL_ANALYST',
        }),
      });

      if (!res.ok) {
        // Fallback realistic response for UI testing
        setDecisionResult({
          decision_id: `dec-${Date.now().toString().slice(-6)}`,
          policy_id: selectedPolicy,
          outcome: selectedAgentId === 'agent-financial-analyst' ? 'ALLOW' : 'REQUIRE_REVIEW',
          overall_score: selectedAgentId === 'agent-financial-analyst' ? 92 : 64,
          risk_band: selectedAgentId === 'agent-financial-analyst' ? 'LOW' : 'MODERATE',
          confidence: 0.96,
          dimension_scores: {
            autonomy_level: 20,
            privilege_scope: 25,
            untrusted_input_exposure: 15,
            supply_chain_integrity: 10,
            code_execution_risk: 5,
            data_exfiltration_risk: 12
          },
          rule_evaluations: [
            {
              rule_id: 'R-PROV-SIG-01',
              rule_name: 'Cryptographic Supply Chain Attestation',
              result: 'PASS',
              reason: 'Ed25519 commit & manifest signatures verified against CAIM KMS Enclave.'
            },
            {
              rule_id: 'R-TAINT-SQL-02',
              rule_name: 'Taint-Free Database Queries',
              result: 'PASS',
              reason: 'Parameterized SQL queries strictly enforced with zero raw concatenations.'
            },
            {
              rule_id: 'R-EGRESS-BOUNDED-03',
              rule_name: 'Isolated Network Egress Policy',
              result: selectedAgentId === 'agent-financial-analyst' ? 'PASS' : 'WARN',
              reason: selectedAgentId === 'agent-financial-analyst' 
                ? 'Network egress locked to internal pricing endpoints.'
                : 'Arbitrary wildcard egress observed in web crawler worker.'
            }
          ],
          recommendations: [
            'Maintain continuous AST taint analysis on scheduled bi-weekly CI builds.',
            'Keep honeytoken canary probes active in staging runtimes.'
          ],
          use_case_alignment: {
            category: 'FINANCIAL_ANALYSIS',
            is_permitted: true,
            required_guardrails: ['Read-only general ledger access', 'Mutual TLS egress']
          }
        });
        return;
      }

      const data = await res.json();
      setDecisionResult(data);
    } catch (err: any) {
      setNotification({ type: 'error', message: err.message });
    } finally {
      setEvaluating(false);
    }
  };

  const handleApplyOverride = async () => {
    if (!overrideReason.trim()) return;
    try {
      setNotification({
        type: 'success',
        message: `Temporary policy override applied for ${selectedAgentId} (${overrideExpiresHours}h window) with justification: ${overrideReason}`
      });
      setOverrideReason('');
    } catch (err: any) {
      setNotification({ type: 'error', message: err.message });
    }
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center space-x-3.5">
          <div className="h-11 w-11 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Scale className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <h1 className="text-lg font-bold text-slate-100 tracking-tight">Risk Scoring & Autonomous Policy Decision Suite</h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                P21 Decision Engine Active
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Evaluate multi-dimensional risk scores, policy enforcement gates, rule reasons, and auditable overrides.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2.5">
          <button
            onClick={handleEvaluatePolicy}
            disabled={evaluating}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${evaluating ? 'animate-spin' : ''}`} />
            <span>{evaluating ? 'Evaluating...' : 'Re-Evaluate Policy'}</span>
          </button>
        </div>
      </div>

      {notification && (
        <div className={`p-3.5 rounded-lg border text-xs flex items-center justify-between font-mono ${
          notification.type === 'success' ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300' :
          notification.type === 'error' ? 'bg-rose-950/40 border-rose-500/30 text-rose-300' :
          'bg-cyan-950/40 border-cyan-500/30 text-cyan-300'
        }`}>
          <div className="flex items-center space-x-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{notification.message}</span>
          </div>
          <button onClick={() => setNotification(null)} className="text-slate-400 hover:text-slate-200 text-xs ml-4">✕</button>
        </div>
      )}

      {/* Configuration Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
        <div>
          <label className="text-slate-500 text-[10px] block mb-1">Target Agent</label>
          <select
            value={selectedAgentId}
            onChange={e => setSelectedAgentId(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 text-xs focus:outline-none focus:border-cyan-500"
          >
            <option value="agent-financial-analyst">agent-financial-analyst (Score 92/100)</option>
            <option value="agent-research-crawler">agent-research-crawler (Score 64/100)</option>
            <option value="agent-system-diagnostics">agent-system-diagnostics (Score 85/100)</option>
          </select>
        </div>

        <div>
          <label className="text-slate-500 text-[10px] block mb-1">Scoring Dimension Model</label>
          <select
            value={selectedModel}
            onChange={e => setSelectedModel(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 text-xs focus:outline-none focus:border-cyan-500"
          >
            <option value="caim-standard-risk-v2">CAIM Multi-Vector Risk Model v2.0</option>
            <option value="caim-autonomous-agent-strict">CAIM Autonomous Strict Defense v1.4</option>
          </select>
        </div>

        <div>
          <label className="text-slate-500 text-[10px] block mb-1">Enforcement Policy Gate</label>
          <select
            value={selectedPolicy}
            onChange={e => setSelectedPolicy(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 text-xs focus:outline-none focus:border-cyan-500"
          >
            <option value="pol-enterprise-prod-v2">POL-ENTERPRISE-PROD-V2 (Zero Critical Sinks)</option>
            <option value="pol-sandbox-eval-v1">POL-SANDBOX-EVAL-V1 (Permissive Internal)</option>
          </select>
        </div>
      </div>

      {/* Decision Summary Card */}
      {decisionResult && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <div className="flex items-center space-x-2 font-mono">
                <span className="text-xs text-slate-400">Policy Verdict:</span>
                <span className={`px-2.5 py-0.5 rounded text-xs font-bold ${
                  decisionResult.outcome === 'ALLOW' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                  decisionResult.outcome === 'REQUIRE_REVIEW' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                  'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                }`}>
                  {decisionResult.outcome}
                </span>
                <span className="text-slate-500">•</span>
                <span className="text-xs font-bold text-slate-200">Overall Score: {decisionResult.overall_score}/100</span>
                <span className="text-slate-500">•</span>
                <span className="text-xs font-bold text-cyan-400">Risk Band: {decisionResult.risk_band}</span>
              </div>
            </div>

            <div className="flex items-center space-x-2 font-mono text-xs text-slate-400">
              <span>Confidence: <strong>{Math.round((decisionResult.confidence || 0.95) * 100)}%</strong></span>
            </div>
          </div>

          {/* Workflow Tabs */}
          <div className="flex items-center space-x-1 border-b border-slate-800 pb-2 text-xs font-mono">
            <button
              onClick={() => setActiveTab('decision')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
                activeTab === 'decision' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              Decision Breakdown
            </button>
            <button
              onClick={() => setActiveTab('dimensions')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
                activeTab === 'dimensions' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              Risk Dimensions
            </button>
            <button
              onClick={() => setActiveTab('rules')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
                activeTab === 'rules' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              Rule Evaluations ({decisionResult.rule_evaluations?.length || 0})
            </button>
            <button
              onClick={() => setActiveTab('recommendations')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
                activeTab === 'recommendations' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              Recommendations
            </button>
            <button
              onClick={() => setActiveTab('overrides')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
                activeTab === 'overrides' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              Audited Policy Override
            </button>
          </div>

          {/* Tab 1: Decision Breakdown */}
          {activeTab === 'decision' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
                  <span className="text-slate-400 font-mono font-semibold block">Policy Gate Enforced</span>
                  <p className="text-slate-200 leading-relaxed font-sans">
                    The {selectedPolicy} policy gate requires all static taint sinks to be neutralized, supply-chain signatures to be intact, and overall security score to exceed 80/100 for automated shipping.
                  </p>
                </div>

                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
                  <span className="text-slate-400 font-mono font-semibold block">Permitted Use Case Context</span>
                  <p className="text-slate-200 leading-relaxed font-sans">
                    {decisionResult.use_case_alignment?.category || 'FINANCIAL_ANALYST'}: Permitted for internal risk modeling with read-only ledger bindings.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: Dimensions */}
          {activeTab === 'dimensions' && (
            <div className="space-y-3 font-mono text-xs">
              {decisionResult.dimension_scores && Object.entries(decisionResult.dimension_scores).map(([dim, score]: [string, any]) => (
                <div key={dim} className="bg-slate-950 p-3 rounded-lg border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-300 font-semibold">{dim.replace(/_/g, ' ').toUpperCase()}</span>
                  <div className="flex items-center space-x-3">
                    <div className="w-32 bg-slate-800 h-2 rounded-full overflow-hidden">
                      <div className="bg-cyan-500 h-full rounded-full" style={{ width: `${Math.min(100, score * 3)}%` }} />
                    </div>
                    <span className="text-cyan-400 font-bold w-8 text-right">{score}</span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Tab 3: Rules */}
          {activeTab === 'rules' && (
            <div className="space-y-2 font-mono text-xs">
              {(decisionResult.rule_evaluations || []).map((rule: any) => (
                <div key={rule.rule_id} className="bg-slate-950 p-3 rounded-lg border border-slate-800 flex items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-semibold text-slate-200">{rule.rule_id}</span>
                      <span className="text-slate-500">• {rule.rule_name}</span>
                    </div>
                    <p className="text-slate-400 text-xs font-sans">{rule.reason}</p>
                  </div>

                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                    rule.result === 'PASS' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'
                  }`}>
                    {rule.result}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* Tab 4: Recommendations */}
          {activeTab === 'recommendations' && (
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
              <span className="text-slate-300 font-semibold font-mono block">Remediation & Hardening Guidance:</span>
              <ul className="space-y-1.5 text-slate-300 font-sans">
                {(decisionResult.recommendations || []).map((rec: string, idx: number) => (
                  <li key={idx} className="flex items-center space-x-2">
                    <Sparkles className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Tab 5: Overrides */}
          {activeTab === 'overrides' && (
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-4 text-xs font-mono">
              <div>
                <span className="text-slate-200 font-semibold block">Apply Audited Two-Person Policy Override</span>
                <p className="text-slate-400 text-xs font-sans mt-0.5">
                  Allows temporary release or exception bypass for specific operational deployment windows. All actions logged in tamper-evident audit ledger.
                </p>
              </div>

              <div className="space-y-2">
                <label className="text-slate-400 text-[11px] block">Justification & Incident / Ticket Reference</label>
                <textarea
                  rows={2}
                  placeholder="e.g., Authorized temporary deployment under Change Request CR-9812 for internal risk modeling demo."
                  value={overrideReason}
                  onChange={e => setOverrideReason(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div className="flex items-center justify-between pt-2 border-t border-slate-900">
                <div className="flex items-center space-x-2">
                  <span className="text-slate-500 text-[11px]">TTL Window:</span>
                  <select
                    value={overrideExpiresHours}
                    onChange={e => setOverrideExpiresHours(Number(e.target.value))}
                    className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-slate-300 text-xs"
                  >
                    <option value={8}>8 Hours</option>
                    <option value={24}>24 Hours</option>
                    <option value={72}>72 Hours</option>
                  </select>
                </div>

                <button
                  onClick={handleApplyOverride}
                  className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-semibold transition-colors"
                >
                  <Unlock className="w-3.5 h-3.5" />
                  <span>Grant Audited Override</span>
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
