import React, { useState } from 'react';
import { 
  Lock, 
  ShieldCheck, 
  ShieldAlert, 
  Layers, 
  CheckCircle2, 
  Clock, 
  Search, 
  FileText, 
  Scale, 
  Users, 
  Sparkles, 
  Database,
  ExternalLink,
  ChevronRight,
  Filter,
  Check,
  X
} from 'lucide-react';

interface GovernanceWorkflowViewProps {
  currentRole: string;
  onNavigateToWorkflow?: (workflow: string, params?: any) => void;
}

export const GovernanceWorkflowView: React.FC<GovernanceWorkflowViewProps> = ({ currentRole, onNavigateToWorkflow }) => {
  const [activeTab, setActiveTab] = useState<'ontology' | 'policies' | 'audit' | 'queues'>('ontology');
  const [searchAudit, setSearchAudit] = useState<string>('');

  const auditEvents = [
    {
      id: 'AUD-2026-0091',
      actor: 'security-auditor@caim.internal',
      action: 'POLICY_OVERRIDE_GRANTED',
      target: 'agent-financial-analyst (v1.0.0)',
      timestamp: '2026-08-26T12:05:00Z',
      details: 'Granted 24h temporary bypass under ticket CR-9812 for sandbox stress testing.'
    },
    {
      id: 'AUD-2026-0090',
      actor: 'release-manager@caim.internal',
      action: 'PACKAGE_BUNDLE_SIGNED',
      target: 'pkg-fin-v100-prod',
      timestamp: '2026-08-26T12:10:00Z',
      details: 'Signed deterministic bundle manifest with root KMS Ed25519 key.'
    }
  ];

  const filteredAudits = auditEvents.filter(a => 
    a.actor.toLowerCase().includes(searchAudit.toLowerCase()) ||
    a.action.toLowerCase().includes(searchAudit.toLowerCase()) ||
    a.target.toLowerCase().includes(searchAudit.toLowerCase())
  );

  return (
    <div className="space-y-6 font-sans">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center space-x-3.5">
          <div className="h-11 w-11 rounded-xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
            <Lock className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <h1 className="text-lg font-bold text-slate-100 tracking-tight">CANE Governance, Ontologies, Policies & Audit Trails</h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                P01 / P21 Governance Active
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Inspect CANE Ontology v2.0.1 specifications, active rulesets, cryptographic audit logs, and review queues.
            </p>
          </div>
        </div>
      </div>

      {/* Main Governance Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
        {/* Navigation Tabs */}
        <div className="flex items-center space-x-1 border-b border-slate-800 pb-2 text-xs font-mono">
          <button
            onClick={() => setActiveTab('ontology')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'ontology' ? 'bg-purple-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            CANE Ontology (v2.0.1)
          </button>
          <button
            onClick={() => setActiveTab('audit')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'audit' ? 'bg-purple-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            Security Audit Trail ({auditEvents.length})
          </button>
        </div>

        {/* Tab 1: Ontology */}
        {activeTab === 'ontology' && (
          <div className="space-y-4 font-mono text-xs">
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
              <span className="text-slate-400 font-semibold block">Canonical Agent Node & Evidence (CANE) Ontology v2.0.1</span>
              <p className="text-slate-300 font-sans text-xs leading-relaxed">
                The CANE Ontology formalizes the epistemic boundaries between Grounded Observations, Synthesized Assertions, and Policy-Binding Claims across 71 static, control-flow, and dynamic analysis engines.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px] block">Formal Schemas</span>
                <span className="text-purple-400 text-lg font-bold">28 Core Schemas</span>
              </div>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px] block">Analysis Engines</span>
                <span className="text-cyan-400 text-lg font-bold">71 Specialized Engines</span>
              </div>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px] block">Policy Gates</span>
                <span className="text-emerald-400 text-lg font-bold">14 Zero-Trust Rules</span>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Security Audit Trail */}
        {activeTab === 'audit' && (
          <div className="space-y-4">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search audit actions, actors, targets..."
                value={searchAudit}
                onChange={e => setSearchAudit(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500 font-mono"
              />
            </div>

            <div className="space-y-3 font-mono text-xs">
              {filteredAudits.map(evt => (
                <div key={evt.id} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-purple-400">{evt.id}</span>
                    <span className="text-slate-500 text-[11px]">{new Date(evt.timestamp).toUTCString()}</span>
                  </div>

                  <div className="flex items-center space-x-2 text-[11px]">
                    <span className="text-slate-300 font-semibold">{evt.actor}</span>
                    <span className="text-slate-500">performed</span>
                    <span className="text-cyan-400 font-semibold">[{evt.action}]</span>
                    <span className="text-slate-500">on</span>
                    <span className="text-slate-300">{evt.target}</span>
                  </div>

                  <p className="text-slate-400 font-sans text-xs pt-1">{evt.details}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
