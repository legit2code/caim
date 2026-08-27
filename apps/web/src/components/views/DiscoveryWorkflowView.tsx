import React, { useState } from 'react';
import { 
  Search, 
  RefreshCw, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  FolderGit2, 
  GitBranch, 
  ShieldCheck, 
  Layers, 
  Clock, 
  Filter, 
  Play, 
  Plus, 
  UserCheck, 
  ExternalLink,
  ChevronRight,
  Sparkles,
  Info
} from 'lucide-react';

interface DiscoveryWorkflowViewProps {
  currentRole: string;
  onNavigateToWorkflow?: (workflow: string, params?: any) => void;
}

export const DiscoveryWorkflowView: React.FC<DiscoveryWorkflowViewProps> = ({ currentRole, onNavigateToWorkflow }) => {
  const [activeTab, setActiveTab] = useState<'scans' | 'adapters' | 'candidates' | 'review' | 'freshness'>('scans');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [notification, setNotification] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);

  const adapters = [
    { name: 'GitHub Enterprise Adapter', status: 'HEALTHY', repos_scanned: 14, last_poll: '2 mins ago', rate_limit: '4,890 / 5,000' },
    { name: 'GitLab Internal Org Adapter', status: 'HEALTHY', repos_scanned: 8, last_poll: '5 mins ago', rate_limit: '9,920 / 10,000' },
    { name: 'Docker / OCI Registry Adapter', status: 'HEALTHY', repos_scanned: 22, last_poll: '1 min ago', rate_limit: 'Unlimited' }
  ];

  const candidates = [
    {
      candidate_id: 'cand-fin-analyst',
      name: 'financial-analyst-agent',
      source: 'github.com/caim-org/financial-analyst-agent',
      confidence: 0.98,
      framework: 'TypeScript (LangChain)',
      status: 'RESOLVED_CANONICAL',
      discovered_at: '2026-08-26T12:00:00Z'
    },
    {
      candidate_id: 'cand-web-crawler',
      name: 'autonomous-web-crawler',
      source: 'github.com/caim-community/web-researcher',
      confidence: 0.89,
      framework: 'Python (AutoGen)',
      status: 'UNDER_REVIEW',
      discovered_at: '2026-08-25T09:30:00Z'
    }
  ];

  const handleRunScan = async () => {
    setIsScanning(true);
    try {
      await new Promise(r => setTimeout(r, 600));
      setNotification({
        type: 'success',
        message: 'Discovery scan completed! 24 repositories scanned, 2 candidate agents reconciled.'
      });
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center space-x-3.5">
          <div className="h-11 w-11 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Search className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <h1 className="text-lg font-bold text-slate-100 tracking-tight">Agent Discovery, Source Ingestion & Identity Resolution</h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                P02 / P03 Discovery Active
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Monitor source adapter health, candidate agent discovery trees, identity disambiguation, and coverage freshness.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2.5">
          <button
            onClick={handleRunScan}
            disabled={isScanning}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition-colors disabled:opacity-50"
          >
            <Play className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
            <span>{isScanning ? 'Scanning Sources...' : 'Trigger Discovery Scan'}</span>
          </button>
          
          <button
            onClick={() => onNavigateToWorkflow?.('agents')}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono transition-colors"
          >
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>Agent Catalog</span>
          </button>
        </div>
      </div>

      {notification && (
        <div className={`p-3.5 rounded-lg border text-xs flex items-center justify-between font-mono ${
          notification.type === 'success' ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300' :
          'bg-cyan-950/40 border-cyan-500/30 text-cyan-300'
        }`}>
          <div className="flex items-center space-x-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{notification.message}</span>
          </div>
          <button onClick={() => setNotification(null)} className="text-slate-400 hover:text-slate-200 text-xs ml-4">✕</button>
        </div>
      )}

      {/* Main Discovery Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
        {/* Navigation Tabs */}
        <div className="flex items-center space-x-1 border-b border-slate-800 pb-2 text-xs font-mono">
          <button
            onClick={() => setActiveTab('scans')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'scans' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            Discovery Scans
          </button>
          <button
            onClick={() => setActiveTab('adapters')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'adapters' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            Source Adapters ({adapters.length})
          </button>
          <button
            onClick={() => setActiveTab('candidates')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'candidates' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            Discovered Candidates ({candidates.length})
          </button>
        </div>

        {/* Tab 1: Scans */}
        {activeTab === 'scans' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                <span className="text-slate-500 text-[10px] block">Total Sources Polled</span>
                <span className="text-cyan-400 text-lg font-bold">44 Repositories</span>
              </div>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                <span className="text-slate-500 text-[10px] block">Discovered Agents</span>
                <span className="text-emerald-400 text-lg font-bold">3 Canonical Agents</span>
              </div>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                <span className="text-slate-500 text-[10px] block">Freshness SLA</span>
                <span className="text-slate-200 text-lg font-bold">100% Up-To-Date</span>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Adapters */}
        {activeTab === 'adapters' && (
          <div className="space-y-3 font-mono text-xs">
            {adapters.map((ad, idx) => (
              <div key={idx} className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="flex items-center space-x-2">
                    <FolderGit2 className="w-4 h-4 text-cyan-400" />
                    <span className="font-semibold text-slate-200">{ad.name}</span>
                  </div>
                  <span className="text-slate-500 text-[11px] block mt-1">Rate Limit: {ad.rate_limit} • Last Polled: {ad.last_poll}</span>
                </div>

                <div className="text-right">
                  <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 font-semibold">
                    {ad.status}
                  </span>
                  <span className="text-slate-500 text-[11px] block mt-1">{ad.repos_scanned} Repos</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Tab 3: Candidates */}
        {activeTab === 'candidates' && (
          <div className="space-y-3 font-mono text-xs">
            {candidates.map(cand => (
              <div key={cand.candidate_id} className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="font-bold text-cyan-400">{cand.name}</span>
                    <span className="text-slate-500">• {cand.framework}</span>
                  </div>
                  <span className="text-slate-400 text-[11px] block mt-1">{cand.source}</span>
                </div>

                <div className="text-right">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                    cand.status === 'RESOLVED_CANONICAL' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'
                  }`}>
                    {cand.status}
                  </span>
                  <span className="text-slate-500 text-[11px] block mt-1">{Math.round(cand.confidence * 100)}% Confidence</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
