import React, { useState } from 'react';
import { 
  Activity, 
  Layers, 
  RefreshCw, 
  RotateCw, 
  Server, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  Play, 
  Pause, 
  Database, 
  Clock, 
  DollarSign, 
  Zap, 
  Cpu, 
  Terminal,
  Filter
} from 'lucide-react';

interface OperationsWorkflowViewProps {
  currentRole: string;
  onNavigateToWorkflow?: (workflow: string, params?: any) => void;
}

export const OperationsWorkflowView: React.FC<OperationsWorkflowViewProps> = ({ currentRole, onNavigateToWorkflow }) => {
  const [activeTab, setActiveTab] = useState<'workflows' | 'queues' | 'dlq' | 'workers' | 'costs'>('workflows');
  const [isReplaying, setIsReplaying] = useState<boolean>(false);
  const [notification, setNotification] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);

  const queues = [
    { name: 'discovery.crawler.v1', active: 2, leased: 1, failed: 0, concurrency: 8 },
    { name: 'analysis.ast.v1', active: 4, leased: 2, failed: 0, concurrency: 16 },
    { name: 'analysis.taint.v1', active: 1, leased: 1, failed: 0, concurrency: 8 },
    { name: 'sandbox.scenarios.v1', active: 0, leased: 0, failed: 0, concurrency: 4 },
    { name: 'decision.policy.v1', active: 0, leased: 0, failed: 0, concurrency: 8 }
  ];

  const dlqJobs = [
    {
      job_id: 'job-dlq-ast-981',
      queue: 'analysis.ast.v1.dlq',
      error_message: 'Connection timeout on ast-node-04 during dynamic import indexing',
      attempts: 3,
      created_at: '2026-08-26T11:45:00Z'
    }
  ];

  const workers = [
    { id: 'worker-ast-01', type: 'AST_PARSER', status: 'HEALTHY', memory_mb: 240, cpu_pct: 12, uptime: '48h 12m' },
    { id: 'worker-taint-01', type: 'TAINT_ENGINE', status: 'HEALTHY', memory_mb: 512, cpu_pct: 28, uptime: '48h 12m' },
    { id: 'worker-sbx-01', type: 'SANDBOX_HYPERVISOR', status: 'HEALTHY', memory_mb: 1024, cpu_pct: 5, uptime: '48h 12m' }
  ];

  const handleReplayDlq = async (jobId: string) => {
    setIsReplaying(true);
    try {
      await new Promise(r => setTimeout(r, 400));
      setNotification({
        type: 'success',
        message: `Job ${jobId} successfully re-enqueued to primary processing queue.`
      });
    } finally {
      setIsReplaying(false);
    }
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center space-x-3.5">
          <div className="h-11 w-11 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Activity className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <h1 className="text-lg font-bold text-slate-100 tracking-tight">Platform Operations, Worker Topologies & DLQ Management</h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                P27 / P29 Queues & Workers Active
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Manage distributed message queues, worker health, Dead-Letter-Queue replay recovery, and cluster utilization.
            </p>
          </div>
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

      {/* Main Operations Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
        {/* Tab Navigation */}
        <div className="flex items-center space-x-1 border-b border-slate-800 pb-2 text-xs font-mono">
          <button
            onClick={() => setActiveTab('workflows')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'workflows' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            System Metrics
          </button>
          <button
            onClick={() => setActiveTab('queues')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'queues' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            Message Queues ({queues.length})
          </button>
          <button
            onClick={() => setActiveTab('dlq')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'dlq' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            Dead Letter Queue ({dlqJobs.length})
          </button>
          <button
            onClick={() => setActiveTab('workers')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'workers' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            Worker Topology ({workers.length})
          </button>
        </div>

        {/* Tab 1: System Metrics */}
        {activeTab === 'workflows' && (
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 font-mono text-xs">
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
              <span className="text-slate-500 text-[10px] block">Cluster Uptime</span>
              <span className="text-emerald-400 text-lg font-bold">99.99%</span>
            </div>
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
              <span className="text-slate-500 text-[10px] block">Active Workflows</span>
              <span className="text-cyan-400 text-lg font-bold">7 Concurrent</span>
            </div>
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
              <span className="text-slate-500 text-[10px] block">Pipeline Latency p95</span>
              <span className="text-slate-200 text-lg font-bold">420ms</span>
            </div>
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
              <span className="text-slate-500 text-[10px] block">DLQ Incident Rate</span>
              <span className="text-emerald-400 text-lg font-bold">0.01%</span>
            </div>
          </div>
        )}

        {/* Tab 2: Queues */}
        {activeTab === 'queues' && (
          <div className="space-y-3 font-mono text-xs">
            {queues.map((q, idx) => (
              <div key={idx} className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="font-semibold text-slate-200">{q.name}</span>
                  <span className="text-slate-500 text-[11px] block">Concurrency Limit: {q.concurrency}</span>
                </div>
                <div className="flex items-center space-x-4 text-[11px]">
                  <span className="text-cyan-400">Active: <strong>{q.active}</strong></span>
                  <span className="text-amber-400">Leased: <strong>{q.leased}</strong></span>
                  <span className="text-emerald-400">Failed: <strong>{q.failed}</strong></span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Tab 3: DLQ */}
        {activeTab === 'dlq' && (
          <div className="space-y-3 font-mono text-xs">
            {dlqJobs.map(job => (
              <div key={job.job_id} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-rose-400">{job.job_id}</span>
                  <button
                    onClick={() => handleReplayDlq(job.job_id)}
                    disabled={isReplaying}
                    className="flex items-center space-x-1 px-3 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-[11px] font-semibold transition-colors"
                  >
                    <RotateCw className={`w-3 h-3 ${isReplaying ? 'animate-spin' : ''}`} />
                    <span>Replay Job</span>
                  </button>
                </div>
                <p className="text-slate-300 text-xs font-sans">{job.error_message}</p>
                <div className="flex items-center space-x-3 text-slate-500 text-[11px]">
                  <span>Origin: {job.queue}</span>
                  <span>•</span>
                  <span>Attempts: {job.attempts}</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Tab 4: Workers */}
        {activeTab === 'workers' && (
          <div className="space-y-3 font-mono text-xs">
            {workers.map(w => (
              <div key={w.id} className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="flex items-center space-x-2">
                    <Server className="w-4 h-4 text-cyan-400" />
                    <span className="font-semibold text-slate-200">{w.id}</span>
                  </div>
                  <span className="text-slate-500 text-[11px] block mt-1">{w.type} • Uptime: {w.uptime}</span>
                </div>

                <div className="flex items-center space-x-4 text-[11px]">
                  <span className="text-slate-400">RAM: <strong className="text-slate-200">{w.memory_mb}MB</strong></span>
                  <span className="text-slate-400">CPU: <strong className="text-slate-200">{w.cpu_pct}%</strong></span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 font-semibold">
                    {w.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
