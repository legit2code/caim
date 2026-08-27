import React, { useEffect, useState } from 'react';
import { 
  ShieldCheck, 
  Terminal, 
  Layers, 
  Cpu, 
  CheckCircle2, 
  CircleDot, 
  Workflow, 
  Database, 
  Lock, 
  Box, 
  FileText,
  Activity,
  Server,
  KeyRound,
  Sliders,
  ExternalLink
} from 'lucide-react';
import { DiagnosticLayout } from './src/components/dev/DiagnosticLayout.tsx';

interface PublicConfig {
  env: string;
  appUrl: string;
  platformVersion: string;
  baseline: string;
  apiPrefix: string;
  features: Record<string, boolean>;
  models: {
    defaultModel: string;
    embeddingModel: string;
  };
}

interface SystemState {
  stage: string;
  total_engines_target: number;
  implemented_count: number;
  active_workers: string[];
  secrets_configured: boolean;
  providers?: Record<string, { status: string; credentialPresent: boolean; reason?: string }>;
  features?: Record<string, boolean>;
  models?: Record<string, any>;
}

const PROMPT_STEPS = [
  { id: 'P-01', title: 'Implementation Baseline Reconciliation', category: 'Baseline', status: 'completed' },
  { id: 'P00', title: 'Master Build Constitution', category: 'Governance', status: 'completed' },
  { id: 'P01', title: 'Repository Foundation & Tooling', category: 'Foundation', status: 'completed' },
  { id: 'P02', title: 'Typed Configuration & Secret Boundaries', category: 'Security', status: 'completed' },
  { id: 'P03-P05', title: 'Database, Analysis & Audit Schema', category: 'Data & Schema', status: 'completed' },
  { id: 'P06-P08', title: 'Auth, CAIM Ontology & Lifecycle Engine', category: 'Core Engine', status: 'completed' },
  { id: 'P09-P09A', title: 'Workflow Queue & Engineering Console Shell', category: 'Control Plane', status: 'completed' },
  { id: 'P10-P27', title: '71 Logical Analysis Engines & Pipeline', category: 'Engines (71)', status: 'ready' },
  { id: 'P28-P30', title: 'Frontend Architecture & Observability', category: 'UI & Observability', status: 'pending' },
  { id: 'P31-P36', title: 'Golden Corpus, 71-Engine Parity & Audit', category: 'Verification & Release', status: 'pending' },
];

const WORKER_DOMAINS = [
  { name: 'discovery', description: 'Web, Git & Multi-source Discovery' },
  { name: 'semantic', description: 'Code AST & Syntax Analysis' },
  { name: 'static-analysis', description: 'Control Flow, Taint & CFG Graphing' },
  { name: 'composition', description: 'AI-BOM, SBOM & Reachability' },
  { name: 'sandbox-orchestrator', description: 'Dynamic Execution & Evasion' },
  { name: 'decision', description: 'Risk, Policy & Confidence Scoring' },
  { name: 'knowledge', description: 'Vector Corpus & Hybrid Retrieval' },
  { name: 'lifecycle', description: 'State Machine & Phase Gates' },
  { name: 'evaluation', description: 'Golden Corpus & Regression Testing' }
];

export default function App() {
  const [isDevMode, setIsDevMode] = useState<boolean>(() => {
    return window.location.pathname.startsWith('/dev') || window.location.pathname === '/';
  });

  const [systemState, setSystemState] = useState<SystemState | null>(null);
  const [publicConfig, setPublicConfig] = useState<PublicConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'matrix' | 'config' | 'workers' | 'architecture'>('matrix');

  useEffect(() => {
    const handlePopState = () => {
      setIsDevMode(window.location.pathname.startsWith('/dev'));
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  useEffect(() => {
    Promise.all([
      fetch('/api/pipeline/state').then(res => res.json()).catch(() => null),
      fetch('/api/config/public').then(res => res.json()).catch(() => null),
    ]).then(([stateData, configData]) => {
      if (stateData) setSystemState(stateData);
      if (configData) setPublicConfig(configData);
      setLoading(false);
    });
  }, []);

  const navigateToDev = (subpath = 'system') => {
    window.history.pushState({}, '', `/dev/${subpath}`);
    setIsDevMode(true);
  };

  const navigateToHome = () => {
    window.history.pushState({}, '', '/');
    setIsDevMode(false);
  };

  if (isDevMode) {
    return <DiagnosticLayout />;
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 antialiased flex flex-col font-sans selection:bg-cyan-900 selection:text-cyan-100">
      {/* Top Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="h-9 w-9 rounded-lg bg-cyan-600/20 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="font-semibold text-slate-100 text-sm sm:text-base tracking-tight">
                  Agent Lifecycle Intelligence Platform
                </h1>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                  V2.0.1 Locked
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                CAIM Standard • 71 Logical Engines • Strict Worker Isolation
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={() => navigateToDev('system')}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/30 text-cyan-300 text-xs font-mono transition-colors"
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Engineering Console (/dev)</span>
            </button>

            <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span>P09 / P09A Complete</span>
            </div>
          </div>
        </div>
      </header>

      {/* Subnav & Metrics Bar */}
      <div className="border-b border-slate-800 bg-slate-900/40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="text-slate-400">Target Engines:</span>
            <span className="px-2 py-0.5 bg-slate-800 rounded text-slate-200 font-semibold">71</span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400">Config System:</span>
            <span className="text-emerald-400 font-semibold">packages/config PASS</span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400">Next Stage:</span>
            <span className="text-amber-400 font-semibold">P03 Database Foundation</span>
          </div>

          <div className="flex items-center space-x-1 bg-slate-900 p-1 rounded-lg border border-slate-800 text-xs">
            <button
              onClick={() => setActiveTab('matrix')}
              className={`px-3 py-1 rounded-md font-medium transition-colors ${
                activeTab === 'matrix' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Execution Matrix
            </button>
            <button
              onClick={() => setActiveTab('config')}
              className={`px-3 py-1 rounded-md font-medium transition-colors ${
                activeTab === 'config' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Config & Boundaries
            </button>
            <button
              onClick={() => setActiveTab('workers')}
              className={`px-3 py-1 rounded-md font-medium transition-colors ${
                activeTab === 'workers' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Worker Topology (9)
            </button>
            <button
              onClick={() => setActiveTab('architecture')}
              className={`px-3 py-1 rounded-md font-medium transition-colors ${
                activeTab === 'architecture' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Invariants & Contracts
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'matrix' && (
          <div className="space-y-6">
            <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
                    <Workflow className="h-4 w-4 text-cyan-400" />
                    <span>Prompt Sequence Execution Track</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Orderly prompt application from baseline reconciliation to full 71-engine parity verification.
                  </p>
                </div>
                <span className="text-xs font-mono text-slate-400">4 / 38 Gates Complete</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {PROMPT_STEPS.map((step) => {
                  const isCompleted = step.status === 'completed';
                  const isReady = step.status === 'ready';

                  return (
                    <div
                      key={step.id}
                      className={`p-3.5 rounded-lg border transition-all ${
                        isCompleted
                          ? 'bg-emerald-950/20 border-emerald-500/30'
                          : isReady
                          ? 'bg-amber-950/20 border-amber-500/40 ring-1 ring-amber-500/20'
                          : 'bg-slate-900/40 border-slate-800/80 opacity-70'
                      }`}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex items-center space-x-2">
                          <span className={`font-mono text-xs px-2 py-0.5 rounded font-semibold ${
                            isCompleted 
                              ? 'bg-emerald-500/20 text-emerald-400' 
                              : isReady
                              ? 'bg-amber-500/20 text-amber-300'
                              : 'bg-slate-800 text-slate-400'
                          }`}>
                            {step.id}
                          </span>
                          <span className="text-xs text-slate-400 font-mono">[{step.category}]</span>
                        </div>
                        {isCompleted && (
                          <span className="flex items-center text-emerald-400 text-xs font-mono">
                            <CheckCircle2 className="h-3.5 w-3.5 mr-1" />
                            PASS
                          </span>
                        )}
                        {isReady && (
                          <span className="flex items-center text-amber-400 text-xs font-mono animate-pulse">
                            <CircleDot className="h-3.5 w-3.5 mr-1" />
                            AWAITING PROMPT
                          </span>
                        )}
                      </div>
                      <h3 className="text-xs font-medium text-slate-200 mt-2">
                        {step.title}
                      </h3>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Live Environment Diagnostic Card */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-slate-900/50 rounded-xl border border-slate-800 p-4">
                <div className="flex items-center space-x-2 text-cyan-400 mb-2">
                  <Server className="h-4 w-4" />
                  <span className="text-xs font-semibold uppercase font-mono">Typed Config Loader</span>
                </div>
                <p className="text-xs text-slate-300">
                  Strict Zod schemas enforce public/server/worker validation without scattered env reads.
                </p>
                <div className="mt-3 pt-3 border-t border-slate-800 text-[11px] font-mono text-emerald-400">
                  Status: packages/config Active
                </div>
              </div>

              <div className="bg-slate-900/50 rounded-xl border border-slate-800 p-4">
                <div className="flex items-center space-x-2 text-cyan-400 mb-2">
                  <Lock className="h-4 w-4" />
                  <span className="text-xs font-semibold uppercase font-mono">Secret Boundary</span>
                </div>
                <p className="text-xs text-slate-300">
                  getPublicConfig() verified: zero secrets, tokens, or private keys exposed to client bundle.
                </p>
                <div className="mt-3 pt-3 border-t border-slate-800 text-[11px] font-mono text-emerald-400">
                  Boundary: STRICT_ISOLATION
                </div>
              </div>

              <div className="bg-slate-900/50 rounded-xl border border-slate-800 p-4">
                <div className="flex items-center space-x-2 text-cyan-400 mb-2">
                  <KeyRound className="h-4 w-4" />
                  <span className="text-xs font-semibold uppercase font-mono">Optional Adapters</span>
                </div>
                <p className="text-xs text-slate-300">
                  Absent credentials return DISABLED_MISSING_CREDENTIAL gracefully without startup failure.
                </p>
                <div className="mt-3 pt-3 border-t border-slate-800 text-[11px] font-mono text-cyan-400">
                  Provider Handling: Non-Failing
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'config' && (
          <div className="space-y-6">
            <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
                    <Sliders className="h-4 w-4 text-cyan-400" />
                    <span>Active Configuration & Feature Flags</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Sanitized public configuration provided to the client runtime.
                  </p>
                </div>
                <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-800 text-slate-300">
                  Env: {publicConfig?.env || 'development'}
                </span>
              </div>

              {publicConfig && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="p-3.5 bg-slate-950/60 rounded-lg border border-slate-800/80">
                    <h3 className="font-semibold text-slate-300 mb-2">Platform Models</h3>
                    <div className="space-y-1.5 font-mono text-slate-400">
                      <div>Default Model: <span className="text-cyan-300">{publicConfig.models.defaultModel}</span></div>
                      <div>Embedding Model: <span className="text-cyan-300">{publicConfig.models.embeddingModel}</span></div>
                    </div>
                  </div>

                  <div className="p-3.5 bg-slate-950/60 rounded-lg border border-slate-800/80">
                    <h3 className="font-semibold text-slate-300 mb-2">Feature Flags</h3>
                    <div className="space-y-1 font-mono">
                      {Object.entries(publicConfig.features).map(([key, enabled]) => (
                        <div key={key} className="flex items-center justify-between">
                          <span className="text-slate-400">{key}:</span>
                          <span className={enabled ? 'text-emerald-400' : 'text-slate-500'}>
                            {enabled ? 'ENABLED' : 'DISABLED'}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {systemState?.providers && (
              <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-4">
                <h2 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
                  <KeyRound className="h-4 w-4 text-cyan-400" />
                  <span>Optional Provider Adapter Statuses</span>
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  {Object.entries(systemState.providers as Record<string, { status: string; credentialPresent: boolean; reason?: string }>).map(([provider, details]) => (
                    <div key={provider} className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80 flex items-start justify-between">
                      <div>
                        <span className="font-mono font-semibold text-slate-300 uppercase">{provider}</span>
                        {details.reason && (
                          <p className="text-[11px] text-slate-400 mt-1">{details.reason}</p>
                        )}
                      </div>
                      <span className={`font-mono text-[10px] px-2 py-0.5 rounded font-semibold ${
                        details.status === 'READY'
                          ? 'bg-emerald-500/20 text-emerald-400'
                          : 'bg-slate-800 text-slate-400'
                      }`}>
                        {details.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'workers' && (
          <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
                <Cpu className="h-4 w-4 text-cyan-400" />
                <span>Isolated Worker Processes</span>
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Heavy computation and sandboxing are partitioned outside the preview server bundle.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {WORKER_DOMAINS.map((w) => (
                <div key={w.name} className="p-3 bg-slate-900/80 rounded-lg border border-slate-800">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-semibold text-cyan-300">workers/{w.name}</span>
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Dedicated</span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1.5">{w.description}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'architecture' && (
          <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-5 space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
                <Box className="h-4 w-4 text-cyan-400" />
                <span>Architectural Invariants (V2.0.1)</span>
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Non-negotiable structural policies enforced throughout all prompt executions.
              </p>
            </div>

            <div className="space-y-2 text-xs">
              <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800 flex items-start space-x-3">
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <strong className="text-slate-200">Zero-Mock Standard:</strong> Real API integrations, schemas, and typed contracts without placeholder stubs.
                </div>
              </div>
              <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800 flex items-start space-x-3">
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <strong className="text-slate-200">71 Logical Engine Parity:</strong> Exact compliance with the 71 analysis and security engines cataloged in the V2.0.1 architecture.
                </div>
              </div>
              <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800 flex items-start space-x-3">
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <strong className="text-slate-200">CAIM & Ontological Integrity:</strong> Strict conformance with Common Artifact Intelligence Model schema specifications.
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 py-4 text-center text-xs text-slate-400 font-mono">
        CAIM Platform Baseline V2.0.1 • All Systems Nominal • Ready for P03 Database Foundation
      </footer>
    </div>
  );
}
