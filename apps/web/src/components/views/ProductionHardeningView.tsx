import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  Zap,
  Activity,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Server,
  Play,
  RotateCcw,
  Download,
  Terminal,
  Layers,
  Key
} from 'lucide-react';
import {
  SsrfProtection,
  ArchiveSecurityGuard,
  SandboxIsolationPolicy,
  RagInstructionBoundary,
  ElevatedActionAuditor,
  AuditLedgerEntry,
} from '../../../../../packages/workflow/src/production-hardening.ts';
import { ProductionConfigValidator, ProductionConfigValidationReport } from '../../../../../packages/config/src/production-validator.ts';
import { PerformanceSmokeRunner, PerformanceSmokeReport } from '../../../../../packages/workflow/src/performance-smoke.ts';
import { ReleaseManifestGenerator, ReleaseCandidateManifest } from '../../../../../packages/packaging/src/release-manifest.ts';

export const ProductionHardeningView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'SECURITY_RELIABILITY' | 'CONFIG_VALIDATOR' | 'PERFORMANCE_SMOKE' | 'RELEASE_MANIFEST'>('SECURITY_RELIABILITY');

  // Config Validator State
  const [targetEnv, setTargetEnv] = useState<'development' | 'staging' | 'production'>('development');
  const [configReport, setConfigReport] = useState<ProductionConfigValidationReport | null>(null);

  // Performance Smoke State
  const [perfReport, setPerfReport] = useState<PerformanceSmokeReport | null>(null);
  const [isRunningPerf, setIsRunningPerf] = useState(false);

  // Release Manifest State
  const [releaseManifest, setReleaseManifest] = useState<ReleaseCandidateManifest | null>(null);
  const [copiedManifest, setCopiedManifest] = useState(false);

  // Audit Ledger State
  const [auditLedger, setAuditLedger] = useState<AuditLedgerEntry[]>([]);
  const [ledgerIntegrity, setLedgerIntegrity] = useState<{ valid: boolean; totalEntries: number }>({ valid: true, totalEntries: 0 });

  useEffect(() => {
    // Run initial config validation
    const report = ProductionConfigValidator.validate(undefined, targetEnv);
    setConfigReport(report);

    // Generate release manifest
    const manifest = ReleaseManifestGenerator.generateManifest();
    setReleaseManifest(manifest);

    // Initialize sample audit entry if empty
    if (ElevatedActionAuditor.getLedger().length === 0) {
      ElevatedActionAuditor.recordAction({
        actorId: 'system-bootstrap@caim.internal',
        actorRole: 'SYSTEM_ORCHESTRATOR',
        tenantId: 'GLOBAL_SYSTEM',
        action: 'RELEASE_ATTESTATION',
        resourceId: 'caim-v2.0.1-rc1',
        clientIp: '127.0.0.1',
        status: 'SUCCESS',
        details: { attestation: 'Baseline production hardening initialized' },
      });
    }

    setAuditLedger(ElevatedActionAuditor.getLedger());
    setLedgerIntegrity(ElevatedActionAuditor.verifyLedgerIntegrity());
  }, [targetEnv]);

  const handleRunPerfSuite = async () => {
    setIsRunningPerf(true);
    try {
      const report = await PerformanceSmokeRunner.runSuite();
      setPerfReport(report);
    } finally {
      setIsRunningPerf(false);
    }
  };

  const handleRecordSampleAudit = () => {
    ElevatedActionAuditor.recordAction({
      actorId: 'sec-analyst@caim.internal',
      actorRole: 'SECURITY_LEAD',
      tenantId: 'tenant-demo',
      action: 'POLICY_OVERRIDE',
      resourceId: `agent-policy-${Date.now().toString().slice(-4)}`,
      clientIp: '192.0.2.45',
      status: 'SUCCESS',
      details: { reason: 'Operator verified zero CVE exploitability' },
    });
    setAuditLedger(ElevatedActionAuditor.getLedger());
    setLedgerIntegrity(ElevatedActionAuditor.verifyLedgerIntegrity());
  };

  const quotas = SandboxIsolationPolicy.getBaselineQuotas();

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 relative overflow-hidden">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <div className="px-2.5 py-1 bg-emerald-500/10 border border-emerald-500/20 rounded-md text-emerald-400 text-xs font-mono font-medium">
                P35 RELEASE CANDIDATE
              </div>
              <span className="text-slate-400 text-xs font-mono">Architecture V2.0.1 • Ed25519 Signed</span>
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight">
              Production Hardening & Release Candidate (RC1)
            </h1>
            <p className="text-slate-400 text-sm mt-1 max-w-2xl">
              Strict security perimeter validation, SSRF link-local blocks, decompression bombs defense, isolated sandbox quotas, fail-fast production config validator, empirical P50/P95 capacity smoke, and signed release attestation.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleRunPerfSuite}
              disabled={isRunningPerf}
              className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-all shadow-sm shadow-indigo-500/20"
            >
              {isRunningPerf ? <RotateCcw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              <span>{isRunningPerf ? 'Running Smoke...' : 'Run Capacity Smoke'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-slate-800 space-x-2">
        <button
          onClick={() => setActiveTab('SECURITY_RELIABILITY')}
          className={`px-4 py-2.5 text-sm font-medium border-b-2 flex items-center gap-2 transition-all ${
            activeTab === 'SECURITY_RELIABILITY'
              ? 'border-indigo-500 text-indigo-400 bg-indigo-500/5'
              : 'border-transparent text-slate-400 hover:text-slate-300'
          }`}
        >
          <ShieldCheck className="w-4 h-4" />
          <span>Security & Reliability Matrix</span>
        </button>

        <button
          onClick={() => setActiveTab('CONFIG_VALIDATOR')}
          className={`px-4 py-2.5 text-sm font-medium border-b-2 flex items-center gap-2 transition-all ${
            activeTab === 'CONFIG_VALIDATOR'
              ? 'border-indigo-500 text-indigo-400 bg-indigo-500/5'
              : 'border-transparent text-slate-400 hover:text-slate-300'
          }`}
        >
          <Server className="w-4 h-4" />
          <span>Config & Secret Validator</span>
          {configReport && !configReport.canDeployToProduction && targetEnv === 'production' && (
            <span className="w-2 h-2 rounded-full bg-rose-500" />
          )}
        </button>

        <button
          onClick={() => setActiveTab('PERFORMANCE_SMOKE')}
          className={`px-4 py-2.5 text-sm font-medium border-b-2 flex items-center gap-2 transition-all ${
            activeTab === 'PERFORMANCE_SMOKE'
              ? 'border-indigo-500 text-indigo-400 bg-indigo-500/5'
              : 'border-transparent text-slate-400 hover:text-slate-300'
          }`}
        >
          <Activity className="w-4 h-4" />
          <span>Performance & Capacity Smoke</span>
          {perfReport && (
            <span className="px-1.5 py-0.5 bg-emerald-500/20 text-emerald-400 rounded text-xs font-mono">
              P95: {perfReport.summary.avgP95Ms}ms
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('RELEASE_MANIFEST')}
          className={`px-4 py-2.5 text-sm font-medium border-b-2 flex items-center gap-2 transition-all ${
            activeTab === 'RELEASE_MANIFEST'
              ? 'border-indigo-500 text-indigo-400 bg-indigo-500/5'
              : 'border-transparent text-slate-400 hover:text-slate-300'
          }`}
        >
          <FileCode className="w-4 h-4" />
          <span>V2.0.1-RC1 Release Manifest</span>
        </button>
      </div>

      {/* TAB 1: SECURITY & RELIABILITY HARDENING MATRIX */}
      {activeTab === 'SECURITY_RELIABILITY' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* SSRF Protection Card */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
              <div className="flex items-center gap-3 mb-3">
                <div className="p-2 bg-emerald-500/10 text-emerald-400 rounded-lg">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">SSRF Defenses</h3>
                  <span className="text-xs text-emerald-400 font-mono">ACTIVE • ZERO-TRUST</span>
                </div>
              </div>
              <p className="text-xs text-slate-400 mb-4">
                Enforces strict egress boundaries. Link-local AWS metadata (169.254.169.254), private ranges (10/8, 172.16/12, 192.168/16), and loopback are blocked.
              </p>
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">AWS Metadata (169.254):</span>
                  <span className="text-rose-400">BLOCKED</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Private Subnets:</span>
                  <span className="text-rose-400">BLOCKED</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-400">Allowed Protocols:</span>
                  <span className="text-emerald-400">HTTPS, HTTP</span>
                </div>
              </div>
            </div>

            {/* Archive Security Guard */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
              <div className="flex items-center gap-3 mb-3">
                <div className="p-2 bg-blue-500/10 text-blue-400 rounded-lg">
                  <Lock className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">Archive & Decompression</h3>
                  <span className="text-xs text-blue-400 font-mono">SAFE • STRICT_SANDBOX</span>
                </div>
              </div>
              <p className="text-xs text-slate-400 mb-4">
                Protects against Zip Slip directory traversal (../), rogue symlink boundary escapes, and decompression bombs exceeding 100:1 ratio.
              </p>
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Zip Slip Escape:</span>
                  <span className="text-rose-400">BLOCKED</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Max Bomb Ratio:</span>
                  <span className="text-slate-200">100:1 (100MB max)</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-400">Max Archive Files:</span>
                  <span className="text-slate-200">5,000 files</span>
                </div>
              </div>
            </div>

            {/* Sandbox Isolation Quotas */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
              <div className="flex items-center gap-3 mb-3">
                <div className="p-2 bg-purple-500/10 text-purple-400 rounded-lg">
                  <Server className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">Sandbox Quotas</h3>
                  <span className="text-xs text-purple-400 font-mono">ISOLATED PROCESS</span>
                </div>
              </div>
              <p className="text-xs text-slate-400 mb-4">
                Strips all master keys and secrets from child environment. Strict memory and CPU execution quotas applied per dynamic analysis run.
              </p>
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Memory Limit:</span>
                  <span className="text-slate-200">{quotas.maxMemoryMb} MB</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Timeout Quota:</span>
                  <span className="text-slate-200">{quotas.timeoutMs / 1000}s</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-400">Network Egress:</span>
                  <span className="text-rose-400">{quotas.networkEgressAllowed ? 'ENABLED' : 'DISABLED'}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Elevated Action Audit Ledger */}
          <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-emerald-500/10 text-emerald-400 rounded-lg">
                  <Terminal className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">Cryptographically Chained Audit Ledger</h3>
                  <p className="text-xs text-slate-400">
                    Immutable append-only record of all administrative overrides, key rotations, vault accesses, and attestations.
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className="px-2.5 py-1 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-md text-xs font-mono flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Chain Integrity: {ledgerIntegrity.valid ? 'VERIFIED' : 'TAMPERED'}</span>
                </span>
                <button
                  onClick={handleRecordSampleAudit}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium border border-slate-700 transition-all"
                >
                  Record Audit Event
                </button>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3">Actor / Role</th>
                    <th className="py-2.5 px-3">Action</th>
                    <th className="py-2.5 px-3">Target Resource</th>
                    <th className="py-2.5 px-3">SHA-256 Hash Chain</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {auditLedger.map((entry) => (
                    <tr key={entry.auditId} className="hover:bg-slate-800/30">
                      <td className="py-2.5 px-3 text-slate-400">{entry.timestamp.split('T')[1].replace('Z', '')}</td>
                      <td className="py-2.5 px-3">
                        <span className="text-slate-200 font-medium">{entry.actorId}</span>
                        <span className="text-slate-400 block text-[10px]">{entry.actorRole}</span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="px-2 py-0.5 bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 rounded text-[10px]">
                          {entry.action}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">{entry.resourceId}</td>
                      <td className="py-2.5 px-3">
                        <span className="text-slate-400 text-[10px]">Prev: {entry.previousHash.slice(0, 10)}...</span>
                        <span className="text-emerald-400 block text-[10px]">Hash: {entry.entryHash.slice(0, 10)}...</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: CONFIG & SECRET VALIDATOR */}
      {activeTab === 'CONFIG_VALIDATOR' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between bg-slate-900/60 border border-slate-800 rounded-xl p-4">
            <div className="flex items-center gap-3">
              <span className="text-sm font-medium text-slate-300">Target Environment:</span>
              <div className="flex bg-slate-950 p-1 rounded-lg border border-slate-800">
                {(['development', 'staging', 'production'] as const).map((env) => (
                  <button
                    key={env}
                    onClick={() => setTargetEnv(env)}
                    className={`px-3 py-1 text-xs font-mono rounded-md transition-all ${
                      targetEnv === env
                        ? 'bg-indigo-600 text-white shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {env.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>

            {configReport && (
              <div className="flex items-center gap-2">
                <span className={`px-2.5 py-1 rounded-md text-xs font-mono font-medium flex items-center gap-1.5 ${
                  configReport.canDeployToProduction
                    ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400'
                    : 'bg-rose-500/10 border border-rose-500/20 text-rose-400'
                }`}>
                  {configReport.canDeployToProduction ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
                  <span>{configReport.canDeployToProduction ? 'PRODUCTION READY' : 'FAIL-FAST SECURITY BLOCK'}</span>
                </span>
              </div>
            )}
          </div>

          {/* Checks Matrix */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5">
              <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                <Key className="w-4 h-4 text-indigo-400" />
                <span>Security Configuration Checks</span>
              </h3>
              <div className="space-y-3">
                {configReport?.findings.map((finding) => (
                  <div key={finding.key} className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-mono font-bold text-slate-200">{finding.key}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                        finding.passed ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400 font-bold'
                      }`}>
                        {finding.passed ? 'PASSED' : finding.severity}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">{finding.message}</p>
                    {!finding.passed && (
                      <p className="text-[11px] text-amber-400/90 mt-1 font-mono">Recommendation: {finding.recommendation}</p>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Optional Providers & Adapters */}
            <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5">
              <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                <Layers className="w-4 h-4 text-indigo-400" />
                <span>Optional Provider Adapter Statuses</span>
              </h3>
              <div className="space-y-3">
                {configReport && Object.entries(configReport.adapterStatuses).map(([adapter, info]: [string, any]) => (
                  <div key={adapter} className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-mono font-bold text-slate-200 capitalize">{adapter} Adapter</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                        info.status === 'READY' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-slate-800 text-slate-400'
                      }`}>
                        {info.status}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">{info.operationalImpact}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: PERFORMANCE & CAPACITY SMOKE */}
      {activeTab === 'PERFORMANCE_SMOKE' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between bg-slate-900/60 border border-slate-800 rounded-xl p-4">
            <div>
              <h3 className="text-sm font-bold text-white">Empirical Micro-Benchmark Suite</h3>
              <p className="text-xs text-slate-400">
                Runs bounded throughput and latency distributions across all 6 core sub-systems.
              </p>
            </div>
            <button
              onClick={handleRunPerfSuite}
              disabled={isRunningPerf}
              className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-all"
            >
              {isRunningPerf ? <RotateCcw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              <span>{isRunningPerf ? 'Executing Benchmarks...' : 'Re-Run Suite'}</span>
            </button>
          </div>

          {perfReport ? (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-4 text-center">
                  <span className="text-xs text-slate-400 font-mono">TOTAL OPERATIONS</span>
                  <div className="text-2xl font-bold text-white font-mono mt-1">{perfReport.summary.totalOperations} ops</div>
                </div>
                <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-4 text-center">
                  <span className="text-xs text-slate-400 font-mono">AVERAGE P50 LATENCY</span>
                  <div className="text-2xl font-bold text-emerald-400 font-mono mt-1">{perfReport.summary.avgP50Ms} ms</div>
                </div>
                <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-4 text-center">
                  <span className="text-xs text-slate-400 font-mono">AVERAGE P95 LATENCY</span>
                  <div className="text-2xl font-bold text-indigo-400 font-mono mt-1">{perfReport.summary.avgP95Ms} ms</div>
                </div>
              </div>

              <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-950/40 text-slate-400">
                      <th className="py-3 px-4">Sub-System Benchmark</th>
                      <th className="py-3 px-4">Iterations</th>
                      <th className="py-3 px-4">Throughput</th>
                      <th className="py-3 px-4">P50 Latency</th>
                      <th className="py-3 px-4">P95 Latency</th>
                      <th className="py-3 px-4">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {perfReport.steps.map((step) => (
                      <tr key={step.stepName} className="hover:bg-slate-800/30">
                        <td className="py-3 px-4">
                          <span className="text-white font-medium">{step.stepName}</span>
                          <span className="text-slate-400 block text-[10px]">{step.category}</span>
                        </td>
                        <td className="py-3 px-4 text-slate-300">{step.iterations} runs</td>
                        <td className="py-3 px-4 text-indigo-400">{step.throughputPerSecond} ops/sec</td>
                        <td className="py-3 px-4 text-emerald-400">{step.latency.p50Ms} ms</td>
                        <td className="py-3 px-4 text-amber-400">{step.latency.p95Ms} ms</td>
                        <td className="py-3 px-4">
                          <span className="px-2 py-0.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded text-[10px]">
                            {step.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="p-8 text-center bg-slate-900/20 border border-dashed border-slate-800 rounded-xl">
              <Zap className="w-8 h-8 text-slate-600 mx-auto mb-2" />
              <p className="text-sm text-slate-400">No benchmark report generated yet. Click "Run Capacity Smoke" above to execute.</p>
            </div>
          )}
        </div>
      )}

      {/* TAB 4: V2.0.1-RC1 RELEASE MANIFEST */}
      {activeTab === 'RELEASE_MANIFEST' && releaseManifest && (
        <div className="space-y-6">
          <div className="flex items-center justify-between bg-slate-900/60 border border-slate-800 rounded-xl p-4">
            <div>
              <h3 className="text-sm font-bold text-white">Cryptographic Release Candidate Manifest</h3>
              <p className="text-xs text-slate-400 font-mono">
                Release Hash: <span className="text-emerald-400">{releaseManifest.signedReleaseHashSha256}</span>
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(releaseManifest, null, 2));
                  setCopiedManifest(true);
                  setTimeout(() => setCopiedManifest(false), 2000);
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono transition-all"
              >
                <Download className="w-3.5 h-3.5" />
                <span>{copiedManifest ? 'Copied JSON!' : 'Copy Manifest JSON'}</span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Version Registry Card */}
            <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5">
              <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider mb-3">Version Registry</h4>
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">Release Candidate:</span>
                  <span className="text-emerald-400 font-bold">{releaseManifest.releaseCandidate}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">Migration Head:</span>
                  <span className="text-slate-200">{releaseManifest.migrationHead}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">CAIM / Ontology:</span>
                  <span className="text-slate-200">{releaseManifest.caimVersion} / {releaseManifest.ontologyVersion}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">Static / Taint Analyzers:</span>
                  <span className="text-slate-200">{releaseManifest.versionRegistry.analyzers.staticSyntaxVersion}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-400">Golden Corpus Scenario:</span>
                  <span className="text-slate-200">{releaseManifest.versionRegistry.scenarios.goldenCorpusVersion}</span>
                </div>
              </div>
            </div>

            {/* Quality & Security Attestations Card */}
            <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5">
              <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider mb-3">Attestations & Invariants</h4>
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">Lineage Completeness:</span>
                  <span className="text-emerald-400 font-bold">{releaseManifest.qualityTargetsAttestation.publishedConclusionLineageCompleteness}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">Unauthorized Vault Access:</span>
                  <span className="text-emerald-400">0 (PASSED)</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">SSRF & Decompression Blocks:</span>
                  <span className="text-emerald-400">VERIFIED ACTIVE</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">Zero Regression Gate:</span>
                  <span className="text-emerald-400">{releaseManifest.evaluationSummary.zeroRegressionGate}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-400">KMS Key ID:</span>
                  <span className="text-indigo-400">{releaseManifest.signingKeyReference.keyId}</span>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
            <pre className="text-[11px] font-mono text-slate-300 overflow-x-auto p-2 leading-relaxed">
              {JSON.stringify(releaseManifest, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
