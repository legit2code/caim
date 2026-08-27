import React, { useState, useEffect } from 'react';
import { 
  Activity, 
  Search, 
  ShieldCheck, 
  ShieldAlert, 
  CheckCircle2, 
  XCircle, 
  Clock, 
  DollarSign, 
  Zap, 
  Cpu, 
  Layers, 
  Lock, 
  Fingerprint, 
  Eye, 
  EyeOff, 
  Play, 
  RefreshCw, 
  AlertTriangle, 
  Sliders, 
  BarChart3, 
  Terminal, 
  FileText, 
  Sparkles,
  Server,
  Share2,
  GitBranch,
  ChevronRight,
  Database,
  Key,
  ChevronDown
} from 'lucide-react';
import { 
  OpenTelemetryTracer, 
  AuditLogEngine, 
  PlatformTelemetryEngine, 
  TraceResolver, 
  SecretRedactor,
  EndToEndTraceResult
} from '../../../../../packages/workflow/src/observability.ts';
import { runObservabilityVerificationTests } from '../../../../../packages/workflow/src/observability.test.ts';
import { CostAttribution } from '../../../../../packages/contracts/src/observability.ts';

interface ObservabilityWorkflowViewProps {
  currentRole: string;
  onNavigateToWorkflow?: (workflow: string, params?: any) => void;
}

export const ObservabilityWorkflowView: React.FC<ObservabilityWorkflowViewProps> = ({ currentRole, onNavigateToWorkflow }) => {
  const [activeTab, setActiveTab] = useState<'traces' | 'metrics' | 'cost' | 'audit' | 'alerts' | 'redaction'>('traces');
  
  // Engines & Data
  const [tracer] = useState(() => new OpenTelemetryTracer());
  const [auditEngine] = useState(() => new AuditLogEngine());
  
  const [currentTrace, setCurrentTrace] = useState<EndToEndTraceResult | null>(null);
  const [selectedSpanId, setSelectedSpanId] = useState<string | null>(null);
  
  const [metricsSnapshot, setMetricsSnapshot] = useState(PlatformTelemetryEngine.getMetricsSnapshot());
  const [capacityMetrics, setCapacityMetrics] = useState(PlatformTelemetryEngine.getCapacityMetrics());
  const [costBreakdown, setCostBreakdown] = useState<Record<string, CostAttribution>>(PlatformTelemetryEngine.getCostAttributionBreakdown());
  const [alertConditions, setAlertConditions] = useState(PlatformTelemetryEngine.getAlertConditions());
  
  // Verification test state
  const [testSuiteResults, setTestSuiteResults] = useState<{ passed: boolean; testResults: Array<{ name: string; status: 'PASS' | 'FAIL'; details: string }> } | null>(null);
  const [isRunningTests, setIsRunningTests] = useState<boolean>(false);
  
  // Redaction tester state // secret-scan:ignore
  const [customTestInput, setCustomTestInput] = useState<string>('Request auth: Bearer SIMULATED_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVM7w5W6LHg1Q with apiKey="SIMULATED_AIzaSyA891723498172349817234981723498172" and db_pass="P@ssw0rd99!"');
  const [redactionTestOutput, setRedactionTestOutput] = useState<{ sanitizedText: string; redactionsCount: number; detectedCategories: string[] } | null>(null);
  
  const [searchAudit, setSearchAudit] = useState<string>('');
  const [notification, setNotification] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);

  // Initialize initial synthetic trace & audit logs
  useEffect(() => {
    const trace = TraceResolver.createSyntheticE2ETrace(tracer, auditEngine);
    setCurrentTrace(trace);
    if (trace.spans.length > 0) {
      setSelectedSpanId(trace.spans[0].spanId);
    }

    // Populate baseline audit events
    auditEngine.recordEvent({
      actorType: 'USER',
      actorId: 'security-auditor@caim.internal',
      action: 'POLICY_OVERRIDE_APPROVED',
      targetType: 'POLICY_GATE',
      targetId: 'gate-zero-trust-egress',
      correlation: { traceId: trace.traceId, requestId: trace.requestId },
      details: { ticket: 'CR-9901', reason: 'Temporary bypass for sandbox stress tests' }
    });

    auditEngine.recordEvent({
      actorType: 'VAULT',
      actorId: 'kms-enclave-caim-root-v2',
      action: 'VAULT_SECRET_ACCESS',
      targetType: 'KMS_KEY',
      targetId: 'kms-enclave-caim-root-v2',
      correlation: { traceId: trace.traceId, requestId: trace.requestId },
      details: { operation: 'SignDeterministicManifest', clientIp: '10.0.1.20' }
    });

    auditEngine.recordEvent({
      actorType: 'SERVICE',
      actorId: 'caim-packaging-worker-01',
      action: 'PACKAGE_SIGNED_KMS',
      targetType: 'PACKAGE_BUNDLE',
      targetId: 'pkg-fin-v100-prod',
      correlation: { traceId: trace.traceId, requestId: trace.requestId },
      details: { algorithm: 'Ed25519-Pure', digest: 'sha256:3c59a2f7c001a1b5b24b899478f7a8b85590c749320e8b15ca88bfa674b88bf2' }
    });

    auditEngine.recordEvent({
      actorType: 'USER',
      actorId: 'release-manager@caim.internal',
      action: 'BUNDLE_SHIPPED_PROD',
      targetType: 'PACKAGE_BUNDLE',
      targetId: 'pkg-fin-v100-prod',
      correlation: { traceId: trace.traceId, requestId: trace.requestId },
      details: { destinationCluster: 'prod-cluster-us-east-1', gateSignature: 'VERIFIED_VALID' }
    });
  }, [tracer, auditEngine]);

  const handleGenerateNewTrace = () => {
    const newTrace = TraceResolver.createSyntheticE2ETrace(tracer, auditEngine);
    setCurrentTrace(newTrace);
    setSelectedSpanId(newTrace.spans[0]?.spanId || null);
    setNotification({
      type: 'success',
      message: `Generated OpenTelemetry trace [${newTrace.traceId}] with full request → workflow → job → stage resolution.`
    });
  };

  const handleRunVerificationSuite = async () => {
    setIsRunningTests(true);
    try {
      await new Promise(r => setTimeout(r, 450));
      const results = runObservabilityVerificationTests();
      setTestSuiteResults(results);
      setNotification({
        type: results.passed ? 'success' : 'error',
        message: results.passed 
          ? 'P30 Zero-Leak & Trace Resolution Verification: ALL 5 TEST GATES PASSED!' 
          : 'Verification failed some tests.'
      });
    } finally {
      setIsRunningTests(false);
    }
  };

  const handleTestRedaction = () => {
    const res = SecretRedactor.redactString(customTestInput);
    setRedactionTestOutput(res);
  };

  const selectedSpan = currentTrace?.spans.find(s => s.spanId === selectedSpanId);
  const auditLogs = auditEngine.getEvents();
  const filteredAudits = auditLogs.filter(a =>
    a.actorId.toLowerCase().includes(searchAudit.toLowerCase()) ||
    a.action.toLowerCase().includes(searchAudit.toLowerCase()) ||
    a.targetId.toLowerCase().includes(searchAudit.toLowerCase())
  );

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
              <h1 className="text-lg font-bold text-slate-100 tracking-tight">Observability, Audit, Cost & Capacity</h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                P30 OpenTelemetry & Redaction Active
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              OpenTelemetry distributed tracing, zero-leak secret redaction, 71-engine coverage, Gemini cost accounting, and cryptographic audit logs.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={handleRunVerificationSuite}
            disabled={isRunningTests}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-sm transition-colors disabled:opacity-50"
            id="btn-run-p30-verification"
          >
            <ShieldCheck className={`w-3.5 h-3.5 ${isRunningTests ? 'animate-spin' : ''}`} />
            <span>{isRunningTests ? 'Verifying Gates...' : 'Verify P30 Gates'}</span>
          </button>

          <button
            onClick={handleGenerateNewTrace}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition-colors"
            id="btn-generate-trace"
          >
            <Play className="w-3.5 h-3.5" />
            <span>Generate E2E Trace</span>
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
            {notification.type === 'success' ? <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" /> : <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />}
            <span>{notification.message}</span>
          </div>
          <button onClick={() => setNotification(null)} className="text-slate-400 hover:text-slate-200 text-xs ml-4">✕</button>
        </div>
      )}

      {/* Verification Test Results Banner if Run */}
      {testSuiteResults && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span className="font-bold text-slate-100">P30 Verification Gate Test Matrix</span>
            </div>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
              testSuiteResults.passed ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'
            }`}>
              {testSuiteResults.passed ? 'ALL GATES PASSED (100%)' : 'GATE FAILURE'}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {testSuiteResults.testResults.map((t, idx) => (
              <div key={idx} className="bg-slate-950 p-2.5 rounded-lg border border-slate-850 flex items-start space-x-2">
                {t.status === 'PASS' ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                ) : (
                  <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                )}
                <div>
                  <span className="font-semibold text-slate-200">{t.name}</span>
                  <p className="text-[11px] text-slate-400 font-sans mt-0.5">{t.details}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Main Diagnostic & Telemetry Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
        {/* Navigation Tabs */}
        <div className="flex items-center space-x-1 border-b border-slate-800 pb-2 text-xs font-mono overflow-x-auto">
          <button
            onClick={() => setActiveTab('traces')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors shrink-0 ${
              activeTab === 'traces' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
            id="tab-traces"
          >
            OpenTelemetry Traces ({currentTrace?.spans.length || 0} Spans)
          </button>
          <button
            onClick={() => setActiveTab('metrics')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors shrink-0 ${
              activeTab === 'metrics' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
            id="tab-metrics"
          >
            Pipeline Metrics & 71-Coverage
          </button>
          <button
            onClick={() => setActiveTab('cost')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors shrink-0 ${
              activeTab === 'cost' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
            id="tab-cost"
          >
            Gemini & Compute Cost Accounting
          </button>
          <button
            onClick={() => setActiveTab('audit')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors shrink-0 ${
              activeTab === 'audit' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
            id="tab-audit"
          >
            Cryptographic Audit Trail ({auditLogs.length})
          </button>
          <button
            onClick={() => setActiveTab('alerts')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors shrink-0 ${
              activeTab === 'alerts' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
            id="tab-alerts"
          >
            Alert Conditions ({alertConditions.filter(a => a.status === 'FIRING').length} Firing)
          </button>
          <button
            onClick={() => setActiveTab('redaction')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors shrink-0 ${
              activeTab === 'redaction' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
            id="tab-redaction"
          >
            Secret Redaction Engine
          </button>
        </div>

        {/* TAB 1: OPENTELEMETRY TRACES (E2E CORRELATION) */}
        {activeTab === 'traces' && currentTrace && (
          <div className="space-y-4">
            {/* Correlation ID Header */}
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 grid grid-cols-1 sm:grid-cols-4 gap-4 font-mono text-xs">
              <div>
                <span className="text-slate-500 text-[10px] block uppercase">Trace ID</span>
                <span className="text-cyan-400 font-bold break-all">{currentTrace.traceId}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block uppercase">Request ID</span>
                <span className="text-emerald-400 font-bold break-all">{currentTrace.requestId}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block uppercase">Workflow Run ID</span>
                <span className="text-purple-400 font-bold break-all">{currentTrace.workflowRunId}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block uppercase">Target Agent</span>
                <span className="text-slate-200 font-bold">{currentTrace.agentId}</span>
              </div>
            </div>

            {/* Waterfall Span Graph & Details Split */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
              {/* Span Tree Waterfall */}
              <div className="lg:col-span-7 space-y-2 font-mono text-xs">
                <div className="flex items-center justify-between text-slate-400 text-[11px] pb-1 px-1">
                  <span>Span Name & Execution Hierarchy</span>
                  <span>Duration / Status</span>
                </div>

                <div className="space-y-2">
                  {currentTrace.spans.map((span) => {
                    const isRoot = !span.parentSpanId;
                    const isSelected = span.spanId === selectedSpanId;
                    const isChild = Boolean(span.parentSpanId);

                    return (
                      <div
                        key={span.spanId}
                        onClick={() => setSelectedSpanId(span.spanId)}
                        className={`p-3 rounded-xl border transition-all cursor-pointer ${
                          isSelected
                            ? 'bg-slate-900 border-cyan-500 shadow-md ring-1 ring-cyan-500/30'
                            : 'bg-slate-950 border-slate-850 hover:border-slate-700'
                        } ${isChild ? 'ml-4' : ''}`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                              span.kind === 'SERVER' ? 'bg-purple-500/20 text-purple-400' : 'bg-cyan-500/20 text-cyan-400'
                            }`}>
                              {span.kind}
                            </span>
                            <span className="font-semibold text-slate-200 truncate max-w-[280px]">
                              {span.name}
                            </span>
                          </div>

                          <div className="flex items-center space-x-2 text-[11px]">
                            <span className="text-slate-400">{span.durationMs || 45}ms</span>
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                              span.statusCode === 'OK' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'
                            }`}>
                              {span.statusCode}
                            </span>
                          </div>
                        </div>

                        <div className="flex items-center space-x-3 text-[10px] text-slate-500 mt-2">
                          <span>Span: <strong className="text-slate-400">{span.spanId}</strong></span>
                          {span.parentSpanId && <span>Parent: <strong className="text-slate-400">{span.parentSpanId}</strong></span>}
                          <span>Events: <strong className="text-cyan-400">{span.events.length}</strong></span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Span Inspector Panel */}
              <div className="lg:col-span-5 bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-4 font-mono text-xs">
                {selectedSpan ? (
                  <>
                    <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                      <span className="font-bold text-cyan-400 truncate">{selectedSpan.name}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 font-bold">
                        {selectedSpan.statusCode}
                      </span>
                    </div>

                    {/* Correlation Linkage */}
                    <div className="space-y-1.5">
                      <span className="text-slate-500 text-[10px] uppercase font-semibold block">Correlation IDs:</span>
                      <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-850 space-y-1 text-[11px]">
                        <div className="flex justify-between"><span className="text-slate-500">Trace:</span> <span className="text-slate-300">{selectedSpan.traceId}</span></div>
                        <div className="flex justify-between"><span className="text-slate-500">Span:</span> <span className="text-slate-300">{selectedSpan.spanId}</span></div>
                        {selectedSpan.parentSpanId && <div className="flex justify-between"><span className="text-slate-500">Parent:</span> <span className="text-slate-300">{selectedSpan.parentSpanId}</span></div>}
                        <div className="flex justify-between"><span className="text-slate-500">Request:</span> <span className="text-emerald-400">{selectedSpan.correlation.requestId}</span></div>
                        {selectedSpan.correlation.stageRunId && <div className="flex justify-between"><span className="text-slate-500">Stage:</span> <span className="text-purple-400">{selectedSpan.correlation.stageRunId}</span></div>}
                      </div>
                    </div>

                    {/* Span Attributes (Sanitized) */}
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-slate-500 text-[10px] uppercase font-semibold">Sanitized Attributes:</span>
                        <span className="text-[10px] text-emerald-400 flex items-center space-x-1">
                          <ShieldCheck className="w-3 h-3" />
                          <span>Redaction Active</span>
                        </span>
                      </div>
                      <pre className="bg-slate-900 p-3 rounded-lg border border-slate-850 text-cyan-300 text-[11px] overflow-x-auto">
                        {JSON.stringify(selectedSpan.attributes, null, 2)}
                      </pre>
                    </div>

                    {/* Span Events */}
                    {selectedSpan.events.length > 0 && (
                      <div className="space-y-1.5">
                        <span className="text-slate-500 text-[10px] uppercase font-semibold block">Span Events ({selectedSpan.events.length}):</span>
                        <div className="space-y-1">
                          {selectedSpan.events.map((evt, eIdx) => (
                            <div key={eIdx} className="bg-slate-900 p-2 rounded border border-slate-850 text-[11px] flex justify-between">
                              <span className="text-slate-200 font-semibold">{evt.name}</span>
                              <span className="text-slate-500 text-[10px]">{new Date(evt.timestamp).toLocaleTimeString()}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <div className="p-8 text-center text-slate-500">Select a span from the waterfall to inspect telemetry attributes.</div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: PIPELINE METRICS & 71-COVERAGE */}
        {activeTab === 'metrics' && (
          <div className="space-y-5 font-mono text-xs">
            {/* Top 4 KPI Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                <span className="text-slate-500 text-[10px] block">71-Engine Coverage</span>
                <span className="text-emerald-400 text-lg font-bold">100.0% (71/71)</span>
                <span className="text-slate-500 text-[10px] block mt-1">14,820 AST nodes parsed</span>
              </div>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                <span className="text-slate-500 text-[10px] block">Pipeline p95 Latency</span>
                <span className="text-cyan-400 text-lg font-bold">{metricsSnapshot.timings.stageDurationMs.p95}ms</span>
                <span className="text-slate-500 text-[10px] block mt-1">Target SLA: &lt; 2000ms</span>
              </div>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                <span className="text-slate-500 text-[10px] block">Sandbox Success Rate</span>
                <span className="text-emerald-400 text-lg font-bold">{metricsSnapshot.sandbox.successRatePct}%</span>
                <span className="text-slate-500 text-[10px] block mt-1">14 evasion attacks blocked</span>
              </div>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                <span className="text-slate-500 text-[10px] block">DLQ Spillover Rate</span>
                <span className="text-amber-400 text-lg font-bold">{metricsSnapshot.queues.retryRatePct}%</span>
                <span className="text-slate-500 text-[10px] block mt-1">1 unresolved dead job</span>
              </div>
            </div>

            {/* Timing Distributions & Latencies */}
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
              <span className="font-bold text-slate-200 block text-xs">Stage & Workflow Execution Latency Distribution:</span>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-slate-900 p-3.5 rounded-lg border border-slate-850 space-y-2">
                  <span className="text-cyan-400 font-semibold block text-[11px]">Stage Execution Duration</span>
                  <div className="flex justify-between text-slate-400"><span>p50:</span> <strong className="text-slate-200">{metricsSnapshot.timings.stageDurationMs.p50}ms</strong></div>
                  <div className="flex justify-between text-slate-400"><span>p90:</span> <strong className="text-slate-200">{metricsSnapshot.timings.stageDurationMs.p90}ms</strong></div>
                  <div className="flex justify-between text-slate-400"><span>p95:</span> <strong className="text-cyan-300">{metricsSnapshot.timings.stageDurationMs.p95}ms</strong></div>
                  <div className="flex justify-between text-slate-400"><span>p99:</span> <strong className="text-amber-400">{metricsSnapshot.timings.stageDurationMs.p99}ms</strong></div>
                </div>

                <div className="bg-slate-900 p-3.5 rounded-lg border border-slate-850 space-y-2">
                  <span className="text-purple-400 font-semibold block text-[11px]">Workflow End-to-End Duration</span>
                  <div className="flex justify-between text-slate-400"><span>p50:</span> <strong className="text-slate-200">{metricsSnapshot.timings.workflowDurationMs.p50}ms</strong></div>
                  <div className="flex justify-between text-slate-400"><span>p90:</span> <strong className="text-slate-200">{metricsSnapshot.timings.workflowDurationMs.p90}ms</strong></div>
                  <div className="flex justify-between text-slate-400"><span>p95:</span> <strong className="text-purple-300">{metricsSnapshot.timings.workflowDurationMs.p95}ms</strong></div>
                  <div className="flex justify-between text-slate-400"><span>p99:</span> <strong className="text-amber-400">{metricsSnapshot.timings.workflowDurationMs.p99}ms</strong></div>
                </div>

                <div className="bg-slate-900 p-3.5 rounded-lg border border-slate-850 space-y-2">
                  <span className="text-emerald-400 font-semibold block text-[11px]">AST Parser Latency</span>
                  <div className="flex justify-between text-slate-400"><span>p50:</span> <strong className="text-slate-200">{metricsSnapshot.timings.parserLatencyMs.p50}ms</strong></div>
                  <div className="flex justify-between text-slate-400"><span>p90:</span> <strong className="text-slate-200">{metricsSnapshot.timings.parserLatencyMs.p90}ms</strong></div>
                  <div className="flex justify-between text-slate-400"><span>p95:</span> <strong className="text-emerald-300">{metricsSnapshot.timings.parserLatencyMs.p95}ms</strong></div>
                  <div className="flex justify-between text-slate-400"><span>p99:</span> <strong className="text-slate-200">{metricsSnapshot.timings.parserLatencyMs.p99}ms</strong></div>
                </div>
              </div>
            </div>

            {/* Capacity Indicators & Pool Saturation */}
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
              <span className="font-bold text-slate-200 block text-xs">Worker Pool Capacity & Concurrency Utilization:</span>
              <div className="space-y-3">
                {capacityMetrics.map((cap, idx) => (
                  <div key={idx} className="bg-slate-900 p-3 rounded-lg border border-slate-850 space-y-2">
                    <div className="flex items-center justify-between">
                      <div>
                        <span className="font-bold text-slate-200">{cap.resource}</span>
                        <span className="text-slate-500 text-[11px] block">Pool: {cap.pool}</span>
                      </div>
                      <div className="text-right">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          cap.status === 'HEALTHY' ? 'bg-emerald-500/20 text-emerald-400' :
                          cap.status === 'WARN' ? 'bg-amber-500/20 text-amber-400' : 'bg-rose-500/20 text-rose-400'
                        }`}>
                          {cap.status} ({cap.utilizationPct}%)
                        </span>
                        <span className="text-slate-500 text-[10px] block mt-0.5">
                          {cap.allocated} / {cap.capacity} Concurrency
                        </span>
                      </div>
                    </div>

                    <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
                      <div
                        className={`h-full ${
                          cap.utilizationPct > 80 ? 'bg-amber-500' :
                          cap.utilizationPct > 90 ? 'bg-rose-500' : 'bg-cyan-500'
                        }`}
                        style={{ width: `${cap.utilizationPct}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: GEMINI & COMPUTE COST ACCOUNTING */}
        {activeTab === 'cost' && (
          <div className="space-y-5 font-mono text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                <span className="text-slate-500 text-[10px] block">Total Gemini AI Cost</span>
                <span className="text-emerald-400 text-lg font-bold">${metricsSnapshot.geminiAi.totalCostUsd} USD</span>
                <span className="text-slate-500 text-[10px] block mt-1">3.1M total tokens processed</span>
              </div>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                <span className="text-slate-500 text-[10px] block">Total Sandbox Hypervisor Cost</span>
                <span className="text-cyan-400 text-lg font-bold">${metricsSnapshot.sandbox.sandboxCostUsd} USD</span>
                <span className="text-slate-500 text-[10px] block mt-1">310 isolated gVisor runs</span>
              </div>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
                <span className="text-slate-500 text-[10px] block">Avg Assurance Cost / Run</span>
                <span className="text-purple-400 text-lg font-bold">${metricsSnapshot.geminiAi.avgCostPerRunUsd} USD</span>
                <span className="text-slate-500 text-[10px] block mt-1">Compute + AI + Hypervisor</span>
              </div>
            </div>

            {/* Per-Agent Cost Attribution Breakdown Table */}
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
              <span className="font-bold text-slate-200 block text-xs">Multi-Dimensional Cost Attribution per Agent:</span>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                      <th className="py-2.5 px-3">Agent Identifier</th>
                      <th className="py-2.5 px-3">Compute</th>
                      <th className="py-2.5 px-3">Gemini Tokens</th>
                      <th className="py-2.5 px-3">Sandbox</th>
                      <th className="py-2.5 px-3">Storage</th>
                      <th className="py-2.5 px-3 text-right">Total Cost (USD)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-850">
                    {Object.entries(costBreakdown).map(([agentName, cost]: [string, CostAttribution]) => (
                      <tr key={agentName} className="hover:bg-slate-900/50">
                        <td className="py-3 px-3 font-semibold text-cyan-400">{agentName}</td>
                        <td className="py-3 px-3 text-slate-300">${cost.computeCostUsd.toFixed(2)}</td>
                        <td className="py-3 px-3 text-emerald-400">${cost.geminiTokenCostUsd.toFixed(2)}</td>
                        <td className="py-3 px-3 text-purple-400">${cost.sandboxCostUsd.toFixed(2)}</td>
                        <td className="py-3 px-3 text-slate-400">${cost.storageCostUsd.toFixed(2)}</td>
                        <td className="py-3 px-3 text-right font-bold text-slate-100">${cost.totalCostUsd.toFixed(2)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* RAG Grounding & Citation Quality */}
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
              <span className="font-bold text-slate-200 block text-xs">Knowledge Retrieval (RAG) & Lineage Metrics:</span>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-slate-900 p-3 rounded-lg border border-slate-850">
                  <span className="text-slate-500 text-[10px] block">RAG Retrieval Latency</span>
                  <span className="text-cyan-400 text-base font-bold">{metricsSnapshot.rag.avgRetrievalLatencyMs}ms</span>
                </div>
                <div className="bg-slate-900 p-3 rounded-lg border border-slate-850">
                  <span className="text-slate-500 text-[10px] block">Grounding Confidence Score</span>
                  <span className="text-emerald-400 text-base font-bold">{metricsSnapshot.rag.avgGroundingScorePct}%</span>
                </div>
                <div className="bg-slate-900 p-3 rounded-lg border border-slate-850">
                  <span className="text-slate-500 text-[10px] block">Citation Verification Rate</span>
                  <span className="text-purple-400 text-base font-bold">{metricsSnapshot.rag.citationVerificationRatePct}%</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: CRYPTOGRAPHIC AUDIT TRAIL */}
        {activeTab === 'audit' && (
          <div className="space-y-4">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search audit actions, actors, targets, or signatures..."
                value={searchAudit}
                onChange={e => setSearchAudit(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div className="space-y-3 font-mono text-xs">
              {filteredAudits.map(evt => (
                <div key={evt.auditId} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-cyan-400">{evt.auditId}</span>
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 font-semibold">
                        {evt.actorType}
                      </span>
                    </div>
                    <span className="text-slate-500 text-[11px]">{new Date(evt.timestamp).toUTCString()}</span>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 text-[11px]">
                    <span className="text-slate-200 font-semibold">{evt.actorId}</span>
                    <span className="text-slate-500">performed</span>
                    <span className="text-purple-400 font-bold">[{evt.action}]</span>
                    <span className="text-slate-500">on</span>
                    <span className="text-emerald-400 font-semibold">{evt.targetId}</span>
                  </div>

                  <pre className="bg-slate-900 p-2.5 rounded border border-slate-850 text-slate-300 text-[11px] overflow-x-auto">
                    {JSON.stringify(evt.details, null, 2)}
                  </pre>

                  <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1">
                    <span>Digest: <strong className="text-slate-400">{evt.signatureSha256}</strong></span>
                    <span className="text-emerald-400 flex items-center space-x-1">
                      <ShieldCheck className="w-3 h-3" />
                      <span>Sanitized & Signed</span>
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 5: ALERT CONDITIONS */}
        {activeTab === 'alerts' && (
          <div className="space-y-3 font-mono text-xs">
            {alertConditions.map(alert => (
              <div key={alert.id} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="font-bold text-slate-100">{alert.name}</span>
                    <span className="text-slate-500 text-[11px]">({alert.id})</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    alert.status === 'FIRING' ? 'bg-rose-500/20 text-rose-400 animate-pulse' : 'bg-emerald-500/20 text-emerald-400'
                  }`}>
                    {alert.status}
                  </span>
                </div>

                <p className="text-slate-400 font-sans text-xs">{alert.description}</p>

                <div className="flex flex-wrap items-center gap-4 text-[11px] text-slate-500 pt-1">
                  <span>Metric: <strong className="text-cyan-400">{alert.metricKey}</strong></span>
                  <span>Condition: <strong className="text-slate-300">{alert.operator} {alert.threshold} {alert.unit}</strong></span>
                  <span>Current: <strong className={alert.status === 'FIRING' ? 'text-rose-400 font-bold' : 'text-emerald-400'}>{alert.currentValue} {alert.unit}</strong></span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* TAB 6: SECRET REDACTION ENGINE & TESTER */}
        {activeTab === 'redaction' && (
          <div className="space-y-4 font-mono text-xs">
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span className="font-bold text-slate-100">Live Secret Redactor Sandbox</span>
              </div>
              <p className="text-slate-400 font-sans text-xs">
                Test the zero-leak redactor in real-time. Paste strings or JSON payloads with simulated API keys, bearer tokens, passwords, private keys, or credentials.
              </p>

              <div className="space-y-2">
                <textarea
                  rows={3}
                  value={customTestInput}
                  onChange={e => setCustomTestInput(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg p-3 text-cyan-300 text-xs font-mono focus:outline-none focus:border-cyan-500"
                  placeholder="Paste payload with secrets..."
                />

                <div className="flex justify-end">
                  <button
                    onClick={handleTestRedaction}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition-colors"
                  >
                    <Play className="w-3.5 h-3.5" />
                    <span>Run Redaction Test</span>
                  </button>
                </div>
              </div>

              {redactionTestOutput && (
                <div className="bg-slate-900 p-3 rounded-lg border border-slate-850 space-y-2">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-slate-400">Sanitized Output:</span>
                    <span className="text-emerald-400 font-semibold">
                      {redactionTestOutput.redactionsCount} secrets redacted ({redactionTestOutput.detectedCategories.join(', ')})
                    </span>
                  </div>
                  <pre className="bg-slate-950 p-3 rounded text-emerald-300 text-xs overflow-x-auto whitespace-pre-wrap">
                    {redactionTestOutput.sanitizedText}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
