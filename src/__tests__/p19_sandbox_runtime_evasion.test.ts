/**
 * P19 — Sandbox, Scenario, Dynamic Behavior & Evasion Test Suite
 * Tests strict isolation, threat model boundaries, default-deny network,
 * canary honeytokens, evasion indicators, and guaranteed teardown.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { 
  SandboxOrchestrationEngine,
  ScenarioRegistry,
  SecretSanitizer,
  CanaryGenerator,
  NetworkPolicyEngine,
  EvasionDetector,
  SandboxLifecycleManager,
  SimulatedSandboxProvider,
  E2BSandboxProvider,
  runDynamicSandboxJob
} from '../../workers/sandbox-orchestrator/index.ts';

describe('P19 — Dynamic Sandbox & Evasion Intelligence', () => {
  beforeEach(async () => {
    await SandboxLifecycleManager.cleanupAllActiveSessions();
  });

  afterEach(async () => {
    await SandboxLifecycleManager.cleanupAllActiveSessions();
  });

  describe('Threat Model & Secret Sanitization Boundary', () => {
    it('strictly strips platform keys (Supabase, Gemini, JWT secrets) from env vars', () => {
      const dirtyEnv = {
        'SAFE_CONFIG_VAR': 'production-mode',
        'GEMINI_API_KEY': 'AIzaSyFakeLiveKey1234567890123456789',
        'SUPABASE_SERVICE_ROLE_KEY': 'sbp_0123456789abcdef0123456789abcdef01234567',
        'SUPABASE_URL': 'https://example.supabase.co',
        'DATABASE_URL': 'postgres://postgres:password@db.supabase.co:5432/postgres',
        'JWT_SECRET': 'super_secret_jwt_signing_key',
        'DISCOVERY_API_TOKEN': 'disc_tok_9988',
      };

      const result = SecretSanitizer.sanitizeEnvVars(dirtyEnv);
      expect(result.report.isClean).toBe(false);
      expect(result.report.sanitizedCount).toBe(6);
      expect(result.sanitized.SAFE_CONFIG_VAR).toBe('production-mode');
      expect(result.sanitized.GEMINI_API_KEY).toBeUndefined();
      expect(result.sanitized.SUPABASE_SERVICE_ROLE_KEY).toBeUndefined();
      expect(result.sanitized.SUPABASE_URL).toBeUndefined();
      expect(result.sanitized.JWT_SECRET).toBeUndefined();
      expect(result.sanitized.DISCOVERY_API_TOKEN).toBeUndefined();
    });

    it('redacts real credentials from file contents prior to sandbox transfer', () => {
      const dirtyFiles = {
        'src/config.js': 'const key = "AIzaSyFakeKeyMustBeRedacted123456789"; console.log(key);',
      };

      const result = SecretSanitizer.sanitizeFilePayload(dirtyFiles);
      expect(result.report.isClean).toBe(false);
      expect(result.sanitized['src/config.js']).toContain('[REDACTED_API_KEY]');
      expect(result.sanitized['src/config.js']).not.toContain('AIzaSy');
    });
  });

  describe('Nonfunctional Canary Honeytoken Engine', () => {
    it('generates high-entropy synthetic honeytoken secrets', () => {
      const canary = CanaryGenerator.generateCanary('Test Stripe API', 'API_KEY', 'STRIPE_SECRET_KEY', 'ENV_VAR');
      expect(canary.synthetic_value).toMatch(/^sk-canary-prod-live-[a-f0-9]+99deadbeef$/);
      expect(canary.tripped).toBe(false);
      expect(canary.target_key_name).toBe('STRIPE_SECRET_KEY');
    });

    it('detects when an execution trace or output accesses or leaks canary secrets', () => {
      const canaries = CanaryGenerator.generateStandardCanarySuite();
      const traceOutput = `Attempting credential dump: found secret ${canaries[0].synthetic_value} in env`;

      const check = CanaryGenerator.checkPayloadForCanary(canaries, traceOutput, 'STDOUT_DUMP');
      expect(check.hasTrip).toBe(true);
      expect(check.trippedCanaries.length).toBe(1);
      expect(check.trippedCanaries[0].name).toBe('Stripe Live API Key');
      expect(check.trippedCanaries[0].tripped_by_action).toBe('STDOUT_DUMP');
    });
  });

  describe('Default-Deny Network Policy & Egress Inspection', () => {
    it('blocks all outbound connection attempts by default (DEFAULT_DENY)', () => {
      const res = NetworkPolicyEngine.evaluateConnection(
        NetworkPolicyEngine.DEFAULT_DENY_POLICY,
        'untrusted-c2.example.com',
        443,
        'HTTPS'
      );

      expect(res.allowed).toBe(false);
      expect(res.ruleMatched).toBe('DEFAULT_DENY_RULE');
      expect(res.event.status).toBe('BLOCKED');
      expect(res.event.category).toBe('NETWORK');
      expect(res.event.action).toBe('EGRESS_BLOCKED');
      expect(res.event.severity).toBe('HIGH');
    });

    it('blocks unauthorized DNS queries when allowDns is false', () => {
      const res = NetworkPolicyEngine.evaluateConnection(
        NetworkPolicyEngine.DEFAULT_DENY_POLICY,
        'malicious-domain.com',
        53,
        'DNS'
      );

      expect(res.allowed).toBe(false);
      expect(res.ruleMatched).toBe('DNS_RESTRICTION');
      expect(res.event.action).toBe('DNS_BLOCKED');
    });

    it('permits connections to strictly whitelisted domains under WHITELIST_ONLY policy', () => {
      const resAllowed = NetworkPolicyEngine.evaluateConnection(
        NetworkPolicyEngine.TEST_WHITELIST_POLICY,
        'registry.npmjs.org',
        443,
        'HTTPS'
      );
      expect(resAllowed.allowed).toBe(true);
      expect(resAllowed.ruleMatched).toBe('WHITELIST_PERMIT');
      expect(resAllowed.event.status).toBe('ALLOWED');

      const resBlocked = NetworkPolicyEngine.evaluateConnection(
        NetworkPolicyEngine.TEST_WHITELIST_POLICY,
        'evil-exfil-server.com',
        443,
        'HTTPS'
      );
      expect(resBlocked.allowed).toBe(false);
      expect(resBlocked.ruleMatched).toBe('WHITELIST_DENY');
    });
  });

  describe('Versioned Scenario Registry & Execution', () => {
    it('loads all 8 standardized canonical scenarios', () => {
      const list = ScenarioRegistry.listScenarios();
      expect(list.length).toBeGreaterThanOrEqual(8);
      
      const ids = list.map(s => s.id);
      expect(ids).toContain('SCN-BENIGN-01');
      expect(ids).toContain('SCN-MALFORMED-01');
      expect(ids).toContain('SCN-PROMPT-INJ-01');
      expect(ids).toContain('SCN-PERM-BOUNDARY-01');
      expect(ids).toContain('SCN-CANARY-01');
      expect(ids).toContain('SCN-NET-RESTRICT-01');
      expect(ids).toContain('SCN-PERSISTENCE-01');
      expect(ids).toContain('SCN-SANDBOX-AWARE-01');
    });

    it('executes SCN-BENIGN-01 cleanly and records complete behavior sequences', async () => {
      const result = await SandboxOrchestrationEngine.runScenario({
        scenarioId: 'SCN-BENIGN-01',
        providerType: 'SIMULATED',
      });

      expect(result.status).toBe('PASSED');
      expect(result.evasion_risk_score).toBe(0.0);
      expect(result.canaries_tripped.length).toBe(0);
      expect(result.teardown.final_status).toBe('TERMINATED');
      expect(result.teardown.guaranteed_clean).toBe(true);
      expect(result.behavior_sequences.length).toBe(4);
    });

    it('executes SCN-CANARY-01 and flags honeytoken access', async () => {
      const result = await SandboxOrchestrationEngine.runScenario({
        scenarioId: 'SCN-CANARY-01',
        providerType: 'SIMULATED',
      });

      expect(result.canaries_injected.length).toBeGreaterThanOrEqual(2);
      expect(result.canaries_tripped.length).toBeGreaterThanOrEqual(1);
      expect(result.runtime_events.some(e => e.category === 'CANARY')).toBe(true);
      expect(result.teardown.guaranteed_clean).toBe(true);
    });

    it('executes SCN-NET-RESTRICT-01 and enforces egress block under default-deny', async () => {
      const result = await SandboxOrchestrationEngine.runScenario({
        scenarioId: 'SCN-NET-RESTRICT-01',
        providerType: 'SIMULATED',
      });

      expect(result.runtime_events.some(e => e.action === 'EGRESS_BLOCKED')).toBe(true);
      expect(result.network_policy.type).toBe('DEFAULT_DENY');
      expect(result.teardown.guaranteed_clean).toBe(true);
    });

    it('executes SCN-SANDBOX-AWARE-01 and flags evasion & anti-analysis indicators', async () => {
      const result = await SandboxOrchestrationEngine.runScenario({
        scenarioId: 'SCN-SANDBOX-AWARE-01',
        providerType: 'SIMULATED',
      });

      expect(result.evasion_risk_score).toBeGreaterThanOrEqual(0.70);
      expect(result.evasion_indicators.some(i => i.type === 'DELAYED_ACTIVATION' && i.detected)).toBe(true);
      expect(result.evasion_indicators.some(i => i.type === 'ENVIRONMENT_FINGERPRINTING' && i.detected)).toBe(true);
      expect(result.anti_analysis_detected).toBe(true);
      expect(result.status).toBe('EVASION_FLAGGED');
    });
  });

  describe('Evasion & Anti-Analysis Detection Engine', () => {
    it('detects prolonged sleep loops and delayed execution', () => {
      const events: any[] = [
        {
          event_id: 'e1',
          timestamp: new Date().toISOString(),
          category: 'SECURITY',
          action: 'EVASION_DELAY_DETECTED',
          metadata: { durationSeconds: 10 },
        }
      ];
      const traces = ['sleep 10; echo "payload"'];

      const res = EvasionDetector.analyze(events, traces);
      expect(res.indicators.find(i => i.type === 'DELAYED_ACTIVATION')?.detected).toBe(true);
      expect(res.evasionRiskScore).toBeGreaterThan(0);
    });

    it('detects /proc/cpuinfo and hypervisor environment fingerprinting', () => {
      const events: any[] = [];
      const traces = ['cat /proc/cpuinfo | grep hypervisor; is_vm_check()'];

      const res = EvasionDetector.analyze(events, traces);
      expect(res.indicators.find(i => i.type === 'ENVIRONMENT_FINGERPRINTING')?.detected).toBe(true);
      expect(res.antiAnalysisDetected).toBe(true);
    });

    it('detects dynamic eval / base64 code obfuscation', () => {
      const events: any[] = [];
      const traces = ['eval(Buffer.from("Y29uc29sZS5sb2coJ2hpZGRlbicp", "base64").toString())'];

      const res = EvasionDetector.analyze(events, traces);
      expect(res.indicators.find(i => i.type === 'CODE_OBFUSCATION')?.detected).toBe(true);
    });
  });

  describe('Guaranteed Teardown Lifecycle Guarantee', () => {
    it('guarantees teardown and releases all resources even if execution throws', async () => {
      const provider = new SimulatedSandboxProvider();
      const sessionId = 'test-teardown-sess-01';

      await provider.provision({
        sessionId,
        scenarioId: 'SCN-BENIGN-01',
        scenarioVersion: '1.0.0',
        resourceQuota: {
          maxDurationMs: 5000,
          maxMemoryMb: 256,
          maxCpuPercentage: 50,
          maxProcessCount: 5,
          maxOutputSizeBytes: 1024,
        },
        networkPolicy: NetworkPolicyEngine.DEFAULT_DENY_POLICY,
        canaries: [],
        envVars: {},
        files: {},
      });

      SandboxLifecycleManager.registerSession(sessionId, provider, 'SCN-BENIGN-01');
      expect(SandboxLifecycleManager.getActiveSessionCount()).toBe(1);

      const teardown = await SandboxLifecycleManager.teardownSession(sessionId);
      expect(teardown.final_status).toBe('TERMINATED');
      expect(teardown.resources_released).toBe(true);
      expect(teardown.guaranteed_clean).toBe(true);
      expect(SandboxLifecycleManager.getActiveSessionCount()).toBe(0);
    });
  });

  describe('E2B Provider Isolation & Degraded Fallback', () => {
    it('supports E2B provider initialization with safe credential sanitization', async () => {
      const e2b = new E2BSandboxProvider();
      expect(e2b.providerType).toBe('E2B');

      const sessionId = await e2b.provision({
        sessionId: 'e2b-test-sess',
        scenarioId: 'SCN-BENIGN-01',
        scenarioVersion: '1.0.0',
        resourceQuota: SandboxOrchestrationEngine.DEFAULT_RESOURCE_QUOTA,
        networkPolicy: NetworkPolicyEngine.DEFAULT_DENY_POLICY,
        canaries: [],
        envVars: {
          'APP_ENV': 'test',
          'SUPABASE_SERVICE_ROLE_KEY': 'forbidden_key_value', // should be sanitized
        },
        files: {
          'index.js': 'console.log("E2B test");',
        },
      });

      const execRes = await e2b.executeCommand(sessionId, {
        command: 'node',
        args: ['index.js'],
      });

      expect(execRes.exitCode).toBe(0);
      const teardown = await e2b.destroy(sessionId);
      expect(teardown.guaranteed_clean).toBe(true);
    });
  });

  describe('Background Worker Job Integration', () => {
    it('runs dynamic sandbox jobs through runDynamicSandboxJob entry point', async () => {
      const jobResult = await runDynamicSandboxJob({
        artifactId: 'art-job-test-01',
        scenarioId: 'SCN-BENIGN-01',
      });

      expect(jobResult.status).toBe('PASSED');
      expect(jobResult.artifact_id).toBe('art-job-test-01');
      expect(jobResult.teardown.guaranteed_clean).toBe(true);
    });
  });
});
