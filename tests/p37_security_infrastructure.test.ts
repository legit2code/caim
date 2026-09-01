import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDb } from '../packages/db/src/migrator.ts';
import { 
  PlatformAuditService, 
  RateLimiterEngine, 
  CsrfProtectionEngine,
  createRateLimiterMiddleware,
  createCsrfProtectionMiddleware,
  SecurityClassificationRank
} from '../packages/auth/src/index.ts';

describe('P37 Security Infrastructure: Rate Limiting, CSRF Defense & Audit Logging', () => {
  let dbClient: any;
  let auditService: PlatformAuditService;
  let rateLimiter: RateLimiterEngine;
  let csrfEngine: CsrfProtectionEngine;

  beforeEach(async () => {
    const memDb = createTestDb({ applyMigrations: true, applySeed: true });
    const pg = memDb.adapters.createPg();
    dbClient = new pg.Client();
    await dbClient.connect();

    auditService = new PlatformAuditService(dbClient);
    rateLimiter = new RateLimiterEngine();
    csrfEngine = new CsrfProtectionEngine();
  });

  describe('1. Rate Limiting Engine (Per-Principal & Tiered Routes)', () => {
    it('should distinguish caller key per-authenticated-principal and apply tiered limits', () => {
      const regularReq = {
        path: '/api/library/agents',
        method: 'GET',
        principal: {
          principal_id: 'user-alice',
          is_authenticated: true,
          role_name: 'SECURITY_ANALYST',
        },
        ip: '192.168.1.10',
        headers: {},
      } as any;

      const regularCheck = rateLimiter.checkLimit(regularReq);
      expect(regularCheck.allowed).toBe(true);
      expect(regularCheck.callerKey).toBe('principal:user-alice');
      expect(regularCheck.limit).toBe(120); // Standard route tier

      const expensiveReq = {
        path: '/api/composer/execute',
        method: 'POST',
        principal: {
          principal_id: 'user-alice',
          is_authenticated: true,
          role_name: 'SECURITY_ANALYST',
        },
        ip: '192.168.1.10',
        headers: {},
      } as any;

      const expensiveCheck = rateLimiter.checkLimit(expensiveReq);
      expect(expensiveCheck.allowed).toBe(true);
      expect(expensiveCheck.tierName).toBe('COMPOSER_EXECUTE');
      expect(expensiveCheck.limit).toBe(10); // Heavy execution tier
    });

    it('should block requests exceeding the tier allowance with 429 semantics', () => {
      const principal = 'user-spammer';
      const genReq = {
        path: '/api/composer/generate',
        method: 'POST',
        principal: {
          principal_id: principal,
          is_authenticated: true,
        },
        headers: {},
      } as any;

      // Fill the expensive bucket (limit: 5 for COMPOSER_GENERATE)
      for (let i = 0; i < 5; i++) {
        const res = rateLimiter.checkLimit(genReq);
        expect(res.allowed).toBe(true);
      }

      // 6th request must be denied
      const deniedRes = rateLimiter.checkLimit(genReq);
      expect(deniedRes.allowed).toBe(false);
      expect(deniedRes.remaining).toBe(0);
      expect(deniedRes.retryAfterSeconds).toBeGreaterThan(0);
    });

    it('should isolate rate limits across distinct principals so one user cannot starve another', () => {
      const reqA = {
        path: '/api/analysis/trigger',
        method: 'POST',
        principal: { principal_id: 'user-a', is_authenticated: true },
        headers: {},
      } as any;

      const reqB = {
        path: '/api/analysis/trigger',
        method: 'POST',
        principal: { principal_id: 'user-b', is_authenticated: true },
        headers: {},
      } as any;

      for (let i = 0; i < 10; i++) {
        rateLimiter.checkLimit(reqA);
      }

      const blockedA = rateLimiter.checkLimit(reqA);
      expect(blockedA.allowed).toBe(false);

      // User B must still be allowed
      const allowedB = rateLimiter.checkLimit(reqB);
      expect(allowedB.allowed).toBe(true);
    });

    it('should fallback to IP-scoped buckets for unauthenticated principals', () => {
      const check = rateLimiter.checkLimit({
        path: '/api/auth/login',
        method: 'POST',
        principal: undefined,
        ip: '10.0.0.99',
        headers: {},
      } as any);
      expect(check.allowed).toBe(true);
      expect(check.callerKey).toContain('ip:10.0.0.99');
    });
  });

  describe('2. CSRF Defense-in-Depth & Cross-Origin Protection', () => {
    it('should allow safe HTTP read-only methods (GET, HEAD, OPTIONS) without custom headers', () => {
      const evalGet = csrfEngine.evaluateRequest({
        method: 'GET',
        headers: {},
        path: '/api/library/agents',
      } as any);
      expect(evalGet.allowed).toBe(true);
      expect(evalGet.authType).toBe('SAME_ORIGIN');
    });

    it('should allow state-changing POST requests carrying Authorization: Bearer JWT', () => {
      const evalPost = csrfEngine.evaluateRequest({
        method: 'POST',
        headers: {
          authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        },
        path: '/api/analysis/trigger',
      } as any);
      expect(evalPost.allowed).toBe(true);
      expect(evalPost.authType).toBe('BEARER_JWT');
    });

    it('should reject state-changing requests lacking Bearer auth or custom headers from untrusted origins', () => {
      const attackEvaluation = csrfEngine.evaluateRequest({
        method: 'POST',
        headers: {
          origin: 'https://evil-hacker-site.com',
          'content-type': 'application/x-www-form-urlencoded',
        },
        path: '/api/composer/execute',
      } as any);
      expect(attackEvaluation.allowed).toBe(false);
      expect(attackEvaluation.reason).toContain("untrusted origin 'https://evil-hacker-site.com'");
    });

    it('should produce a comprehensive CSRF security report', () => {
      const report = csrfEngine.getCsrfSecurityReport();
      expect(report.auth_mechanism).toContain('Authorization: Bearer');
      expect(report.rationale).toContain('ambient credentials');
      expect(report.csrf_tokens_required).toBe(false);
      expect(report.defense_in_depth_controls.length).toBeGreaterThan(0);
    });
  });

  describe('3. Central Append-Only Platform Audit Log', () => {
    it('should append structured audit entries and compute SHA-256 signatures', async () => {
      const entry1 = await auditService.recordAuditEntry({
        principal_id: 'user-analyst-1',
        action: 'ANALYSIS_TRIGGERED',
        target_entity_type: 'AGENT_VERSION',
        target_entity_id: 'av-finance-001',
        outcome: 'SUCCESS',
        client_ip: '127.0.0.1',
        user_agent: 'Vitest Test Runner',
        details: { score: 92, risk: 'LOW' },
      });

      expect(entry1.audit_id).toBeDefined();
      expect(entry1.signature_sha256).toMatch(/^sha256:/);
      expect(entry1.action).toBe('ANALYSIS_TRIGGERED');

      const entry2 = await auditService.recordAuditEntry({
        principal_id: 'user-admin-1',
        action: 'SCORING_OVERRIDDEN',
        target_entity_type: 'POLICY_DECISION',
        target_entity_id: 'av-finance-001',
        outcome: 'SUCCESS',
        client_ip: '127.0.0.1',
        details: { override_score: 95, justification: 'Authorized business override' },
      });

      expect(entry2.audit_id).toBeDefined();
      expect(entry2.action).toBe('SCORING_OVERRIDDEN');
    });

    it('should redact sensitive tokens and keys in audit details using SecretRedactor', async () => {
      const entry = await auditService.recordAuditEntry({
        principal_id: 'user-dev',
        action: 'COMPOSER_GENERATION_TRIGGERED',
        target_entity_type: 'COMPOSER_ARTIFACT',
        target_entity_id: 'art-001',
        outcome: 'SUCCESS',
        details: {
          api_key: 'sk-live-1234567890abcdef1234567890abcdef',
          bearer: 'Bearer secret_token_xyz',
          normal_field: 'safe_value',
        },
      });

      expect(entry.details.api_key).toBe('[REDACTED_SECRET]');
      expect(entry.details.normal_field).toBe('safe_value');
    });

    it('should query audit logs with rich filters and return structured stats', async () => {
      await auditService.recordAuditEntry({
        principal_id: 'user-ops',
        action: 'DISCOVERY_RUN',
        target_entity_type: 'DISCOVERY_PIPELINE',
        target_entity_id: 'disc-01',
        outcome: 'SUCCESS',
      });

      await auditService.recordAuditEntry({
        principal_id: 'user-ops',
        action: 'AGENT_INGESTED',
        target_entity_type: 'CANONICAL_AGENT',
        target_entity_id: 'agent-99',
        outcome: 'SUCCESS',
      });

      const queryResult = await auditService.queryAuditLogs({
        principal_id: 'user-ops',
        limit: 10,
      });

      expect(queryResult.total).toBeGreaterThanOrEqual(2);
      expect(queryResult.logs.length).toBeGreaterThanOrEqual(2);

      const stats = await auditService.getAuditStats();
      expect(stats.total_events).toBeGreaterThanOrEqual(2);
      expect(stats.action_breakdown['DISCOVERY_RUN']).toBeGreaterThanOrEqual(1);
      expect(stats.action_breakdown['AGENT_INGESTED']).toBeGreaterThanOrEqual(1);
    });
  });
});
