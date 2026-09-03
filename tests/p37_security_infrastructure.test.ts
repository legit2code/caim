import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDb } from '../packages/db/src/migrator.ts';
import { 
  PlatformAuditService, 
  RateLimiterEngine, 
  CsrfProtectionEngine,
  createRateLimiterMiddleware,
  createCsrfProtectionMiddleware,
  SecurityClassificationRank,
  PostgresRateLimitStore,
  SharedInMemoryRateLimitStore,
  RATE_LIMIT_TIERS
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
    rateLimiter = new RateLimiterEngine({ dbClient });
    csrfEngine = new CsrfProtectionEngine();
  });

  describe('1. Rate Limiting Engine (Per-Principal & Tiered Routes)', () => {
    it('should distinguish caller key per-authenticated-principal and apply tiered limits', async () => {
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

      const regularCheck = await rateLimiter.checkLimit(regularReq);
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

      const expensiveCheck = await rateLimiter.checkLimit(expensiveReq);
      expect(expensiveCheck.allowed).toBe(true);
      expect(expensiveCheck.tierName).toBe('COMPOSER_EXECUTE');
      expect(expensiveCheck.limit).toBe(10); // Heavy execution tier
    });

    it('should block requests exceeding the tier allowance with 429 semantics', async () => {
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
        const res = await rateLimiter.checkLimit(genReq);
        expect(res.allowed).toBe(true);
      }

      // 6th request must be denied
      const deniedRes = await rateLimiter.checkLimit(genReq);
      expect(deniedRes.allowed).toBe(false);
      expect(deniedRes.remaining).toBe(0);
      expect(deniedRes.retryAfterSeconds).toBeGreaterThan(0);
    });

    it('should isolate rate limits across distinct principals so one user cannot starve another', async () => {
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
        await rateLimiter.checkLimit(reqA);
      }

      const blockedA = await rateLimiter.checkLimit(reqA);
      expect(blockedA.allowed).toBe(false);

      // User B must still be allowed
      const allowedB = await rateLimiter.checkLimit(reqB);
      expect(allowedB.allowed).toBe(true);
    });

    it('should fallback to IP-scoped buckets for unauthenticated principals', async () => {
      const check = await rateLimiter.checkLimit({
        path: '/api/auth/login',
        method: 'POST',
        principal: undefined,
        ip: '10.0.0.99',
        headers: {},
      } as any);
      expect(check.allowed).toBe(true);
      expect(check.callerKey).toContain('ip:10.0.0.99');
    });

    it('should enforce a shared combined rate limit across two separate simulated server instances (PostgreSQL backing store)', async () => {
      // Create two separate server instances sharing the exact same PostgreSQL database
      const serverInstance1 = new RateLimiterEngine({ dbClient });
      const serverInstance2 = new RateLimiterEngine({ dbClient });

      const principalId = 'user-loadbalancer-test';
      const expensiveRequest = {
        path: '/api/composer/generate',
        method: 'POST',
        principal: { principal_id: principalId, is_authenticated: true },
        headers: {},
      } as any;

      // Tier limit for COMPOSER_GENERATE is 5 requests per window
      // Send 3 requests through Server Instance 1
      for (let i = 0; i < 3; i++) {
        const res = await serverInstance1.checkLimit(expensiveRequest);
        expect(res.allowed).toBe(true);
      }

      // Send 2 requests through Server Instance 2 (total 5 requests across both instances)
      for (let i = 0; i < 2; i++) {
        const res = await serverInstance2.checkLimit(expensiveRequest);
        expect(res.allowed).toBe(true);
      }

      // 6th request sent to Server Instance 1 must be blocked (shared limit exhausted!)
      const blocked1 = await serverInstance1.checkLimit(expensiveRequest);
      expect(blocked1.allowed).toBe(false);
      expect(blocked1.remaining).toBe(0);

      // 7th request sent to Server Instance 2 must also be blocked
      const blocked2 = await serverInstance2.checkLimit(expensiveRequest);
      expect(blocked2.allowed).toBe(false);
      expect(blocked2.remaining).toBe(0);
    });

    it('should enforce a shared combined rate limit across two separate simulated server instances (Shared store)', async () => {
      const sharedStore = new SharedInMemoryRateLimitStore();
      const serverA = new RateLimiterEngine({ store: sharedStore });
      const serverB = new RateLimiterEngine({ store: sharedStore });

      const request = {
        path: '/api/composer/execute',
        method: 'POST',
        principal: { principal_id: 'shared-user-01', is_authenticated: true },
        headers: {},
      } as any;

      // Tier limit for COMPOSER_EXECUTE is 10 requests per window
      // Send 6 requests to Server A
      for (let i = 0; i < 6; i++) {
        const res = await serverA.checkLimit(request);
        expect(res.allowed).toBe(true);
      }

      // Send 4 requests to Server B (reaches combined 10)
      for (let i = 0; i < 4; i++) {
        const res = await serverB.checkLimit(request);
        expect(res.allowed).toBe(true);
      }

      // 11th request on Server A or Server B must be blocked
      const checkA = await serverA.checkLimit(request);
      expect(checkA.allowed).toBe(false);

      const checkB = await serverB.checkLimit(request);
      expect(checkB.allowed).toBe(false);
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
