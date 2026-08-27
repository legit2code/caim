import { z } from 'zod';
import { 
  createSuccessEnvelope, 
  createErrorEnvelope, 
  ApiSuccessEnvelope, 
  ApiErrorEnvelope,
  EnvelopeMeta
} from './envelopes.ts';
import { 
  ApiError, 
  ValidationError, 
  UnauthorizedError, 
  ForbiddenError, 
  NotFoundError, 
  ConflictError, 
  PolicyBlockedError, 
  PartialAnalysisError, 
  DependencyFailureError, 
  RateLimitedError,
  mapErrorToEnvelope 
} from './errors.ts';
import { IdempotencyManager } from './idempotency.ts';
import { ApiAuthenticator } from './auth.ts';
import { PaginationQuerySchema, paginateAndFilterArray, parseFilterParams } from './pagination.ts';
import { OpenApiGenerator } from './openapi/generator.ts';
import { EventCatalogRegistry } from './events/catalog.ts';
import { QueueOwnershipRegistry } from './queues/registry.ts';
import { SecurityClassificationRank } from '../../auth/src/index.ts';

export interface ApiRequestContext {
  headers: Record<string, string | string[] | undefined>;
  params?: Record<string, string>;
  query?: Record<string, any>;
  body?: any;
  requestId?: string;
  url?: string;
  method?: string;
}

export interface ApiResponse {
  statusCode: number;
  body: ApiSuccessEnvelope | ApiErrorEnvelope;
  headers?: Record<string, string>;
}

export class ApplicationApiRouter {
  private readonly idempotency = IdempotencyManager.getInstance();
  private readonly openApi = new OpenApiGenerator();
  private readonly eventCatalog = EventCatalogRegistry.getInstance();
  private readonly queueRegistry = QueueOwnershipRegistry.getInstance();

  // In-memory domain stores for mock/application service backing
  private agentsStore = new Map<string, any>();
  private agentVersionsStore = new Map<string, any>();
  private analysisRunsStore = new Map<string, any>();
  private validationRunsStore = new Map<string, any>();
  private approvalsStore = new Map<string, any[]>();
  private dlqStore = new Map<string, any>();

  constructor() {
    this.seedDefaultEntities();
    this.registerOpenApiDocs();
  }

  public getOpenApi(): OpenApiGenerator {
    return this.openApi;
  }

  public getEventCatalog(): EventCatalogRegistry {
    return this.eventCatalog;
  }

  public getQueueRegistry(): QueueOwnershipRegistry {
    return this.queueRegistry;
  }

  /**
   * Universal Request Handler wrapping Auth, Idempotency, Validation, Service Dispatch, and Error Mapping
   */
  public async handleRequest(
    handler: (ctx: { principal: any; requestId: string; params: Record<string, string>; query: any; body: any }) => Promise<{ data: any; meta?: Partial<EnvelopeMeta>; statusCode?: number }>,
    req: ApiRequestContext,
    options?: {
      requiresAuth?: boolean;
      allowedRoles?: string[];
      requiredClassification?: SecurityClassificationRank;
      supportsIdempotency?: boolean;
      bodySchema?: z.ZodType<any>;
    }
  ): Promise<ApiResponse> {
    const requestId = req.requestId || `req-${crypto.randomUUID()}`;
    const idempotencyKey = (req.headers['idempotency-key'] || req.headers['Idempotency-Key'] || req.body?.idempotencyKey) as string | undefined;

    try {
      // 1. Auth context extraction & policy enforcement
      const principal = ApiAuthenticator.extractPrincipal(req.headers);
      if (options?.requiresAuth) {
        ApiAuthenticator.requireAuthenticated(principal);
      }
      if (options?.allowedRoles && options.allowedRoles.length > 0) {
        ApiAuthenticator.requireRoles(principal, options.allowedRoles as any);
      }
      if (options?.requiredClassification !== undefined) {
        ApiAuthenticator.requireClassification(principal, options.requiredClassification);
      }

      // 2. Idempotency handling
      if (options?.supportsIdempotency && idempotencyKey) {
        const cached = this.idempotency.acquire(idempotencyKey, principal.principal_id);
        if (cached) {
          return {
            statusCode: cached.statusCode,
            body: {
              ...(cached.responseBody as any),
              meta: {
                ...((cached.responseBody as any).meta || {}),
                idempotency_replayed: true,
                request_id: requestId,
              },
            },
            headers: { 'X-Idempotency-Replayed': 'true' },
          };
        }
      }

      // 3. Request body validation
      let parsedBody = req.body;
      if (options?.bodySchema && req.body) {
        parsedBody = options.bodySchema.parse(req.body);
      }

      // 4. Execute domain handler
      const result = await handler({
        principal,
        requestId,
        params: req.params || {},
        query: req.query || {},
        body: parsedBody,
      });

      const statusCode = result.statusCode || 200;
      const successEnvelope = createSuccessEnvelope(result.data, {
        request_id: requestId,
        ...result.meta,
      });

      // 5. Complete idempotency key
      if (options?.supportsIdempotency && idempotencyKey) {
        this.idempotency.complete(idempotencyKey, statusCode, successEnvelope, principal.principal_id);
      }

      return {
        statusCode,
        body: successEnvelope,
      };
    } catch (err: unknown) {
      if (options?.supportsIdempotency && idempotencyKey) {
        this.idempotency.fail(idempotencyKey, req.headers['x-principal-id'] as string);
      }
      const { statusCode, envelope } = mapErrorToEnvelope(err, requestId);
      return {
        statusCode,
        body: envelope,
      };
    }
  }

  // =========================================================================
  // 1. Agent Registry & Discovery Family
  // =========================================================================

  public async listAgents(req: ApiRequestContext): Promise<ApiResponse> {
    return this.handleRequest(async (ctx) => {
      const pagination = PaginationQuerySchema.parse(ctx.query);
      const filters = parseFilterParams(ctx.query);
      const allAgents = Array.from(this.agentsStore.values());
      const paged = paginateAndFilterArray(allAgents, pagination, filters);
      return { data: paged.data, meta: paged.meta };
    }, req);
  }

  public async createAgent(req: ApiRequestContext): Promise<ApiResponse> {
    const schema = z.object({
      agentId: z.string().min(1),
      canonicalName: z.string().min(1),
      description: z.string().optional(),
      framework: z.string().default('TypeScript'),
      author: z.string().default('Unknown'),
    });

    return this.handleRequest(async (ctx) => {
      if (this.agentsStore.has(ctx.body.agentId)) {
        throw new ConflictError(`Agent with ID '${ctx.body.agentId}' already exists`);
      }
      const newAgent = {
        agent_id: ctx.body.agentId,
        canonical_name: ctx.body.canonicalName,
        description: ctx.body.description || '',
        framework: ctx.body.framework,
        author: ctx.body.author,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      this.agentsStore.set(newAgent.agent_id, newAgent);
      return { data: newAgent, statusCode: 201 };
    }, req, {
      requiresAuth: true,
      allowedRoles: ['analyst', 'admin', 'operator'],
      supportsIdempotency: true,
      bodySchema: schema,
    });
  }

  public async getAgent(req: ApiRequestContext): Promise<ApiResponse> {
    return this.handleRequest(async (ctx) => {
      const agentId = ctx.params.agentId;
      const agent = this.agentsStore.get(agentId);
      if (!agent) {
        throw new NotFoundError('Agent', agentId);
      }
      return { data: agent };
    }, req);
  }

  public async registerAgentVersion(req: ApiRequestContext): Promise<ApiResponse> {
    const schema = z.object({
      agentVersionId: z.string().min(1),
      versionLabel: z.string().min(1),
      sourceLocator: z.string().optional(),
      contentHash: z.string().optional(),
      securityClassification: z.enum(['PUBLIC_METADATA', 'INTERNAL', 'SENSITIVE', 'VAULT_RESTRICTED']).default('INTERNAL'),
    });

    return this.handleRequest(async (ctx) => {
      const agentId = ctx.params.agentId;
      if (!this.agentsStore.has(agentId)) {
        throw new NotFoundError('Agent', agentId);
      }
      if (this.agentVersionsStore.has(ctx.body.agentVersionId)) {
        throw new ConflictError(`AgentVersion with ID '${ctx.body.agentVersionId}' already exists`);
      }

      const version = {
        agent_version_id: ctx.body.agentVersionId,
        agent_id: agentId,
        version_label: ctx.body.versionLabel,
        source_locator: ctx.body.sourceLocator || 'memory://source/default',
        content_hash: ctx.body.contentHash || 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        security_classification: ctx.body.securityClassification,
        created_at: new Date().toISOString(),
      };
      this.agentVersionsStore.set(version.agent_version_id, version);
      return { data: version, statusCode: 201 };
    }, req, {
      requiresAuth: true,
      allowedRoles: ['analyst', 'admin', 'operator'],
      supportsIdempotency: true,
      bodySchema: schema,
    });
  }

  public async getAgentVersion(req: ApiRequestContext): Promise<ApiResponse> {
    return this.handleRequest(async (ctx) => {
      const { agentId, versionId } = ctx.params;
      const version = this.agentVersionsStore.get(versionId);
      if (!version || version.agent_id !== agentId) {
        throw new NotFoundError('AgentVersion', versionId);
      }
      return { data: version };
    }, req);
  }

  // =========================================================================
  // 2. Analysis Pipeline Family
  // =========================================================================

  public async createAnalysisRun(req: ApiRequestContext): Promise<ApiResponse> {
    const schema = z.object({
      analysisRunId: z.string().optional(),
      agentVersionId: z.string().min(1),
      pipelineVersion: z.string().default('2.0.1'),
      simulatePartial: z.boolean().optional(),
      simulateDependencyFailure: z.boolean().optional(),
    });

    return this.handleRequest(async (ctx) => {
      if (ctx.body.simulateDependencyFailure) {
        throw new DependencyFailureError('AST-Syntax-Parser-Worker', 'Connection pool exhausted on node-ast-04', 2000);
      }

      const runId = ctx.body.analysisRunId || `ar-${crypto.randomUUID().slice(0, 8)}`;
      const run = {
        analysis_run_id: runId,
        agent_version_id: ctx.body.agentVersionId,
        pipeline_version: ctx.body.pipelineVersion,
        status: ctx.body.simulatePartial ? 'PARTIAL' : 'COMPLETED',
        findings_count: ctx.body.simulatePartial ? 1 : 4,
        claims_count: ctx.body.simulatePartial ? 1 : 6,
        score: {
          overall_score: ctx.body.simulatePartial ? 55 : 88,
          risk_band: ctx.body.simulatePartial ? 'MODERATE' : 'LOW',
          confidence: 0.95,
        },
        findings: [
          {
            finding_id: `find-${runId}-01`,
            severity: 'LOW',
            title: 'Permissive dynamic import detected',
            location: 'src/agent.ts:12',
          },
        ],
        claims: [
          {
            claim_id: `clm-${runId}-01`,
            claim_type: 'SECURITY_POSTURE',
            claim_state: 'SUPPORTED',
            confidence: 0.96,
          },
        ],
        created_at: new Date().toISOString(),
      };
      this.analysisRunsStore.set(runId, run);

      if (ctx.body.simulatePartial) {
        return {
          data: run,
          statusCode: 200,
          meta: { warning: 'Analysis completed with PARTIAL stage coverage due to unreachable AST sinks' },
        };
      }

      return { data: run, statusCode: 201 };
    }, req, {
      requiresAuth: true,
      allowedRoles: ['analyst', 'admin', 'operator'],
      supportsIdempotency: true,
      bodySchema: schema,
    });
  }

  public async getAnalysisRun(req: ApiRequestContext): Promise<ApiResponse> {
    return this.handleRequest(async (ctx) => {
      const runId = ctx.params.runId;
      const run = this.analysisRunsStore.get(runId);
      if (!run) {
        throw new NotFoundError('AnalysisRun', runId);
      }
      return { data: run };
    }, req);
  }

  public async getAnalysisFindings(req: ApiRequestContext): Promise<ApiResponse> {
    return this.handleRequest(async (ctx) => {
      const runId = ctx.params.runId;
      const run = this.analysisRunsStore.get(runId);
      if (!run) {
        throw new NotFoundError('AnalysisRun', runId);
      }
      const pagination = PaginationQuerySchema.parse(ctx.query);
      const paged = paginateAndFilterArray(run.findings || [], pagination);
      return { data: paged.data, meta: paged.meta };
    }, req);
  }

  // =========================================================================
  // 3. Validation & Policy Gate Family
  // =========================================================================

  public async evaluatePolicyGate(req: ApiRequestContext): Promise<ApiResponse> {
    const schema = z.object({
      agentVersionId: z.string().min(1),
      requestedOutcome: z.enum(['ALLOW', 'ALLOW_WITH_WARNING', 'REQUIRE_REVIEW', 'RESTRICT', 'QUARANTINE', 'DENY_SHIPPING']).default('ALLOW'),
      forceBlock: z.boolean().optional(),
    });

    return this.handleRequest(async (ctx) => {
      if (ctx.body.forceBlock || ctx.body.requestedOutcome === 'DENY_SHIPPING') {
        throw new PolicyBlockedError('Policy gate blocked release: Critical unmitigated taint flow to external sink', {
          policy_outcome: 'DENY_SHIPPING',
          blockers: ['CRITICAL_TAINT_SINK_REACHABLE', 'MISSING_TWO_PERSON_AUTHORIZATION'],
          agent_version_id: ctx.body.agentVersionId,
        });
      }

      return {
        data: {
          allowed: true,
          outcome: ctx.body.requestedOutcome,
          agent_version_id: ctx.body.agentVersionId,
          evaluated_at: new Date().toISOString(),
          blockers: [],
        },
      };
    }, req, {
      requiresAuth: true,
      allowedRoles: ['analyst', 'release_approver', 'admin'],
      bodySchema: schema,
    });
  }

  public async submitApproval(req: ApiRequestContext): Promise<ApiResponse> {
    const schema = z.object({
      agentVersionId: z.string().min(1),
      decision: z.enum(['APPROVED', 'REJECTED']),
      rationale: z.string().min(3),
    });

    return this.handleRequest(async (ctx) => {
      const approval = {
        approval_id: `appr-${crypto.randomUUID().slice(0, 8)}`,
        agent_version_id: ctx.body.agentVersionId,
        approver_id: ctx.principal.principal_id,
        approver_role: ctx.principal.roles.includes('admin') ? 'PLATFORM_ADMIN' : 'SECURITY_AUDITOR',
        decision: ctx.body.decision,
        rationale: ctx.body.rationale,
        decided_at: new Date().toISOString(),
      };

      const existing = this.approvalsStore.get(ctx.body.agentVersionId) || [];
      existing.push(approval);
      this.approvalsStore.set(ctx.body.agentVersionId, existing);

      return { data: approval, statusCode: 201 };
    }, req, {
      requiresAuth: true,
      allowedRoles: ['release_approver', 'auditor', 'admin'],
      supportsIdempotency: true,
      bodySchema: schema,
    });
  }

  // =========================================================================
  // 4. System Health & Readiness Family
  // =========================================================================

  public async getHealth(req: ApiRequestContext): Promise<ApiResponse> {
    return this.handleRequest(async () => {
      return {
        data: {
          status: 'UP',
          timestamp: new Date().toISOString(),
          uptime_seconds: process.uptime(),
          memory_usage_mb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        },
      };
    }, req);
  }

  public async getReadiness(req: ApiRequestContext): Promise<ApiResponse> {
    return this.handleRequest(async () => {
      return {
        data: {
          status: 'READY',
          checks: {
            database_pool: { status: 'HEALTHY', active_connections: 5, max_connections: 20 },
            workflow_queue: { status: 'HEALTHY', active_queues: 7, leased_jobs: 0 },
            kms_signing_enclave: { status: 'HEALTHY', active_key_id: 'caim-release-key-01', key_status: 'ACTIVE' },
            event_catalog: { status: 'HEALTHY', registered_events_count: this.eventCatalog.listAll().length },
            queue_registry: { status: 'HEALTHY', registered_queues_count: this.queueRegistry.listAll().length },
          },
          timestamp: new Date().toISOString(),
        },
      };
    }, req);
  }

  public async getOpenApiSpec(req: ApiRequestContext): Promise<ApiResponse> {
    return this.handleRequest(async () => {
      return {
        data: this.openApi.generateDocument(),
      };
    }, req);
  }

  // =========================================================================
  // 5. Queues & DLQ Family
  // =========================================================================

  public async listQueues(req: ApiRequestContext): Promise<ApiResponse> {
    return this.handleRequest(async () => {
      const allQueues = this.queueRegistry.listAll();
      return {
        data: allQueues.map((q) => ({
          queue_key: q.queueKey,
          domain: q.domain,
          owning_service: q.owningService,
          description: q.description,
          concurrency_limit: q.concurrencyLimit,
          max_lease_duration_ms: q.maxLeaseDurationMs,
          dead_letter_queue_key: q.deadLetterQueueKey,
        })),
      };
    }, req, {
      requiresAuth: true,
      allowedRoles: ['operator', 'admin', 'analyst'],
    });
  }

  public async replayDlqJob(req: ApiRequestContext): Promise<ApiResponse> {
    return this.handleRequest(async (ctx) => {
      const dlqId = ctx.params.dlqId;
      return {
        data: {
          replayed: true,
          dead_letter_job_id: dlqId,
          target_queue: 'queue:analysis:syntax',
          replayed_at: new Date().toISOString(),
          initiated_by: ctx.principal.principal_id,
        },
      };
    }, req, {
      requiresAuth: true,
      allowedRoles: ['operator', 'admin'],
      supportsIdempotency: true,
    });
  }

  // =========================================================================
  // Seeds & Route Documentation
  // =========================================================================

  private seedDefaultEntities(): void {
    this.agentsStore.set('agent-financial-analyst', {
      agent_id: 'agent-financial-analyst',
      canonical_name: 'Financial Portfolio Analyst Agent',
      description: 'Deterministic portfolio risk & compliance analysis',
      framework: 'TypeScript',
      author: 'CAIM Enterprise Security',
      created_at: '2026-08-26T12:00:00Z',
      updated_at: '2026-08-26T12:00:00Z',
    });

    this.agentVersionsStore.set('av-fin-v100', {
      agent_version_id: 'av-fin-v100',
      agent_id: 'agent-financial-analyst',
      version_label: 'v1.0.0',
      source_locator: 'memory://source/fin-analyst',
      content_hash: 'sha256:3c59a2f7c001a1b5b24b899478f7a8b85590c749320e8b15ca88bfa674b88bf2',
      security_classification: 'INTERNAL',
      created_at: '2026-08-26T12:00:00Z',
    });
  }

  private registerOpenApiDocs(): void {
    this.openApi.registerRoute({
      path: '/agents',
      method: 'get',
      summary: 'List Canonical Agents',
      description: 'Returns a paginated list of canonical registered agents with optional field filtering and sorting.',
      tags: ['Agent Registry'],
      requestQuery: PaginationQuerySchema,
    });

    this.openApi.registerRoute({
      path: '/agents',
      method: 'post',
      summary: 'Create Canonical Agent',
      description: 'Registers a new canonical agent. Supports exact idempotency execution via Idempotency-Key.',
      tags: ['Agent Registry'],
      requiresAuth: true,
      requiredRoles: ['analyst', 'admin', 'operator'],
      supportsIdempotency: true,
    });

    this.openApi.registerRoute({
      path: '/agents/{agentId}',
      method: 'get',
      summary: 'Get Canonical Agent',
      description: 'Retrieves canonical agent definition and metadata by agentId.',
      tags: ['Agent Registry'],
    });

    this.openApi.registerRoute({
      path: '/agents/{agentId}/versions',
      method: 'post',
      summary: 'Register Agent Version',
      description: 'Registers a new version for an existing canonical agent.',
      tags: ['Agent Registry'],
      requiresAuth: true,
      requiredRoles: ['analyst', 'admin', 'operator'],
      supportsIdempotency: true,
    });

    this.openApi.registerRoute({
      path: '/analysis/runs',
      method: 'post',
      summary: 'Trigger Analysis Run',
      description: 'Dispatches multi-phase intelligence analysis pipeline across syntax, taint, and decision scoring.',
      tags: ['Analysis & Intelligence'],
      requiresAuth: true,
      requiredRoles: ['analyst', 'admin', 'operator'],
      supportsIdempotency: true,
    });

    this.openApi.registerRoute({
      path: '/policy/evaluations',
      method: 'post',
      summary: 'Evaluate Policy Gate',
      description: 'Evaluates policy rulesets and checks if an agent version is cleared for packaging and shipment.',
      tags: ['Lifecycle & Policy'],
      requiresAuth: true,
      requiredRoles: ['analyst', 'release_approver', 'admin'],
    });

    this.openApi.registerRoute({
      path: '/approvals',
      method: 'post',
      summary: 'Submit Two-Person Approval',
      description: 'Records an audited security approval or sign-off on an agent version.',
      tags: ['Lifecycle & Policy'],
      requiresAuth: true,
      requiredRoles: ['release_approver', 'auditor', 'admin'],
      supportsIdempotency: true,
    });

    this.openApi.registerRoute({
      path: '/health',
      method: 'get',
      summary: 'System Liveness Health Check',
      description: 'Returns liveness status, process uptime, and memory consumption.',
      tags: ['System'],
    });

    this.openApi.registerRoute({
      path: '/ready',
      method: 'get',
      summary: 'System Readiness Check',
      description: 'Returns detailed readiness for database pool, workflow queues, and KMS signing enclaves.',
      tags: ['System'],
    });

    this.openApi.registerRoute({
      path: '/openapi.json',
      method: 'get',
      summary: 'OpenAPI 3.1 Specification',
      description: 'Returns OpenAPI 3.1.0 JSON document generated dynamically from validated contracts.',
      tags: ['System'],
    });
  }
}
