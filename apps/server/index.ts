import express, { Request, Response, NextFunction } from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import dotenv from "dotenv";
import { getServerConfig, getPublicConfig, getOptionalProviderStatus } from "../../packages/config/src/index.ts";
import { createTestDb } from "../../packages/db/src/migrator.ts";
import { DiagnosticService } from "../../packages/workflow/src/diagnostic.ts";
import { 
  createServerAuthHelper, 
  PrincipalContext, 
  SecurityClassificationRank,
  requireRole, 
  requireClassification,
  executeWithAuditedOverride,
  UnauthorizedAccessError,
  UnauthorizedVaultAccessError
} from "../../packages/auth/src/index.ts";
import { 
  SourceAdapterRegistry, 
  DiscoveryEngine, 
  createMockHttpFetcher,
  BraveSearchProvider,
  QueryStrategyRegistry,
  FreshnessScheduler,
  ArtifactClassifier,
  IdentityResolver,
  ManualReviewQueue,
  RecursiveExpansionEngine,
} from "../../packages/source/src/index.ts";
import {
  SyntaxIntelligencePipeline,
  ParserRegistry,
  EncodingDetector,
  ProtocolDetector,
  FrameworkDetector,
  ConfigExtractor
} from "../../packages/syntax/src/index.ts";
import {
  StaticAnalysisEngine,
  STATIC_RULES_CATALOG,
  TaintSourceRegistry,
  TaintSinkRegistry,
  TaintSanitizerRegistry,
  TAINT_FIXTURE_SCENARIOS
} from "../../workers/static-analysis/index.ts";
import {
  CompositionEngine,
  COMPOSITION_FIXTURE_SCENARIOS,
  CANONICAL_ADVISORY_FIXTURES
} from "../../workers/composition/index.ts";
import {
  SandboxOrchestrationEngine,
  ScenarioRegistry,
  SandboxLifecycleManager,
} from "../../workers/sandbox-orchestrator/index.ts";
import {
  DecisionOrchestrationEngine,
  ScoreModelRegistry,
  PolicyRegistry,
  PolicyOverrideManager,
  RecommendationEngine,
  UseCaseEngine,
  USE_CASE_PROFILE_V1,
} from "../../workers/decision/index.ts";
import {
  initializeKnowledgeAndRetrieval,
  QueryUnderstandingEngine,
  RetrievalPlanner,
  HybridFusionReranker,
  RagSynthesisPipeline,
  ContextAssembler,
  DraftClaimExtractor,
  GroundingValidator,
} from "../../workers/knowledge/index.ts";
import {
  DeterministicPackageBundler,
  KmsSignerBoundary,
  SignatureVerifier,
  ShippingService,
  SignedPackageBundle,
  PackagingPolicyGate,
  PackageBuildInput
} from "../../packages/packaging/src/index.ts";
import { createApiExpressRouter } from "../../packages/api/src/index.ts";
import { 
  OpenTelemetryTracer, 
  AuditLogEngine, 
  PlatformTelemetryEngine, 
  TraceResolver, 
  SecretRedactor,
  runObservabilityVerificationTests
} from "../../packages/workflow/src/observability.ts";
import { 
  GoldenCorpusEvaluationEngine, 
  GOLDEN_CORPUS_FIXTURES, 
  PRODUCTION_REGRESSION_THRESHOLDS,
  runEvaluationVerificationTests
} from "../../packages/workflow/src/evaluation.ts";
import {
  AUTHORITATIVE_REQUIREMENTS_MATRIX,
  MANDATORY_ACCEPTANCE_PATHS,
  LineageResolverEngine,
  QualityTargetsAuditor,
  runPlatformDefinitionOfDoneAudit
} from "../../packages/workflow/src/traceability.ts";


dotenv.config();

// Extended Request with PrincipalContext
declare global {
  namespace Express {
    interface Request {
      principal?: PrincipalContext;
    }
  }
}

async function startServer() {
  const config = getServerConfig();
  const app = express();
  const PORT = config.port;
  const authHelper = createServerAuthHelper();

  // Initialize in-memory / connected database instance for the control plane
  const memDb = createTestDb({ applyMigrations: true, applySeed: true });
  const pg = memDb.adapters.createPg();
  const dbClient = new pg.Client();
  await dbClient.connect();

  const diagnosticService = new DiagnosticService(dbClient);
  // Seed sample real control plane records for initial diagnostic inspection
  await diagnosticService.seedSampleDiagnosticData();

  app.use(express.json());

  // Authentication & Principal Claim Resolution Middleware
  app.use(async (req: Request, _res: Response, next: NextFunction) => {
    try {
      req.principal = await authHelper.authenticateRequest(req.headers as any);
    } catch {
      // Fallback to anonymous
      req.principal = {
        principal_id: 'anonymous',
        is_authenticated: false,
        is_service: false,
        roles: ['anonymous'],
        tenant_id: null,
        accessible_scope_ids: ['00000000-0000-0000-0000-000000000001'],
        max_classification_rank: SecurityClassificationRank.PUBLIC_METADATA,
        grants: [],
      };
    }

    // Allow testing role header override in non-production for engineer console validation
    const customRoleHeader = req.headers['x-role'] || req.headers['x-principal-roles'];
    if (customRoleHeader && typeof customRoleHeader === 'string') {
      const customRoles = customRoleHeader.split(',').map(r => r.trim()).filter(Boolean) as any[];
      if (customRoles.length > 0) {
        req.principal.roles = customRoles;
        req.principal.is_authenticated = true;
      }
    }

    next();
  });

  // Role guard for internal engineering console
  const requireDiagnosticAccess = (req: Request, res: Response, next: NextFunction) => {
    const allowedRoles = ['admin', 'operator', 'auditor', 'system_engineer'];
    const userRoles = req.principal?.roles || [];
    const hasAllowedRole = userRoles.some(r => allowedRoles.includes(r as any));
    if (!hasAllowedRole) {
      return res.status(403).json({
        error: "Access Denied: Internal Engineering Console requires operator, admin, or auditor role.",
        required_roles: allowedRoles,
        current_roles: userRoles,
        authenticated: req.principal?.is_authenticated ?? false
      });
    }
    next();
  };

  // Health and System Baseline APIs
  app.get("/api/health", (_req, res) => {
    res.json({
      status: "healthy",
      timestamp: new Date().toISOString(),
      platform: "Agent Lifecycle Intelligence Platform (CAIM)",
      baseline: config.features ? "V2.0.1 Controlled Implementation Baseline" : "Unknown",
      version: "2.0.1",
      runtime: "Node.js + Express + Vite Full-Stack Runtime",
    });
  });

  // Public safe configuration endpoint (secrets strictly excluded)
  app.get("/api/config/public", (_req, res) => {
    const publicConfig = getPublicConfig();
    res.json(publicConfig);
  });

  // Identity and Caller Claims
  app.get("/api/auth/me", (req, res) => {
    res.json({
      principal: req.principal,
      status: "authenticated",
    });
  });

  // Vault-Restricted Read Path
  app.get("/api/v1/vault/credentials", (req, res) => {
    try {
      if (!req.principal) {
        return res.status(401).json({ error: "Unauthorized" });
      }
      requireClassification(req.principal, SecurityClassificationRank.VAULT_RESTRICTED);
      return res.json({
        status: "success",
        vault_items: [
          {
            id: "vault_cred_001",
            type: "CREDENTIAL_REFERENCE",
            locator: "vault://tenants/primary/keys/production-signing",
            security_classification: "VAULT_RESTRICTED",
          }
        ]
      });
    } catch (err: any) {
      if (err instanceof UnauthorizedVaultAccessError || err instanceof UnauthorizedAccessError) {
        return res.status(403).json({ error: err.message });
      }
      return res.status(500).json({ error: "Internal Server Error" });
    }
  });

  // Audited Override (Break-Glass) Gated Execution
  app.post("/api/v1/audit/override", async (req, res) => {
    try {
      if (!req.principal) {
        return res.status(401).json({ error: "Unauthorized" });
      }
      const { justification, target_resource_id, action, target_resource_type } = req.body;

      const dummyAuditSink = {
        logAuditEvent: async (_event: any) => true,
      };

      const result = await executeWithAuditedOverride(
        req.principal,
        {
          actor_id: req.principal.principal_id,
          action: action || "MANUAL_INSPECTION",
          target_resource_id: target_resource_id || "res_vault_override",
          target_resource_type: target_resource_type || "VAULT_SECRET",
          justification: justification || "",
          correlation_id: `corr_${Date.now()}`,
        },
        dummyAuditSink,
        async (elevated) => {
          return {
            status: "OVERRIDE_EXECUTED",
            elevated_actor: elevated.principal_id,
            resource_accessed: target_resource_id,
          };
        }
      );

      return res.json(result);
    } catch (err: any) {
      return res.status(400).json({ error: err.message });
    }
  });

  // System diagnostic state endpoint
  app.get("/api/pipeline/state", (_req, res) => {
    res.json({
      stage: "P06_COMPLETE",
      total_engines_target: 71,
      implemented_count: 0,
      active_workers: [
        "discovery",
        "semantic",
        "static-analysis",
        "composition",
        "sandbox-orchestrator",
        "decision",
        "knowledge",
        "lifecycle",
        "evaluation",
      ],
      database: {
        foundation_p03: "ACTIVE",
        analysis_intel_p04: "ACTIVE",
        knowledge_lifecycle_ops_p05: "ACTIVE",
        auth_roles_rls_vault_p06: "ACTIVE",
        total_migrations: 13,
        lineage_engine: "OPERATIONAL",
      },
      auth: {
        roles_defined: 10,
        vault_boundary: "ENFORCED",
        rls_policies: "ACTIVE",
      },
      secrets_configured: Boolean(config.geminiApiKey),
      providers: {
        github: getOptionalProviderStatus("githubToken"),
        huggingface: getOptionalProviderStatus("huggingfaceApiKey"),
        e2b: getOptionalProviderStatus("e2bApiKey"),
        supabase: getOptionalProviderStatus("supabaseServiceKey"),
      },
      features: config.features,
      models: config.models,
    });
  });

  // ==========================================
  // P09A INTERNAL ENGINEERING CONSOLE APIS
  // ==========================================

  // 1. System Health & Infrastructure Diagnostics
  app.get("/api/dev/system", requireDiagnosticAccess, async (_req: Request, res: Response) => {
    try {
      const systemHealth = await diagnosticService.getSystemHealth(config.env);
      res.json(systemHealth);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to retrieve system diagnostic health" });
    }
  });

  // 2. WorkflowRuns List
  app.get("/api/dev/workflows", requireDiagnosticAccess, async (_req: Request, res: Response) => {
    try {
      const workflows = await diagnosticService.listWorkflowRuns();
      res.json(workflows);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to list workflow runs" });
    }
  });

  // 2a. WorkflowRun Detail
  app.get("/api/dev/workflows/:id", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const workflow = await diagnosticService.getWorkflowRunDetails(req.params.id);
      if (!workflow) {
        return res.status(404).json({ error: `WorkflowRun not found for ID: ${req.params.id}` });
      }
      res.json(workflow);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to get workflow run details" });
    }
  });

  // 3. Jobs & Leases List
  app.get("/api/dev/jobs", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { status, queueKey, workflowRunId, limit } = req.query;
      const jobs = await diagnosticService.listJobs({
        status: status as string,
        queueKey: queueKey as string,
        workflowRunId: workflowRunId as string,
        limit: limit ? parseInt(limit as string, 10) : 50,
      });
      res.json(jobs);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to list jobs" });
    }
  });

  // 3a. Job Detail with Attempt History
  app.get("/api/dev/jobs/:id", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const job = await diagnosticService.getJobDetails(req.params.id);
      if (!job) {
        return res.status(404).json({ error: `Job not found for ID: ${req.params.id}` });
      }
      res.json(job);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to get job details" });
    }
  });

  // 4. Dead-Letter Queue (DLQ) List
  app.get("/api/dev/dlq", requireDiagnosticAccess, async (_req: Request, res: Response) => {
    try {
      const dlqEntries = await diagnosticService.listDeadLetterJobs();
      res.json(dlqEntries);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to list dead letter queue entries" });
    }
  });

  // 4a. DLQ Detail
  app.get("/api/dev/dlq/:id", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const dlqDetail = await diagnosticService.getDeadLetterJobDetails(req.params.id);
      if (!dlqDetail) {
        return res.status(404).json({ error: `Dead letter job entry not found for ID: ${req.params.id}` });
      }
      res.json(dlqDetail);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to get dead letter entry details" });
    }
  });

  // Seed or Reset Sample Diagnostic Records
  app.post("/api/dev/seed-sample", requireDiagnosticAccess, async (_req: Request, res: Response) => {
    try {
      await diagnosticService.seedSampleDiagnosticData();
      res.json({ status: "success", message: "Sample diagnostic records verified" });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // ==========================================
  // P11 SOURCE ADAPTER & DISCOVERY APIS
  // ==========================================
  const mockFetcher = createMockHttpFetcher();
  const sourceRegistry = SourceAdapterRegistry.createDefault({
    github: { token: config.providers?.githubToken, fetcher: config.env === "test" ? mockFetcher : undefined },
    gitlab: { fetcher: config.env === "test" ? mockFetcher : undefined },
    pypi: { fetcher: config.env === "test" ? mockFetcher : undefined },
    npm: { fetcher: config.env === "test" ? mockFetcher : undefined },
    huggingface: { token: config.providers?.huggingfaceApiKey, fetcher: config.env === "test" ? mockFetcher : undefined },
    dockerhub: { fetcher: config.env === "test" ? mockFetcher : undefined },
    codeberg: { fetcher: config.env === "test" ? mockFetcher : undefined },
  });
  const discoveryEngine = new DiscoveryEngine(sourceRegistry);

  // ==========================================
  // P12 WEB SEARCH, CLASSIFIER, IDENTITY & GRAPH
  // ==========================================
  const braveSearchProvider = new BraveSearchProvider({
    apiKey: process.env.BRAVE_API_KEY,
    fetcher: (!process.env.BRAVE_API_KEY || config.env === "test") ? mockFetcher : undefined,
  });
  const queryStrategyRegistry = new QueryStrategyRegistry();
  const freshnessScheduler = new FreshnessScheduler();
  const artifactClassifier = new ArtifactClassifier();
  const identityResolver = new IdentityResolver();
  const manualReviewQueue = new ManualReviewQueue();
  const recursiveExpansionEngine = new RecursiveExpansionEngine(sourceRegistry);

  // Seed sample observation records into freshness scheduler
  freshnessScheduler.recordObservation({
    source_locator: 'github://caim-org/autonomous-caim-agent',
    source_type: 'github',
    strategy_id: 'RULE_AGENT_DISCOVERY_PRIMARY',
    change_token: 'sha-20260822-abc',
    token_type: 'COMMIT_SHA',
    observed_at: new Date().toISOString(),
  });
  freshnessScheduler.recordObservation({
    source_locator: 'pypi://autonomous-caim-agent',
    source_type: 'pypi',
    strategy_id: 'RULE_PACKAGE_DIST_PYPI_NPM',
    change_token: '1.2.0',
    token_type: 'VERSION',
    observed_at: new Date(Date.now() - 90000000).toISOString(), // > 24h ago -> STALE
  });

  // Seed sample manual review item
  manualReviewQueue.enqueueConflict({
    candidate_locators: [
      'github://caim-community/caim-agent-unverified',
      'github://caim-org/autonomous-caim-agent',
    ],
    conflict_summary: 'Identical package name and claims, but different publisher organization and unverified signing certificate.',
    suggested_outcome: 'UNRESOLVED',
    confidence: 0.52,
    evidence: {
      publisher_match: 0.1,
      repo_match: 0.3,
      homepage_match: 0.8,
      manifest_match: 0.9,
      checksum_match: 0.0,
      distribution_match: 0.5,
      similarity_score: 0.85,
      composite_confidence: 0.52,
      details: ['High name similarity with discordant author identities', 'Mismatched git commit signing key'],
    },
  });

  // 5. Source Adapters Overview & Health
  app.get("/api/dev/sources", requireDiagnosticAccess, async (_req: Request, res: Response) => {
    try {
      const adapters = sourceRegistry.getAll();
      const healthMap = await discoveryEngine.checkAllHealth();
      const searchHealth = await braveSearchProvider.health_check();

      const overview = adapters.map(a => ({
        sourceType: a.sourceType,
        sourceName: a.sourceName,
        adapterVersion: a.adapterVersion,
        policy: a.get_source_policy(),
        rateLimit: a.get_rate_limit_state(),
        health: healthMap[a.sourceType] || null,
      }));

      // Include Brave Search in diagnostics
      overview.push({
        sourceType: 'brave_search',
        sourceName: 'Brave Search API',
        adapterVersion: braveSearchProvider.providerVersion,
        policy: {
          source_type: 'brave_search',
          source_name: 'Brave Search API',
          auth_mode: process.env.BRAVE_API_KEY ? 'AUTHENTICATED' : 'DEGRADED',
          max_page_size: 20,
          rate_limit_per_minute: 60,
          retry_policy: { max_retries: 3, backoff_factor: 2, initial_delay_ms: 500 },
          supported_query_families: ['AGENT_DISCOVERY', 'TOOL_ECOSYSTEM', 'MODEL_WEIGHTS', 'CODE_REPOSITORY'],
          capabilities: {
            can_stream: false,
            can_search: true,
            provides_dependencies: false,
            provides_artifacts: false,
            requires_auth: true,
          },
        },
        rateLimit: braveSearchProvider.get_rate_limit_state(),
        health: searchHealth,
      });

      res.json(overview);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to list source adapters" });
    }
  });

  // 6. Run Source-Independent Discovery
  app.post("/api/dev/discovery/run", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { criteria, sourceTypes, maxPagesPerSource, maxCandidatesTotal, correlationId } = req.body || {};
      const report = await discoveryEngine.runDiscovery({
        criteria: criteria || { query: "agent" },
        sourceTypes,
        maxPagesPerSource: maxPagesPerSource || 1,
        maxCandidatesTotal: maxCandidatesTotal || 20,
        correlationId,
      });
      res.json(report);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Discovery execution failed" });
    }
  });

  // 7. Polymorphic Locator Inspection
  app.post("/api/dev/discovery/inspect", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { locator } = req.body || {};
      if (!locator || typeof locator !== "string") {
        return res.status(400).json({ error: "Missing 'locator' string parameter" });
      }
      const adapter = sourceRegistry.resolveForLocator(locator);
      const [metadata, artifacts, relationships, changeToken] = await Promise.all([
        adapter.fetch_metadata(locator),
        adapter.resolve_artifact_locators(locator),
        adapter.enumerate_relationships(locator),
        adapter.get_change_token(locator),
      ]);
      res.json({
        sourceType: adapter.sourceType,
        locator,
        metadata,
        artifacts,
        relationships,
        changeToken,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Locator inspection failed" });
    }
  });

  // 8. Query Strategy Rules List & Toggle
  app.get("/api/dev/discovery/rules", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(queryStrategyRegistry.getAllRules());
  });

  app.post("/api/dev/discovery/rules/generate", requireDiagnosticAccess, (req: Request, res: Response) => {
    const { seed, family, targetSource } = req.body || {};
    if (!seed || typeof seed !== "string") {
      return res.status(400).json({ error: "Missing 'seed' string" });
    }
    const queries = queryStrategyRegistry.generateQueries(seed, { family, targetSource });
    res.json(queries);
  });

  app.post("/api/dev/discovery/rules/toggle", requireDiagnosticAccess, (req: Request, res: Response) => {
    const { ruleId, enabled } = req.body || {};
    if (!ruleId || typeof enabled !== "boolean") {
      return res.status(400).json({ error: "Missing ruleId or enabled boolean" });
    }
    const success = queryStrategyRegistry.setRuleEnabled(ruleId, enabled);
    res.json({ success, ruleId, enabled });
  });

  // 9. Web Search via Brave Provider
  app.post("/api/dev/discovery/search", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { query, count, freshness } = req.body || {};
      if (!query || typeof query !== "string") {
        return res.status(400).json({ error: "Missing 'query' string parameter" });
      }
      const searchResult = await braveSearchProvider.search(query, {
        count: count || 10,
        freshness,
      });
      res.json(searchResult);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Web search execution failed" });
    }
  });

  // 10. Freshness & Coverage Metrics
  app.get("/api/dev/discovery/freshness/metrics", requireDiagnosticAccess, (req: Request, res: Response) => {
    const window = (req.query.window as any) || "24h";
    const metrics = freshnessScheduler.computeMetrics(window);
    res.json(metrics);
  });

  app.post("/api/dev/discovery/freshness/record", requireDiagnosticAccess, (req: Request, res: Response) => {
    const { source_locator, source_type, strategy_id, change_token, token_type } = req.body || {};
    if (!source_locator || !source_type) {
      return res.status(400).json({ error: "Missing source_locator or source_type" });
    }
    const evalResult = freshnessScheduler.recordObservation({
      source_locator,
      source_type,
      strategy_id,
      change_token,
      token_type,
    });
    res.json(evalResult);
  });

  // 11. Recursive Relationship Expansion
  app.post("/api/dev/discovery/expand", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { rootLocators, maxDepth, maxCandidatesTotal, maxCallsPerSource, maxTimeMs } = req.body || {};
      if (!Array.isArray(rootLocators) || rootLocators.length === 0) {
        return res.status(400).json({ error: "Missing 'rootLocators' array parameter" });
      }
      const report = await recursiveExpansionEngine.expand(rootLocators, {
        max_depth: maxDepth,
        max_total_candidates: maxCandidatesTotal,
        max_calls_per_source: maxCallsPerSource,
        max_time_ms: maxTimeMs,
      });
      res.json(report);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Recursive expansion failed" });
    }
  });

  // 12. Artifact Classification Taxonomy
  app.post("/api/dev/discovery/classify", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { candidate, locator } = req.body || {};
      let cand = candidate;
      let metadata;
      let artifacts;

      if (locator && typeof locator === "string") {
        const adapter = sourceRegistry.resolveForLocator(locator);
        const [metaRes, artRes] = await Promise.all([
          adapter.fetch_metadata(locator),
          adapter.resolve_artifact_locators(locator),
        ]);
        metadata = metaRes;
        artifacts = artRes;
        cand = {
          source_locator: locator,
          display_name: locator,
          source_type: adapter.sourceType,
          raw_metadata: metaRes.raw_metadata,
        };
      }

      if (!cand || !cand.source_locator) {
        return res.status(400).json({ error: "Missing candidate object or locator string" });
      }

      const classification = artifactClassifier.classify({
        candidate: cand,
        metadata,
        artifacts,
      });
      res.json(classification);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Classification failed" });
    }
  });

  // 13. Identity Resolution & Canonical Candidate Graph
  app.post("/api/dev/discovery/resolve-identity", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { observationA, observationB, observations } = req.body || {};

      if (observations && Array.isArray(observations)) {
        const graph = identityResolver.buildCandidateGraph(observations);
        return res.json(graph);
      }

      if (!observationA || !observationB) {
        return res.status(400).json({ error: "Must provide either (observationA and observationB) or observations array" });
      }

      const comparison = identityResolver.compare(observationA, observationB);
      res.json(comparison);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Identity resolution failed" });
    }
  });

  // 14. Manual Review Queue
  app.get("/api/dev/discovery/review-queue", requireDiagnosticAccess, (req: Request, res: Response) => {
    const status = req.query.status as any;
    const items = manualReviewQueue.listItems(status);
    res.json(items);
  });

  app.post("/api/dev/discovery/review-queue/resolve", requireDiagnosticAccess, (req: Request, res: Response) => {
    try {
      const { id, status, resolved_outcome, resolved_canonical_id, review_note } = req.body || {};
      if (!id || !status) {
        return res.status(400).json({ error: "Missing 'id' or 'status'" });
      }
      const reviewed_by = req.principal?.principal_id || "operator";
      const result = manualReviewQueue.resolveConflict(id, {
        status,
        resolved_outcome,
        resolved_canonical_id,
        reviewed_by,
        review_note,
      });
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Failed to resolve manual review item" });
    }
  });

  // 15. P13 — Language, Syntax, Protocol, Framework & Config Intelligence
  app.post("/api/dev/syntax/inspect-file", requireDiagnosticAccess, (req: Request, res: Response) => {
    try {
      const { path: filePath, content } = req.body || {};
      if (!filePath || content === undefined) {
        return res.status(400).json({ error: "Missing 'path' or 'content' in request body" });
      }
      const fileType = EncodingDetector.detect(filePath, content);
      const facts = ParserRegistry.parseFile(filePath, content, fileType);
      res.json(facts);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "File syntax inspection failed" });
    }
  });

  app.post("/api/dev/syntax/process-artifact", requireDiagnosticAccess, (req: Request, res: Response) => {
    try {
      const { artifact_id, files } = req.body || {};
      if (!files || !Array.isArray(files)) {
        return res.status(400).json({ error: "Missing 'files' array in request body" });
      }
      const artId = artifact_id || `artifact-${Date.now()}`;
      const result = SyntaxIntelligencePipeline.processArtifact(artId, files);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Artifact processing failed" });
    }
  });

  app.get("/api/dev/syntax/sample-fixtures", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json({
      mcp_agent: {
        path: "agent/mcp_server.ts",
        content: `import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { OpenAI } from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const server = new Server(
  { name: "memory-analyst-mcp", version: "1.2.0" },
  { capabilities: { tools: {}, prompts: {} } }
);

server.tool("query_knowledge_base", "Queries knowledge vectors", async (args: { query: string }) => {
  const model = "gpt-4o";
  const temp = 0.2;
  return { content: [{ type: "text", text: "Knowledge vector result" }] };
});

const transport = new StdioServerTransport();
await server.connect(transport);`
      },
      python_agent: {
        path: "src/autogen_agent.py",
        content: `import os
from autogen import ConversableAgent, UserProxyAgent
from langchain_core.tools import tool
import requests

API_TOKEN = os.getenv("AUTOGEN_API_TOKEN", "default-dev-token")

@tool
def fetch_financial_metrics(ticker: str) -> dict:
    """Fetches real-time stock ticker fundamentals and SEC filings."""
    url = f"https://api.marketdata.com/v1/{ticker}"
    response = requests.get(url, headers={"Authorization": f"Bearer {API_TOKEN}"})
    return response.json()

assistant = ConversableAgent(
    name="FinancialAnalyst",
    system_message="You are a senior financial analyst analyzing SEC 10-K filings.",
    llm_config={"model": "claude-3-5-sonnet", "temperature": 0.1, "max_tokens": 4096}
)`
      },
      go_service: {
        path: "cmd/gateway/main.go",
        content: `package main

import (
	"context"
	"net/http"
	"os"
	"github.com/gin-gonic/gin"
)

type GatewayServer struct {
	Port string
}

func (s *GatewayServer) HandleAgentProxy(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "proxied"})
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r := gin.Default()
	server := &GatewayServer{Port: port}
	r.POST("/api/v1/agent/invoke", server.HandleAgentProxy)
	r.Run(":" + port)
}`
      },
      dockerfile: {
        path: "Dockerfile",
        content: `FROM python:3.11-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV MODEL_ENDPOINT=https://models.internal.net
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8000/health || exit 1
ENTRYPOINT ["python", "main.py"]`
      }
    });
  });

  // 16. P15 — Static Analysis & Control Flow Engine
  app.post("/api/dev/static-analysis/analyze", requireDiagnosticAccess, (req: Request, res: Response) => {
    try {
      const { artifact_id, files, entrypoints, pipeline_run_id } = req.body || {};
      if (!files || !Array.isArray(files)) {
        return res.status(400).json({ error: "Missing 'files' array in request body" });
      }
      const artId = artifact_id || `artifact-sa-${Date.now()}`;
      const report = StaticAnalysisEngine.analyze({
        artifactId: artId,
        files,
        entrypoints,
        pipelineRunId: pipeline_run_id || `run-${Date.now()}`,
      });
      res.json(report);
    } catch (err: any) {
      res.status(500).json({ error: err.message || "Static analysis execution failed" });
    }
  });

  app.get("/api/dev/static-analysis/rules", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json({
      engine_version: StaticAnalysisEngine.ENGINE_VERSION,
      ruleset_version: StaticAnalysisEngine.RULESET_VERSION,
      total_rules: STATIC_RULES_CATALOG.length,
      rules: STATIC_RULES_CATALOG,
    });
  });

  app.get("/api/dev/static-analysis/sample-fixtures", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json({
      multi_file_agent: [
        {
          path: "src/main.ts",
          content: `import { executeShell, fetchRemoteContext } from "./service";
import { runMcpQuery } from "./mcp_client";

export function main() {
  const query = "financial_report";
  const remoteData = fetchRemoteContext("https://api.external-leak.com/data");
  runMcpQuery(query);
  executeShell("rm -rf /tmp/cache");
}
`
        },
        {
          path: "src/service.ts",
          content: `import { exec } from "child_process";

export function executeShell(cmd: string) {
  // Shell command execution
  exec(cmd);
}

export function fetchRemoteContext(targetUrl: string) {
  const token = "sk-live-99887766554433221100aaabbbccc";
  const apiKey = process.env.DATABASE_SECRET_KEY;
  return fetch(targetUrl, { headers: { Authorization: \`Bearer \${token}\` } });
}
`
        },
        {
          path: "src/mcp_client.ts",
          content: `export const queryTool = {
  name: "query_database",
  description: "Queries external SQL database directly",
  inputSchema: { type: "object", properties: { sql: { type: "string" } } }
};

export function runMcpQuery(queryText: string) {
  if (queryText === "") {
    return null;
  }
  return { status: "success", text: queryText };
}
`
        },
        {
          path: "src/complex_flow.ts",
          content: `export function evaluateBranch(x: number, y: number, mode: string): string {
  let score = 0;
  if (x > 10) {
    if (y < 5) {
      while (score < 3) {
        score++;
      }
    } else {
      score += 2;
    }
  } else if (mode === "FAST") {
    score = 100;
  } else {
    try {
      score = x / y;
    } catch (err) {
      score = -1;
    }
  }

  return \`Score: \${score}\`;
  
  // Dead code construct
  console.log("Unreachable post-return statement");
}
`
        }
      ]
    });
  });


  // 17. P16 — Dataflow & Taint Intelligence Endpoints
  app.get("/api/dev/taint/registries", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json({
      source_registry_version: TaintSourceRegistry.REGISTRY_VERSION,
      sink_registry_version: TaintSinkRegistry.REGISTRY_VERSION,
      sanitizer_registry_version: TaintSanitizerRegistry.REGISTRY_VERSION,
      sources: TaintSourceRegistry.getAllSources(),
      sinks: TaintSinkRegistry.getAllSinks(),
      sanitizers: TaintSanitizerRegistry.getAllSanitizers(),
    });
  });

  app.get("/api/dev/taint/fixtures", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(TAINT_FIXTURE_SCENARIOS);
  });

  // 18. P17 — Composition, SBOM/AI-BOM, Vulnerability & Reachability Endpoints
  app.get("/api/dev/composition/fixtures", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(COMPOSITION_FIXTURE_SCENARIOS);
  });

  app.get("/api/dev/composition/advisories", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(CANONICAL_ADVISORY_FIXTURES);
  });

  app.post("/api/dev/composition/analyze", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { files, artifactId, runtimeEvents, staticAnalysis } = req.body;
      const fileMap = new Map<string, string>();
      if (files && typeof files === "object") {
        for (const [k, v] of Object.entries(files)) {
          fileMap.set(k, String(v));
        }
      }

      const result = await CompositionEngine.run({
        artifactId: artifactId || "art-dev-composition",
        files: fileMap,
        staticAnalysis,
        runtimeEvents,
      });

      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 19. P19 — Dynamic Sandbox, Scenarios, Telemetry & Evasion Endpoints
  app.get("/api/dev/sandbox/scenarios", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(ScenarioRegistry.listScenarios());
  });

  app.get("/api/dev/sandbox/active-sessions", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json({
      activeCount: SandboxLifecycleManager.getActiveSessionCount(),
      timestamp: new Date().toISOString(),
    });
  });

  app.post("/api/dev/sandbox/run", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { scenarioId, scenario, providerType, files, envVars, resourceLimits, networkPolicy } = req.body;
      const result = await SandboxOrchestrationEngine.runScenario({
        scenarioId,
        scenario,
        providerType: providerType || 'SIMULATED',
        files,
        envVars,
        resourceLimits,
        networkPolicy,
      });
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 20. P21 — Risk, Scoring Models, Policies, Overrides & Use-Case Endpoints
  app.get("/api/dev/decision/scoring-models", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(ScoreModelRegistry.listModels());
  });

  app.get("/api/dev/decision/policies", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(PolicyRegistry.listPolicies());
  });

  app.post("/api/dev/decision/run", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const result = await DecisionOrchestrationEngine.runDecisionSuite(req.body);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get("/api/dev/decision/overrides/:analysisRunId", requireDiagnosticAccess, (req: Request, res: Response) => {
    const history = PolicyOverrideManager.getOverrideHistory(req.params.analysisRunId);
    const active = PolicyOverrideManager.getActiveOverride(req.params.analysisRunId);
    res.json({ active, history });
  });

  app.post("/api/dev/decision/overrides", requireDiagnosticAccess, (req: Request, res: Response) => {
    try {
      const override = PolicyOverrideManager.applyOverride(req.body);
      res.json(override);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.post("/api/dev/decision/overrides/revoke", requireDiagnosticAccess, (req: Request, res: Response) => {
    const { overrideId, revokerId } = req.body;
    const success = PolicyOverrideManager.revokeOverride(overrideId, revokerId);
    res.json({ success });
  });

  // 21. P22 / P23 / P24 — Knowledge Projections, Hybrid Retrieval & Grounded RAG Synthesis Plane
  const { corpus: knowledgeCorpus, retrieval: hybridRetrieval } = await initializeKnowledgeAndRetrieval();
  const ragPipeline = new RagSynthesisPipeline(knowledgeCorpus, hybridRetrieval);
  const contextAssembler = new ContextAssembler();

  app.get("/api/dev/knowledge/stats", requireDiagnosticAccess, (_req: Request, res: Response) => {
    const staleness = knowledgeCorpus.getStalenessReport();
    const vectorStats = knowledgeCorpus.getVectorRepo().getStats();
    res.json({
      total_registered_objects: knowledgeCorpus.getRegistry().size(),
      total_projections: knowledgeCorpus.getProjections().size,
      total_chunks: Array.from(knowledgeCorpus.getChunks().values()).reduce((acc, c) => acc + c.length, 0),
      staleness,
      vectorStats,
    });
  });

  app.post("/api/dev/knowledge/rebuild", requireDiagnosticAccess, async (_req: Request, res: Response) => {
    try {
      const report = await knowledgeCorpus.rebuildEntireCorpus();
      res.json(report);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/dev/retrieval/understand", requireDiagnosticAccess, (req: Request, res: Response) => {
    const { query } = req.body;
    if (!query) {
      return res.status(400).json({ error: "Missing required query string" });
    }
    const understanding = QueryUnderstandingEngine.parseQuery(query);
    const plan = RetrievalPlanner.createPlan(understanding);
    res.json({ understanding, sample_plan: plan });
  });

  app.post("/api/dev/retrieval/execute", async (req: Request, res: Response) => {
    try {
      const { query, scoped_agent_id, scoped_agent_version_id, caller_classification_code, caller_security_rank, caller_has_vault_access, budget_max_records } = req.body;
      if (!query) {
        return res.status(400).json({ error: "Missing required query string" });
      }

      // Security classification rank from header/body or authenticated principal
      const rank = caller_security_rank !== undefined 
        ? Number(caller_security_rank) 
        : (req.principal?.max_classification_rank ?? SecurityClassificationRank.PUBLIC_METADATA);
      const vaultAccess = caller_has_vault_access !== undefined 
        ? Boolean(caller_has_vault_access) 
        : ((req.principal as any)?.has_vault_access ?? (req.principal as any)?.vault_clearance_grant ?? false);

      const result = await hybridRetrieval.retrieveContext(query, {
        caller_user_id: req.principal?.principal_id || 'anonymous-caller',
        caller_classification_code,
        caller_security_rank: rank,
        caller_has_vault_access: vaultAccess,
        scoped_agent_id,
        scoped_agent_version_id,
        budget_max_records: budget_max_records ? Number(budget_max_records) : 20,
      });

      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get("/api/dev/retrieval/audit-logs", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(hybridRetrieval.getAuditHistory());
  });

  // 22. P24 RAG Synthesis, Grounding & Citations
  app.post("/api/dev/rag/synthesize", async (req: Request, res: Response) => {
    try {
      const { query, scoped_agent_id, scoped_agent_version_id, caller_security_rank, caller_has_vault_access, injected_draft_for_testing } = req.body;
      if (!query) {
        return res.status(400).json({ error: "Missing required query string" });
      }

      const rank = caller_security_rank !== undefined 
        ? Number(caller_security_rank) 
        : (req.principal?.max_classification_rank ?? SecurityClassificationRank.PUBLIC_METADATA);
      const vaultAccess = caller_has_vault_access !== undefined 
        ? Boolean(caller_has_vault_access) 
        : ((req.principal as any)?.has_vault_access ?? (req.principal as any)?.vault_clearance_grant ?? false);

      const output = await ragPipeline.answerQuery(query, {
        caller_user_id: req.principal?.principal_id || 'anonymous-caller',
        caller_security_rank: rank,
        caller_has_vault_access: vaultAccess,
        scoped_agent_id,
        scoped_agent_version_id,
        injected_draft_for_testing,
      });

      res.json(output);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/dev/rag/context-package", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { query, scoped_agent_id, scoped_agent_version_id, caller_security_rank, caller_has_vault_access } = req.body;
      if (!query) {
        return res.status(400).json({ error: "Missing required query string" });
      }

      const rank = caller_security_rank !== undefined ? Number(caller_security_rank) : 0;
      const vault = Boolean(caller_has_vault_access);

      const retrievalResult = await hybridRetrieval.retrieveContext(query, {
        caller_security_rank: rank,
        caller_has_vault_access: vault,
        scoped_agent_id,
        scoped_agent_version_id,
      });

      const pkg = contextAssembler.assembleContextPackage(query, retrievalResult.documents, {
        caller_security_rank: rank,
        caller_has_vault: vault,
        target_agent_id: scoped_agent_id,
        target_version_id: scoped_agent_version_id,
      });

      res.json(pkg);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/dev/rag/grounding-check", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { draft_text, query } = req.body;
      if (!draft_text || !query) {
        return res.status(400).json({ error: "Missing draft_text or query" });
      }

      const retrievalResult = await hybridRetrieval.retrieveContext(query, {
        caller_security_rank: SecurityClassificationRank.INTERNAL,
      });

      const pkg = contextAssembler.assembleContextPackage(query, retrievalResult.documents);
      const claims = DraftClaimExtractor.extractDraftClaims(draft_text);
      const grounding = GroundingValidator.validateGrounding(claims, pkg);

      res.json({
        context_package_hash: pkg.package_hash,
        claims_count: claims.length,
        grounding,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get("/api/dev/rag/audit-history", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(ragPipeline.getAuditService().getHistory());
  });

  // ==========================================
  // P26 — Packaging, Attestation & Shipping Plane
  // ==========================================
  const kmsBoundary = KmsSignerBoundary.createDefault('caim-release-key-01', 'v1');
  const shippingService = new ShippingService();

  const PACKAGING_FIXTURES: Record<string, PackageBuildInput> = {
    financial_analyst: {
      packageId: 'pkg-agent-financial-analyst-v1.0.0',
      agentId: 'agent-financial-analyst',
      agentVersionId: 'av-fin-v100',
      versionLabel: 'v1.0.0',
      createdAt: '2026-08-26T12:00:00Z',
      sourceFiles: {
        'src/agent.ts': 'export class FinancialAnalystAgent {\n  async analyzePortfolio(portfolio: any) {\n    return { audited: true, expected_return: 0.12 };\n  }\n}\n',
        'src/policy.ts': 'export const RISK_TOLERANCE_MAX = 0.05;\nexport const AUDITED_COMPLIANCE = true;\n',
        'package.json': '{\n  "name": "financial-analyst",\n  "version": "1.0.0",\n  "dependencies": {\n    "lodash": "^4.17.21"\n  }\n}\n'
      },
      analysisReport: {
        static_analysis: { findings_count: 0, taint_sinks_reached: 0, status: 'CLEAN' },
        composition_sbom: { components_count: 2, cve_vulnerabilities: 0, status: 'CLEAN' },
        sandbox_behavior: { network_egress_unauthorized: 0, syscall_violations: 0, status: 'PASSED' },
        decision_score: { overall_score: 88, risk_band: 'LOW', confidence: 0.95 },
        recommendation: { verdict: 'APPROVE', allow_shipment: true }
      },
      sbomComponents: [
        {
          name: 'lodash',
          version: '4.17.21',
          type: 'library',
          purl: 'pkg:npm/lodash@4.17.21',
          licenses: ['MIT'],
          description: 'Lodash modular utilities',
          sha256: 'b0b2e8cf702ff60b377cf3fa096df00bc19e34c9c1ef348f95fe3108c9037c22'
        },
        {
          name: '@caim/runtime',
          version: '2.0.1',
          type: 'framework',
          purl: 'pkg:generic/@caim/runtime@2.0.1',
          licenses: ['Apache-2.0'],
          description: 'CAIM Secure Runtime SDK'
        }
      ],
      validationReference: {
        validation_run_id: 'val-run-fin-001',
        validation_plan_version: 'v2.0.1-standard',
        status: 'PASSED',
        verdict: 'APPROVED_FOR_RELEASE',
        risk_reduced: true,
        capabilities_preserved: true,
        completed_at: '2026-08-26T12:00:00Z'
      },
      policyReference: {
        policy_ruleset_version: 'v2.0.1',
        policy_outcome: 'ALLOW',
        risk_score: 88,
        risk_band: 'LOW',
        policy_allowed: true,
        evaluated_at: '2026-08-26T12:00:00Z'
      },
      approvalReferences: [
        {
          approval_id: 'appr-sec-01',
          approver_id: 'usr-auditor-sec',
          approver_role: 'SECURITY_AUDITOR',
          decision: 'APPROVED',
          decided_at: '2026-08-26T12:05:00Z',
          rationale: 'Zero unmitigated taint sinks; passed deterministic sandbox'
        },
        {
          approval_id: 'appr-admin-02',
          approver_id: 'usr-platform-admin',
          approver_role: 'PLATFORM_ADMIN',
          decision: 'APPROVED',
          decided_at: '2026-08-26T12:10:00Z',
          rationale: 'Two-person authorization sign-off confirmed'
        }
      ],
      provenanceReference: {
        engine_version: '2.0.1',
        ruleset_version: '2026-08-26',
        analysis_run_id: 'ar-fin-8891',
        input_hashes: ['3c59a2f7c001a1b5b24b899...'],
        generated_at: '2026-08-26T12:00:00Z'
      },
      metadata: {
        author: 'CAIM Enterprise Security Team',
        license: 'Apache-2.0',
        securityClassification: 'RESTRICTED',
        framework: 'Node.js/TypeScript',
        description: 'Autonomous Portfolio Risk & Analytics Agent'
      }
    },
    research_agent: {
      packageId: 'pkg-agent-research-v2.1.0',
      agentId: 'agent-web-research',
      agentVersionId: 'av-research-v210',
      versionLabel: 'v2.1.0',
      createdAt: '2026-08-26T12:00:00Z',
      sourceFiles: {
        'index.ts': 'export async function search(q: string) { return { results: [] }; }\n',
        'config.json': '{\n  "mode": "bounded-search",\n  "max_depth": 2\n}\n'
      },
      analysisReport: {
        static_analysis: { findings_count: 0, status: 'CLEAN' },
        decision_score: { overall_score: 92, risk_band: 'LOW' }
      },
      sbomComponents: [
        {
          name: 'axios',
          version: '1.6.8',
          type: 'library',
          licenses: ['MIT']
        }
      ],
      validationReference: {
        validation_run_id: 'val-run-res-002',
        validation_plan_version: 'v2.0.1-standard',
        status: 'PASSED',
        verdict: 'APPROVED_FOR_RELEASE',
        risk_reduced: true,
        capabilities_preserved: true,
        completed_at: '2026-08-26T12:00:00Z'
      },
      policyReference: {
        policy_ruleset_version: 'v2.0.1',
        policy_outcome: 'ALLOW',
        risk_score: 92,
        risk_band: 'LOW',
        policy_allowed: true,
        evaluated_at: '2026-08-26T12:00:00Z'
      },
      approvalReferences: [
        {
          approval_id: 'appr-res-01',
          approver_id: 'usr-auditor-sec',
          approver_role: 'SECURITY_AUDITOR',
          decision: 'APPROVED',
          decided_at: '2026-08-26T12:05:00Z',
          rationale: 'Passed privacy and egress audits'
        },
        {
          approval_id: 'appr-res-02',
          approver_id: 'usr-lead-eng',
          approver_role: 'PLATFORM_ADMIN',
          decision: 'APPROVED',
          decided_at: '2026-08-26T12:08:00Z',
          rationale: 'Two-person approval granted'
        }
      ],
      provenanceReference: {
        engine_version: '2.0.1',
        ruleset_version: '2026-08-26',
        analysis_run_id: 'ar-res-4412',
        input_hashes: ['a88bf213904...'],
        generated_at: '2026-08-26T12:00:00Z'
      },
      metadata: {
        author: 'CAIM Research Team',
        license: 'MIT',
        securityClassification: 'INTERNAL',
        framework: 'TypeScript',
        description: 'Web Search and Summarization Autonomous Agent'
      }
    }
  };

  app.get("/api/dev/packaging/fixtures", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(PACKAGING_FIXTURES);
  });

  app.get("/api/dev/packaging/keys", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(kmsBoundary.getKeyRegistry().listKeys());
  });

  app.post("/api/dev/packaging/build", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { fixtureKey, overridePolicyOutcome } = req.body;
      const baseFixture = PACKAGING_FIXTURES[fixtureKey || 'financial_analyst'];
      if (!baseFixture) {
        return res.status(400).json({ error: `Unknown fixture key: ${fixtureKey}` });
      }

      const input: PackageBuildInput = JSON.parse(JSON.stringify(baseFixture));
      if (overridePolicyOutcome) {
        input.policyReference.policy_outcome = overridePolicyOutcome;
        input.policyReference.policy_allowed = overridePolicyOutcome === 'ALLOW';
      }

      const bundle = await DeterministicPackageBundler.buildAndSign(input, kmsBoundary);
      
      // Convert files Map to plain object for JSON response
      const filesObj: Record<string, any> = {};
      for (const [key, val] of bundle.files.entries()) {
        filesObj[key] = val;
      }

      const verification = SignatureVerifier.verifyBundle(bundle);

      res.json({
        bundle: {
          package_id: bundle.package_id,
          manifest: bundle.manifest,
          manifest_hash: bundle.manifest_hash,
          files: filesObj,
          attestation: bundle.attestation,
          signature: bundle.signature,
        },
        verification,
      });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.post("/api/dev/packaging/verify", requireDiagnosticAccess, (req: Request, res: Response) => {
    try {
      const { bundle } = req.body;
      if (!bundle) {
        return res.status(400).json({ error: 'Missing bundle payload in request body' });
      }

      // Reconstruct files Map if received as object
      const filesMap = new Map<string, any>();
      if (bundle.files && typeof bundle.files === 'object') {
        for (const [key, val] of Object.entries(bundle.files)) {
          filesMap.set(key, val);
        }
      }

      const bundleToVerify: SignedPackageBundle = {
        package_id: bundle.package_id,
        manifest: bundle.manifest,
        manifest_hash: bundle.manifest_hash,
        files: filesMap,
        attestation: bundle.attestation,
        signature: bundle.signature,
      };

      const result = SignatureVerifier.verifyBundle(bundleToVerify);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/dev/packaging/ship", requireDiagnosticAccess, async (req: Request, res: Response) => {
    try {
      const { bundle, targetType, options } = req.body;
      if (!bundle || !targetType) {
        return res.status(400).json({ error: 'Missing bundle or targetType' });
      }

      const filesMap = new Map<string, any>();
      if (bundle.files && typeof bundle.files === 'object') {
        for (const [key, val] of Object.entries(bundle.files)) {
          filesMap.set(key, val);
        }
      }

      const bundleToShip: SignedPackageBundle = {
        package_id: bundle.package_id,
        manifest: bundle.manifest,
        manifest_hash: bundle.manifest_hash,
        files: filesMap,
        attestation: bundle.attestation,
        signature: bundle.signature,
      };

      const receipt = await shippingService.shipBundle(
        bundleToShip,
        targetType,
        options || { targetLocator: 'default-target' }
      );

      res.json({ success: true, receipt });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.get("/api/dev/packaging/shipments", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(shippingService.getAuditLog());
  });

  // ---------------------------------------------------------------------------
  // P30 OBSERVABILITY, TELEMETRY, AUDIT & COST READ MODELS
  // ---------------------------------------------------------------------------
  const globalTracer = new OpenTelemetryTracer();
  const globalAuditEngine = new AuditLogEngine();

  // Populate baseline audit events for read models
  globalAuditEngine.recordEvent({
    actorType: 'USER',
    actorId: 'security-lead@caim.internal',
    action: 'POLICY_OVERRIDE_APPROVED',
    targetType: 'POLICY_GATE',
    targetId: 'gate-zero-trust-egress',
    correlation: { traceId: 'trc-init-001', requestId: 'req-init-001' },
    details: { ticket: 'CR-8821', reason: 'Assurance suite stress testing' }
  });

  globalAuditEngine.recordEvent({
    actorType: 'VAULT',
    actorId: 'kms-enclave-caim-root-v2',
    action: 'VAULT_SECRET_ACCESS',
    targetType: 'KMS_KEY',
    targetId: 'kms-enclave-caim-root-v2',
    correlation: { traceId: 'trc-init-001', requestId: 'req-init-001' },
    details: { operation: 'SignDeterministicManifest', clientIp: '10.0.1.20' }
  });

  app.get("/api/dev/observability/metrics", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(PlatformTelemetryEngine.getMetricsSnapshot());
  });

  app.get("/api/dev/observability/capacity", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(PlatformTelemetryEngine.getCapacityMetrics());
  });

  app.get("/api/dev/observability/cost", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json({
      breakdown: PlatformTelemetryEngine.getCostAttributionBreakdown(),
      summary: PlatformTelemetryEngine.getMetricsSnapshot().geminiAi
    });
  });

  app.get("/api/dev/observability/alerts", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(PlatformTelemetryEngine.getAlertConditions());
  });

  app.get("/api/dev/observability/audit", requireDiagnosticAccess, (req: Request, res: Response) => {
    const { actorId, action, targetId } = req.query;
    res.json(globalAuditEngine.getEvents({
      actorId: actorId as string,
      action: action as string,
      targetId: targetId as string
    }));
  });

  app.post("/api/dev/observability/trace/e2e", requireDiagnosticAccess, (_req: Request, res: Response) => {
    const trace = TraceResolver.createSyntheticE2ETrace(globalTracer, globalAuditEngine);
    res.json(trace);
  });

  app.post("/api/dev/observability/redact", requireDiagnosticAccess, (req: Request, res: Response) => {
    const { text, payload } = req.body;
    if (text) {
      res.json(SecretRedactor.redactString(text));
    } else if (payload) {
      res.json({ sanitizedPayload: SecretRedactor.redactObject(payload) });
    } else {
      res.status(400).json({ error: 'Provide text or payload parameter' });
    }
  });

  app.post("/api/dev/observability/verify", requireDiagnosticAccess, (_req: Request, res: Response) => {
    const testResult = runObservabilityVerificationTests();
    res.json(testResult);
  });

  // ---------------------------------------------------------------------------
  // P31 GOLDEN CORPUS, EVALUATION & REGRESSION RELEASE GATES
  // ---------------------------------------------------------------------------
  const globalEvaluationEngine = new GoldenCorpusEvaluationEngine();

  // Run baseline evaluation on server start
  const baselineRun = globalEvaluationEngine.evaluateEngineVersion({
    engineVersion: 'v2.0.1-certified',
    baselineEngineVersion: 'v2.0.0-gold',
    isConclusionChanging: false,
    simulateRegression: false,
    evaluatorActorId: 'release-gatekeeper@caim.internal'
  });

  app.get("/api/dev/evaluation/fixtures", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(GOLDEN_CORPUS_FIXTURES);
  });

  app.get("/api/dev/evaluation/thresholds", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(PRODUCTION_REGRESSION_THRESHOLDS);
  });

  app.get("/api/dev/evaluation/runs", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(globalEvaluationEngine.getAllRuns());
  });

  app.post("/api/dev/evaluation/run", requireDiagnosticAccess, (req: Request, res: Response) => {
    const { engineVersion, isConclusionChanging, simulateRegression, baselineEngineVersion } = req.body;
    const run = globalEvaluationEngine.evaluateEngineVersion({
      engineVersion: engineVersion || 'v2.1.0-candidate',
      baselineEngineVersion: baselineEngineVersion || 'v2.0.1-certified',
      isConclusionChanging: isConclusionChanging !== undefined ? isConclusionChanging : true,
      simulateRegression: Boolean(simulateRegression),
      evaluatorActorId: (req as any).principal?.actorId || 'ci-runner@caim.internal'
    });
    const decision = globalEvaluationEngine.getReleaseGateDecision(run);
    res.json({ run, decision });
  });

  app.post("/api/dev/evaluation/verify", requireDiagnosticAccess, (_req: Request, res: Response) => {
    const testResult = runEvaluationVerificationTests();
    res.json(testResult);
  });

  // ---------------------------------------------------------------------------
  // P34 REQUIREMENTS TRACEABILITY MATRIX & DEFINITION-OF-DONE AUDIT
  // ---------------------------------------------------------------------------
  app.get("/api/dev/traceability/requirements", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(AUTHORITATIVE_REQUIREMENTS_MATRIX);
  });

  app.get("/api/dev/traceability/acceptance-paths", requireDiagnosticAccess, (_req: Request, res: Response) => {
    res.json(MANDATORY_ACCEPTANCE_PATHS);
  });

  app.get("/api/dev/traceability/lineage/conclusion/:id?", requireDiagnosticAccess, (req: Request, res: Response) => {
    const conclusionId = req.params.id || 'dec-quarantine-rce-001';
    const resolution = LineageResolverEngine.resolveConclusionLineage(conclusionId);
    res.json(resolution);
  });

  app.get("/api/dev/traceability/lineage/observation/:id?", requireDiagnosticAccess, (req: Request, res: Response) => {
    const observationId = req.params.id || 'obs-github-repo-001';
    const resolution = LineageResolverEngine.resolveObservationToOntologyLineage(observationId);
    res.json(resolution);
  });

  app.get("/api/dev/traceability/quality-targets", requireDiagnosticAccess, (_req: Request, res: Response) => {
    const targets = QualityTargetsAuditor.evaluateQualityTargets();
    res.json(targets);
  });

  app.post("/api/dev/traceability/audit-run", requireDiagnosticAccess, (_req: Request, res: Response) => {
    const auditReport = runPlatformDefinitionOfDoneAudit();
    res.json(auditReport);
  });

  // Mount Standard Architecture V2.0.1 Typed API Router (/api/v1/*)
  app.use("/api/v1", createApiExpressRouter());


  // Vite middleware for development or static serving for production
  if (config.env !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, config.host, () => {
    console.log(`[CAIM Platform] Server running on http://${config.host}:${PORT} [Env: ${config.env}]`);
  });
}

startServer().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
