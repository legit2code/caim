import {
  FeatureFlagsSchema,
  FeatureFlags,
  ModelConfigSchema,
  ModelConfig,
  PublicConfigSchema,
  PublicConfig,
  ServerConfigSchema,
  ServerConfig,
  WorkerConfigSchema,
  WorkerConfig,
  OptionalProviders,
} from './schema.ts';

export class ConfigurationError extends Error {
  constructor(message: string, public readonly details?: unknown) {
    super(`[ConfigurationError] ${message}`);
    this.name = 'ConfigurationError';
  }
}

export type ProviderAdapterStatus =
  | { status: 'READY'; credentialPresent: true }
  | { status: 'DISABLED_MISSING_CREDENTIAL'; credentialPresent: false; reason: string };

function parseBoolean(val: string | undefined, defaultValue: boolean): boolean {
  if (val === undefined || val === '') return defaultValue;
  return val.toLowerCase() === 'true' || val === '1';
}

/**
 * Loads feature flags safely from environment variables or defaults.
 */
export function getFeatureFlags(): FeatureFlags {
  const raw = {
    enableDynamicSandbox: parseBoolean(process.env.FEATURE_DYNAMIC_SANDBOX, true),
    enableEvasionDetection: parseBoolean(process.env.FEATURE_EVASION_DETECTION, true),
    enableTaintAnalysis: parseBoolean(process.env.FEATURE_TAINT_ANALYSIS, true),
    enableHybridRAG: parseBoolean(process.env.FEATURE_HYBRID_RAG, true),
    enableContinuousMonitoring: parseBoolean(process.env.FEATURE_CONTINUOUS_MONITORING, false),
    enableAutomatedRemediation: parseBoolean(process.env.FEATURE_AUTOMATED_REMEDIATION, false),
    enableModelCardAIBOM: parseBoolean(process.env.FEATURE_MODEL_CARD_AIBOM, true),
  };

  const parsed = FeatureFlagsSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ConfigurationError('Invalid feature flag configuration', parsed.error.format());
  }
  return parsed.data;
}

/**
 * Loads model configuration.
 */
export function getModelConfig(): ModelConfig {
  const raw = {
    geminiModelDefault: process.env.GEMINI_MODEL_DEFAULT || 'gemini-2.5-flash',
    geminiModelPro: process.env.GEMINI_MODEL_PRO || 'gemini-2.5-pro',
    geminiEmbeddingModel: process.env.GEMINI_MODEL_EMBEDDING || 'text-embedding-004',
    temperature: process.env.MODEL_TEMPERATURE ? parseFloat(process.env.MODEL_TEMPERATURE) : 0.2,
    maxOutputTokens: process.env.MODEL_MAX_OUTPUT_TOKENS ? parseInt(process.env.MODEL_MAX_OUTPUT_TOKENS, 10) : 8192,
  };

  const parsed = ModelConfigSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ConfigurationError('Invalid model configuration', parsed.error.format());
  }
  return parsed.data;
}

/**
 * Loads sanitized public configuration suitable for browser consumption.
 * Guaranteed to NEVER include secrets, API keys, or private signing keys.
 */
export function getPublicConfig(): PublicConfig {
  const features = getFeatureFlags();
  const models = getModelConfig();

  const raw = {
    env: (process.env.NODE_ENV as any) || 'development',
    appUrl: process.env.APP_URL || 'http://localhost:3000',
    platformVersion: '2.0.1',
    baseline: 'V2.0.1 Controlled Implementation Baseline',
    apiPrefix: '/api',
    features,
    models: {
      defaultModel: models.geminiModelDefault,
      embeddingModel: models.geminiEmbeddingModel,
    },
  };

  const parsed = PublicConfigSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ConfigurationError('Invalid public configuration', parsed.error.format());
  }
  return parsed.data;
}

/**
 * Loads authoritative server-side configuration.
 */
export function getServerConfig(): ServerConfig {
  const features = getFeatureFlags();
  const models = getModelConfig();

  const raw = {
    env: (process.env.NODE_ENV as any) || 'development',
    port: 3000,
    host: '0.0.0.0',
    appUrl: process.env.APP_URL || 'http://localhost:3000',
    geminiApiKey: process.env.GEMINI_API_KEY,
    signing: {
      keyId: process.env.SIGNING_KEY_ID || 'caim-v2-dev-key',
      algorithm: (process.env.SIGNING_ALGORITHM as any) || 'Ed25519',
      privateKey: process.env.SIGNING_PRIVATE_KEY,
      publicKey: process.env.SIGNING_PUBLIC_KEY,
    },
    providers: {
      githubToken: process.env.GITHUB_TOKEN,
      huggingfaceApiKey: process.env.HUGGINGFACE_API_KEY,
      e2bApiKey: process.env.E2B_API_KEY,
      sentryDsn: process.env.SENTRY_DSN,
      supabaseServiceKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
      supabaseUrl: process.env.SUPABASE_URL,
    },
    features,
    models,
  };

  const parsed = ServerConfigSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ConfigurationError('Invalid server configuration', parsed.error.format());
  }
  return parsed.data;
}

/**
 * Loads worker configuration for a specific worker domain.
 */
export function getWorkerConfig(workerDomain: string): WorkerConfig {
  const raw = {
    workerDomain,
    concurrency: process.env.WORKER_CONCURRENCY ? parseInt(process.env.WORKER_CONCURRENCY, 10) : 4,
    heartbeatIntervalMs: 10000,
    taskTimeoutMs: 300000,
    sandboxMemoryLimitMb: 1024,
    isolatedProcess: true,
    geminiApiKey: process.env.GEMINI_API_KEY,
    providers: {
      githubToken: process.env.GITHUB_TOKEN,
      huggingfaceApiKey: process.env.HUGGINGFACE_API_KEY,
      e2bApiKey: process.env.E2B_API_KEY,
      sentryDsn: process.env.SENTRY_DSN,
      supabaseServiceKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
      supabaseUrl: process.env.SUPABASE_URL,
    },
  };

  const parsed = WorkerConfigSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ConfigurationError(`Invalid worker configuration for ${workerDomain}`, parsed.error.format());
  }
  return parsed.data;
}

/**
 * Checks status of optional external provider adapters without throwing or halting startup.
 */
export function getOptionalProviderStatus(provider: keyof OptionalProviders): ProviderAdapterStatus {
  const serverConfig = getServerConfig();
  const credential = serverConfig.providers[provider];

  if (credential && credential.trim().length > 0) {
    return { status: 'READY', credentialPresent: true };
  }

  return {
    status: 'DISABLED_MISSING_CREDENTIAL',
    credentialPresent: false,
    reason: `Optional provider '${String(provider)}' is inactive because credentials are not configured in environment.`,
  };
}
