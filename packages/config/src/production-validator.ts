import { ServerConfig } from './schema.ts';
import { getServerConfig } from './loaders.ts';

export interface ConfigValidationFinding {
  key: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  category: 'MANDATORY_SECRET' | 'INSECURE_DEFAULT' | 'OPTIONAL_ADAPTER' | 'ENVIRONMENT_MISMATCH' | 'DEV_FIXTURE';
  message: string;
  recommendation: string;
  passed: boolean;
}

export interface ProductionConfigValidationReport {
  timestamp: string;
  environment: 'development' | 'staging' | 'production' | 'test';
  isValid: boolean;
  canDeployToProduction: boolean;
  totalChecks: number;
  passedChecks: number;
  failedChecks: number;
  findings: ConfigValidationFinding[];
  adapterStatuses: Record<string, {
    status: 'READY' | 'DISABLED_OPTIONAL' | 'DISABLED_MISSING_CREDENTIAL';
    credentialConfigured: boolean;
    operationalImpact: string;
  }>;
}

export class ProductionConfigValidator {
  /**
   * Validates the configuration against strict production security standards.
   * In 'production' environment, fails fast if any CRITICAL or HIGH finding is detected.
   */
  static validate(customConfig?: Partial<ServerConfig>, targetEnv?: 'development' | 'staging' | 'production' | 'test'): ProductionConfigValidationReport {
    const config = customConfig ? { ...getServerConfig(), ...customConfig } : getServerConfig();
    const env = targetEnv || (process.env.NODE_ENV as any) || config.env || 'development';
    const isProduction = env === 'production';

    const findings: ConfigValidationFinding[] = [];

    // 1. Mandatory Secrets & Keys Check
    // Master Key / Secret Key validation
    const hasSupabaseServiceKey = Boolean(config.providers.supabaseServiceKey && config.providers.supabaseServiceKey.trim().length > 0);
    const hasSigningPrivateKey = Boolean(config.signing.privateKey && config.signing.privateKey.trim().length > 0);
    const hasGeminiApiKey = Boolean(config.geminiApiKey && config.geminiApiKey.trim().length > 0);

    if (isProduction) {
      findings.push({
        key: 'SIGNING_PRIVATE_KEY',
        severity: 'CRITICAL',
        category: 'MANDATORY_SECRET',
        message: hasSigningPrivateKey ? 'Production Ed25519/KMS private signing key configured' : 'Missing mandatory SIGNING_PRIVATE_KEY for package attestation',
        recommendation: 'Configure a secure Ed25519 private key or Cloud KMS key reference in production.',
        passed: hasSigningPrivateKey,
      });

      findings.push({
        key: 'GEMINI_API_KEY',
        severity: 'CRITICAL',
        category: 'MANDATORY_SECRET',
        message: hasGeminiApiKey ? 'Server-side GEMINI_API_KEY is configured' : 'Missing GEMINI_API_KEY for server-side AI evaluation and analysis',
        recommendation: 'Set GEMINI_API_KEY as a secure server-side environment secret.',
        passed: hasGeminiApiKey,
      });
    } else {
      findings.push({
        key: 'SIGNING_PRIVATE_KEY',
        severity: 'INFORMATIONAL',
        category: 'MANDATORY_SECRET',
        message: hasSigningPrivateKey ? 'Signing private key configured' : 'Signing private key optional in development (ephemeral key generated on demand)',
        recommendation: 'In dev/test, an ephemeral in-memory Ed25519 keypair is used automatically.',
        passed: true,
      });

      findings.push({
        key: 'GEMINI_API_KEY',
        severity: hasGeminiApiKey ? 'INFORMATIONAL' : 'MEDIUM',
        category: 'MANDATORY_SECRET',
        message: hasGeminiApiKey ? 'GEMINI_API_KEY is configured' : 'GEMINI_API_KEY not configured (mock/fallback evaluation mode active)',
        recommendation: 'Provide GEMINI_API_KEY to test live generative AI features.',
        passed: true,
      });
    }

    // 2. Insecure Default Checks
    const isDefaultDevKeyId = config.signing.keyId === 'caim-v2-dev-key';
    if (isProduction && isDefaultDevKeyId) {
      findings.push({
        key: 'SIGNING_KEY_ID',
        severity: 'HIGH',
        category: 'INSECURE_DEFAULT',
        message: 'Insecure default SIGNING_KEY_ID ("caim-v2-dev-key") detected in production',
        recommendation: 'Set a dedicated production key ID (e.g. "caim-prod-kms-2026-v1").',
        passed: false,
      });
    } else {
      findings.push({
        key: 'SIGNING_KEY_ID',
        severity: 'INFORMATIONAL',
        category: 'INSECURE_DEFAULT',
        message: `Signing Key ID is "${config.signing.keyId}"`,
        recommendation: 'Valid for current environment.',
        passed: true,
      });
    }

    // App URL Insecure Host Check in Production
    const isLocalhostAppUrl = config.appUrl.includes('localhost') || config.appUrl.includes('127.0.0.1');
    if (isProduction && isLocalhostAppUrl) {
      findings.push({
        key: 'APP_URL',
        severity: 'HIGH',
        category: 'ENVIRONMENT_MISMATCH',
        message: `APP_URL points to localhost (${config.appUrl}) in production mode`,
        recommendation: 'Set APP_URL to the fully-qualified HTTPS production domain.',
        passed: false,
      });
    } else {
      findings.push({
        key: 'APP_URL',
        severity: 'INFORMATIONAL',
        category: 'ENVIRONMENT_MISMATCH',
        message: `APP_URL is ${config.appUrl}`,
        recommendation: 'Valid application base URL.',
        passed: true,
      });
    }

    // 3. Optional Adapters Status Analysis
    const adapterStatuses: Record<string, {
      status: 'READY' | 'DISABLED_OPTIONAL' | 'DISABLED_MISSING_CREDENTIAL';
      credentialConfigured: boolean;
      operationalImpact: string;
    }> = {
      github: {
        status: config.providers.githubToken ? 'READY' : 'DISABLED_OPTIONAL',
        credentialConfigured: Boolean(config.providers.githubToken),
        operationalImpact: config.providers.githubToken 
          ? 'Full GitHub API discovery, release scanning, and authenticated rate limits (5,000 req/hr).'
          : 'Public repository discovery only (60 req/hr unauthenticated rate limit).',
      },
      huggingface: {
        status: config.providers.huggingfaceApiKey ? 'READY' : 'DISABLED_OPTIONAL',
        credentialConfigured: Boolean(config.providers.huggingfaceApiKey),
        operationalImpact: config.providers.huggingfaceApiKey
          ? 'Authenticated model card and dataset extraction from Hugging Face Hub.'
          : 'Public model discovery only; gated models skipped.',
      },
      e2b: {
        status: config.providers.e2bApiKey ? 'READY' : 'DISABLED_OPTIONAL',
        credentialConfigured: Boolean(config.providers.e2bApiKey),
        operationalImpact: config.providers.e2bApiKey
          ? 'Cloud-hosted Firecracker microVM dynamic sandboxing enabled.'
          : 'Local isolated Node.js container / VM process sandbox enabled as baseline.',
      },
      sentry: {
        status: config.providers.sentryDsn ? 'READY' : 'DISABLED_OPTIONAL',
        credentialConfigured: Boolean(config.providers.sentryDsn),
        operationalImpact: config.providers.sentryDsn
          ? 'Remote crash and exception telemetry forwarded to Sentry.'
          : 'Local structured audit logs and OpenTelemetry in-memory collector active.',
      },
      supabase: {
        status: hasSupabaseServiceKey ? 'READY' : 'DISABLED_OPTIONAL',
        credentialConfigured: hasSupabaseServiceKey,
        operationalImpact: hasSupabaseServiceKey
          ? 'Managed PostgreSQL with RLS, Vault, and Realtime replication.'
          : 'Local PostgreSQL / in-memory transaction store active.',
      },
    };

    // 4. Development Fixtures Check
    const allowDevFixtures = !isProduction;
    findings.push({
      key: 'DEV_FIXTURES_POLICY',
      severity: 'INFORMATIONAL',
      category: 'DEV_FIXTURE',
      message: allowDevFixtures 
        ? 'Development fixtures and synthetic corpus replay permitted in non-production environment'
        : 'Development fixtures isolated; strictly live data stores in production',
      recommendation: 'Ensure mock credentials and test seeds are excluded from release containers.',
      passed: true,
    });

    const totalChecks = findings.length;
    const failedChecks = findings.filter(f => !f.passed).length;
    const passedChecks = totalChecks - failedChecks;

    // In production, any CRITICAL or HIGH failure prevents deployment
    const hasCriticalOrHighFailure = findings.some(f => !f.passed && (f.severity === 'CRITICAL' || f.severity === 'HIGH'));
    const canDeployToProduction = !hasCriticalOrHighFailure;
    const isValid = failedChecks === 0;

    return {
      timestamp: new Date().toISOString(),
      environment: env,
      isValid,
      canDeployToProduction,
      totalChecks,
      passedChecks,
      failedChecks,
      findings,
      adapterStatuses,
    };
  }

  /**
   * Throws ConfigurationError if production requirements are violated when running in production.
   */
  static assertProductionReadiness(customConfig?: Partial<ServerConfig>): void {
    const report = this.validate(customConfig, 'production');
    if (!report.canDeployToProduction) {
      const issues = report.findings.filter(f => !f.passed).map(f => `[${f.severity}] ${f.key}: ${f.message}`).join('; ');
      throw new Error(`[ProductionConfigViolation] Cannot deploy to production. Failed security gates: ${issues}`);
    }
  }
}
