/**
 * Real Multi-Tier Principal-Scoped Rate Limiter
 * 
 * Provides rate limiting for all /api/* routes, scoped per authenticated principal
 * (fallback to client IP if unauthenticated). Enforces strict limits on expensive compute/API routes.
 */

import { Request, Response, NextFunction } from 'express';
import { PrincipalContext } from './types.ts';

export interface RateLimitConfig {
  windowMs: number; // Duration of window in milliseconds (e.g. 60,000 for 1 minute)
  maxRequests: number; // Maximum requests allowed within window
  tierName?: string; // Descriptive tier identifier
}

export interface RouteRateLimitRule {
  pathPattern: RegExp | string;
  methods?: string[]; // Optional method filter (e.g. ['POST'])
  config: RateLimitConfig;
  description: string;
}

export interface RateLimitBucket {
  count: number;
  resetAt: number; // Epoch ms when bucket resets
}

export const RATE_LIMIT_TIERS = {
  // Expensive compute, external search, LLM RAG, and microVM sandbox routes
  COMPOSER_GENERATE: { windowMs: 60_000, maxRequests: 5, tierName: 'COMPOSER_GENERATE' },      // 5 req / min
  COMPOSER_EXECUTE: { windowMs: 60_000, maxRequests: 10, tierName: 'COMPOSER_EXECUTE' },       // 10 req / min
  ANALYSIS_TRIGGER: { windowMs: 60_000, maxRequests: 10, tierName: 'ANALYSIS_TRIGGER' },       // 10 req / min
  DISCOVERY_TRIGGER: { windowMs: 60_000, maxRequests: 10, tierName: 'DISCOVERY_TRIGGER' },     // 10 req / min
  RAG_CHAT: { windowMs: 60_000, maxRequests: 20, tierName: 'RAG_CHAT' },                       // 20 req / min

  // General standard API routes
  DEFAULT_API: { windowMs: 60_000, maxRequests: 120, tierName: 'DEFAULT_API' },                // 120 req / min
  AUTH_ENDPOINTS: { windowMs: 60_000, maxRequests: 30, tierName: 'AUTH_ENDPOINTS' },           // 30 req / min
} as const;

export class RateLimiterEngine {
  private buckets: Map<string, RateLimitBucket> = new Map();
  private rules: RouteRateLimitRule[] = [];
  private defaultConfig: RateLimitConfig = RATE_LIMIT_TIERS.DEFAULT_API;

  constructor(rules?: RouteRateLimitRule[], defaultConfig?: RateLimitConfig) {
    if (rules) {
      this.rules = rules;
    } else {
      this.initDefaultRules();
    }
    if (defaultConfig) {
      this.defaultConfig = defaultConfig;
    }

    // Periodic cleanup of expired buckets every 5 minutes
    if (typeof setInterval !== 'undefined') {
      setInterval(() => this.cleanupExpiredBuckets(), 5 * 60 * 1000).unref?.();
    }
  }

  private initDefaultRules() {
    this.rules = [
      {
        pathPattern: /^\/api\/composer\/generate/,
        methods: ['POST'],
        config: RATE_LIMIT_TIERS.COMPOSER_GENERATE,
        description: 'Composer Code Generation (LLM Synthesis & AST Verification)',
      },
      {
        pathPattern: /^\/api\/composer\/execute/,
        methods: ['POST'],
        config: RATE_LIMIT_TIERS.COMPOSER_EXECUTE,
        description: 'Composer MicroVM Isolated Execution & Canary Verification',
      },
      {
        pathPattern: /^\/api\/(analysis\/trigger|analysis\/runs|dev\/analysis\/trigger)/,
        methods: ['POST'],
        config: RATE_LIMIT_TIERS.ANALYSIS_TRIGGER,
        description: 'Analysis Trigger (Full AST, Taint Graph & Dynamic E2B Sandbox Verification)',
      },
      {
        pathPattern: /^\/api\/(discovery\/pipeline\/trigger|discovery\/run|dev\/discovery\/run)/,
        methods: ['POST'],
        config: RATE_LIMIT_TIERS.DISCOVERY_TRIGGER,
        description: 'Discovery Pipeline Scan (Web Crawling & Multi-Source Polymorphic Resolution)',
      },
      {
        pathPattern: /^\/api\/rag\/chat/,
        methods: ['POST'],
        config: RATE_LIMIT_TIERS.RAG_CHAT,
        description: 'Grounded RAG Chat Synthesis (Hybrid Fusion & Vector Retrieval)',
      },
      {
        pathPattern: /^\/api\/auth\/(login|register|refresh)/,
        methods: ['POST'],
        config: RATE_LIMIT_TIERS.AUTH_ENDPOINTS,
        description: 'Authentication & Credential Exchange',
      },
    ];
  }

  /**
   * Resolves the rate-limiting key for a given request.
   * Priority: Authenticated principal_id > Fallback Client IP
   */
  public resolveCallerKey(req: Request): { key: string; isPrincipal: boolean; principalId: string } {
    const principal = (req as any).principal as PrincipalContext | undefined;
    if (principal && principal.is_authenticated && principal.principal_id && principal.principal_id !== 'anonymous') {
      return {
        key: `principal:${principal.principal_id}`,
        isPrincipal: true,
        principalId: principal.principal_id,
      };
    }

    const ip = req.ip || req.socket?.remoteAddress || req.headers['x-forwarded-for'] || '127.0.0.1';
    const cleanIp = Array.isArray(ip) ? ip[0] : (typeof ip === 'string' ? ip.split(',')[0].trim() : '127.0.0.1');
    return {
      key: `ip:${cleanIp}`,
      isPrincipal: false,
      principalId: `anonymous-${cleanIp}`,
    };
  }

  /**
   * Finds matching route config rule or falls back to default.
   */
  public matchRule(path: string, method: string): { config: RateLimitConfig; description: string } {
    for (const rule of this.rules) {
      if (rule.methods && !rule.methods.includes(method.toUpperCase())) {
        continue;
      }
      if (typeof rule.pathPattern === 'string') {
        if (path.startsWith(rule.pathPattern)) {
          return { config: rule.config, description: rule.description };
        }
      } else if (rule.pathPattern.test(path)) {
        return { config: rule.config, description: rule.description };
      }
    }
    return { config: this.defaultConfig, description: 'Standard API Endpoint' };
  }

  /**
   * Evaluates request against rate limit.
   */
  public checkLimit(req: Request): {
    allowed: boolean;
    limit: number;
    remaining: number;
    resetAt: number; // Unix timestamp in seconds
    retryAfterSeconds: number;
    tierName: string;
    description: string;
    callerKey: string;
  } {
    const path = req.path || req.originalUrl || '/';
    const method = req.method || 'GET';
    const { key, principalId } = this.resolveCallerKey(req);
    const { config, description } = this.matchRule(path, method);

    const bucketKey = `${key}:${config.tierName || 'default'}`;
    const now = Date.now();

    let bucket = this.buckets.get(bucketKey);
    if (!bucket || now >= bucket.resetAt) {
      bucket = {
        count: 0,
        resetAt: now + config.windowMs,
      };
      this.buckets.set(bucketKey, bucket);
    }

    bucket.count += 1;
    const allowed = bucket.count <= config.maxRequests;
    const remaining = Math.max(0, config.maxRequests - bucket.count);
    const resetAtSeconds = Math.ceil(bucket.resetAt / 1000);
    const retryAfterSeconds = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));

    return {
      allowed,
      limit: config.maxRequests,
      remaining,
      resetAt: resetAtSeconds,
      retryAfterSeconds,
      tierName: config.tierName || 'DEFAULT_API',
      description,
      callerKey: key,
    };
  }

  /**
   * Resets all buckets (useful for test assertions).
   */
  public resetAll(): void {
    this.buckets.clear();
  }

  /**
   * Cleans up expired buckets.
   */
  public cleanupExpiredBuckets(): void {
    const now = Date.now();
    for (const [key, bucket] of this.buckets.entries()) {
      if (now >= bucket.resetAt) {
        this.buckets.delete(key);
      }
    }
  }

  /**
   * Returns current active bucket statistics.
   */
  public getStats(): { totalBuckets: number; activeTiers: Record<string, number> } {
    const activeTiers: Record<string, number> = {};
    for (const key of this.buckets.keys()) {
      const tier = key.split(':')[2] || 'default';
      activeTiers[tier] = (activeTiers[tier] || 0) + 1;
    }
    return {
      totalBuckets: this.buckets.size,
      activeTiers,
    };
  }
}

/**
 * Creates Express middleware enforcing rate limits on all /api/* routes.
 */
export function createRateLimiterMiddleware(engine: RateLimiterEngine) {
  return (req: Request, res: Response, next: NextFunction) => {
    // Only apply rate limiting to /api/* routes
    if (!req.path.startsWith('/api') && !req.originalUrl.startsWith('/api')) {
      return next();
    }

    // Health check and root diagnostic bypass to ensure container readiness probes never fail
    if (req.path === '/api/health' || req.path === '/api/config/public') {
      return next();
    }

    const check = engine.checkLimit(req);

    // Set standard RFC rate-limiting headers
    res.setHeader('X-RateLimit-Limit', check.limit.toString());
    res.setHeader('X-RateLimit-Remaining', check.remaining.toString());
    res.setHeader('X-RateLimit-Reset', check.resetAt.toString());
    res.setHeader('X-RateLimit-Tier', check.tierName);

    if (!check.allowed) {
      res.setHeader('Retry-After', check.retryAfterSeconds.toString());
      return res.status(429).json({
        error: `Too Many Requests: Rate limit of ${check.limit} requests per minute exceeded for ${check.callerKey} on ${check.description}.`,
        code: 'RATE_LIMIT_EXCEEDED',
        tier: check.tierName,
        limit: check.limit,
        window_seconds: 60,
        retry_after_seconds: check.retryAfterSeconds,
      });
    }

    next();
  };
}
