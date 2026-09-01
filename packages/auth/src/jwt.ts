/**
 * Enterprise JSON Web Token (JWT) Service
 * Issues standard signed HS256/RS256 JWTs with short expiry, signature verification, and refresh token rotation.
 */

import jwt, { SignOptions, VerifyOptions } from 'jsonwebtoken';
import crypto from 'crypto';
import { BusinessRole, ServiceIdentity } from './types.ts';

function resolveDefaultJwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (process.env.NODE_ENV === 'production' && !secret) {
    throw new Error(
      'FATAL SECURITY VIOLATION: process.env.JWT_SECRET is not configured. JWT_SECRET must be explicitly set in production environments.'
    );
  }
  return secret || 'caim-enterprise-v2-jwt-secret-authenticated-production-token-2026';
}

export const DEFAULT_JWT_SECRET = resolveDefaultJwtSecret();
export const DEFAULT_ACCESS_TOKEN_EXPIRY = '15m'; // Short-lived token per security requirements

export interface JwtPrincipalClaims {
  sub: string; // principal_id
  email: string;
  roles: BusinessRole[];
  tenant_id?: string | null;
  accessible_scope_ids?: string[];
  is_service?: boolean;
  service_name?: ServiceIdentity;
  iss?: string;
  aud?: string;
  iat?: number;
  exp?: number;
}

export interface SignTokenOptions {
  secret?: string;
  expiresIn?: SignOptions['expiresIn'];
  issuer?: string;
  audience?: string;
}

/**
 * Signs a short-lived access token with cryptographically verified claims.
 */
export function signAccessToken(
  claims: {
    principal_id: string;
    email: string;
    roles: BusinessRole[];
    tenant_id?: string | null;
    accessible_scope_ids?: string[];
    is_service?: boolean;
    service_name?: ServiceIdentity;
  },
  options?: SignTokenOptions
): string {
  const secret = options?.secret || DEFAULT_JWT_SECRET;
  const payload: Omit<JwtPrincipalClaims, 'iat' | 'exp'> = {
    sub: claims.principal_id,
    email: claims.email,
    roles: claims.roles && claims.roles.length > 0 ? claims.roles : ['user'],
    tenant_id: claims.tenant_id || null,
    accessible_scope_ids: claims.accessible_scope_ids || ['00000000-0000-0000-0000-000000000001'],
    is_service: claims.is_service ?? false,
    service_name: claims.service_name,
  };

  const signOpts: SignOptions = {
    algorithm: 'HS256',
    expiresIn: options?.expiresIn ?? DEFAULT_ACCESS_TOKEN_EXPIRY,
    issuer: options?.issuer || 'caim-auth-service',
    audience: options?.audience || 'caim-platform',
  };

  return jwt.sign(payload, secret, signOpts);
}

/**
 * Strictly verifies JWT signature and expiry.
 * Throws JsonWebTokenError or TokenExpiredError if invalid.
 */
export function verifyAccessToken(token: string, secret?: string): JwtPrincipalClaims {
  if (!token || typeof token !== 'string') {
    throw new Error('Missing or invalid token string');
  }

  const effectiveSecret = secret || DEFAULT_JWT_SECRET;
  const verifyOpts: VerifyOptions = {
    algorithms: ['HS256'],
    issuer: 'caim-auth-service',
    audience: 'caim-platform',
  };

  const decoded = jwt.verify(token, effectiveSecret, verifyOpts) as JwtPrincipalClaims;
  return decoded;
}

/**
 * Generates an opaque cryptographically secure refresh token + sha256 hash.
 */
export function generateRefreshToken(): { token: string; tokenHash: string } {
  const token = `rt_${crypto.randomBytes(32).toString('hex')}`;
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  return { token, tokenHash };
}

/**
 * Computes sha256 hash of a refresh token string for lookup.
 */
export function hashRefreshToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}
