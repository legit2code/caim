import { PrincipalContext, BusinessRole, ServiceIdentity, UnauthorizedAccessError } from './types.ts';
import { resolvePrincipalClaims } from './claims.ts';
import { verifyAccessToken, DEFAULT_JWT_SECRET } from './jwt.ts';

export interface SupabaseServerAuthConfig {
  supabaseUrl?: string;
  supabaseServiceKey?: string;
  jwtSecret?: string;
  serviceSecret?: string;
  allowDevBypass?: boolean;
}

export class SupabaseServerAuth {
  private serviceKey?: string;
  private jwtSecret: string;
  private serviceSecret: string;
  private allowDevBypass: boolean;

  constructor(config?: Partial<SupabaseServerAuthConfig>) {
    this.serviceKey = config?.supabaseServiceKey || process.env.SUPABASE_SERVICE_KEY;
    this.jwtSecret = config?.jwtSecret || process.env.JWT_SECRET || DEFAULT_JWT_SECRET;
    this.serviceSecret = config?.serviceSecret || process.env.SERVICE_TO_SERVICE_SECRET || this.serviceKey || 'caim-internal-mesh-secret-key-2026';
    
    // Auth bypass is strictly forbidden in production
    const isProd = process.env.NODE_ENV === 'production';
    this.allowDevBypass = !isProd && (config?.allowDevBypass ?? false);
  }

  /**
   * Resolves caller identity and roles from verified JWT token or verified service credentials.
   * NOTE: Client-supplied role headers (x-roles, x-user-role, x-role) are NEVER trusted or used to grant roles.
   */
  public async authenticateRequest(headers: Record<string, string | string[] | undefined>): Promise<PrincipalContext> {
    const authHeader = headers['authorization'] || headers['Authorization'];
    const serviceHeader = headers['x-service-identity'] || headers['X-Service-Identity'];
    const serviceSecretHeader = headers['x-service-secret'] || headers['X-Service-Secret'] || headers['x-service-key'] || headers['X-Service-Key'];
    const tenantHeader = headers['x-tenant-id'] || headers['X-Tenant-Id'];
    const bypassHeader = headers['x-bypass-auth'] || headers['X-Bypass-Auth'];

    // 1. Service-to-Service identity verification (REQUIRES verified shared secret)
    if (serviceHeader && typeof serviceHeader === 'string') {
      const isSecretValid = typeof serviceSecretHeader === 'string' && (
        serviceSecretHeader === this.serviceSecret ||
        (this.serviceKey && serviceSecretHeader === this.serviceKey)
      );

      if (isSecretValid) {
        return resolvePrincipalClaims({
          principal_id: `service:${serviceHeader}`,
          is_service: true,
          service_name: serviceHeader as ServiceIdentity,
          tenant_id: typeof tenantHeader === 'string' ? tenantHeader : undefined,
        });
      }

      // If service header is passed without valid secret, reject service elevation
      return resolvePrincipalClaims({
        principal_id: undefined,
        roles: ['anonymous'],
      });
    }

    // 2. Bearer JWT extraction & cryptographic signature/expiry verification
    if (authHeader && typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7).trim();

      try {
        const decoded = verifyAccessToken(token, this.jwtSecret);
        
        return resolvePrincipalClaims({
          principal_id: decoded.sub,
          roles: decoded.roles && Array.isArray(decoded.roles) ? decoded.roles : ['user'],
          tenant_id: decoded.tenant_id || (typeof tenantHeader === 'string' ? tenantHeader : null),
          accessible_scope_ids: decoded.accessible_scope_ids,
          is_service: decoded.is_service ?? false,
          service_name: decoded.service_name,
        });
      } catch (err: any) {
        // Token verification failed (invalid signature, expired, tampered)
        // Strictly return unauthenticated anonymous context — do not grant any roles
        return resolvePrincipalClaims({
          principal_id: undefined,
          roles: ['anonymous'],
        });
      }
    }

    // 3. Optional Dev Bypass Header (STRICTLY gated out in production)
    const isProduction = process.env.NODE_ENV === 'production';
    if (!isProduction && this.allowDevBypass && bypassHeader === 'true') {
      return resolvePrincipalClaims({
        principal_id: 'dev_bypass_principal',
        roles: ['user'],
      });
    }

    // 4. Fallback to anonymous unauthenticated caller
    return resolvePrincipalClaims({
      principal_id: undefined,
      roles: ['anonymous'],
    });
  }
}

export function createServerAuthHelper(config?: Partial<SupabaseServerAuthConfig>): SupabaseServerAuth {
  return new SupabaseServerAuth(config);
}
