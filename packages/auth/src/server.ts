import { PrincipalContext, BusinessRole, ServiceIdentity } from './types.ts';
import { resolvePrincipalClaims } from './claims.ts';

export interface SupabaseServerAuthConfig {
  supabaseUrl: string;
  supabaseServiceKey?: string;
  jwtSecret?: string;
}

export class SupabaseServerAuth {
  private serviceKey?: string;

  constructor(config?: Partial<SupabaseServerAuthConfig>) {
    this.serviceKey = config?.supabaseServiceKey || process.env.SUPABASE_SERVICE_KEY;
  }

  /**
   * Resolves caller identity and roles from HTTP Authorization header or token.
   */
  public async authenticateRequest(headers: Record<string, string | string[] | undefined>): Promise<PrincipalContext> {
    const authHeader = headers['authorization'] || headers['Authorization'];
    const serviceHeader = headers['x-service-identity'] || headers['X-Service-Identity'];
    const tenantHeader = headers['x-tenant-id'] || headers['X-Tenant-Id'];
    const roleHeader = headers['x-roles'] || headers['X-Roles'];

    // 1. Service-to-Service identity header
    if (serviceHeader && typeof serviceHeader === 'string') {
      return resolvePrincipalClaims({
        principal_id: `service:${serviceHeader}`,
        is_service: true,
        service_name: serviceHeader as ServiceIdentity,
        tenant_id: typeof tenantHeader === 'string' ? tenantHeader : undefined,
      });
    }

    // 2. Bearer token extraction
    if (authHeader && typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7).trim();
      
      // In local dev/test or mock JWT decoding
      const roles: BusinessRole[] = (typeof roleHeader === 'string' ? roleHeader.split(',') : []) as BusinessRole[];
      
      return resolvePrincipalClaims({
        principal_id: token.startsWith('usr_') || token.startsWith('user_') ? token : `principal_${token.slice(0, 8)}`,
        roles: roles.length > 0 ? roles : ['user'],
        tenant_id: typeof tenantHeader === 'string' ? tenantHeader : null,
      });
    }

    // 3. Fallback to anonymous unauthenticated caller
    return resolvePrincipalClaims({
      principal_id: undefined,
      roles: ['anonymous'],
    });
  }
}

export function createServerAuthHelper(config?: Partial<SupabaseServerAuthConfig>): SupabaseServerAuth {
  return new SupabaseServerAuth(config);
}
