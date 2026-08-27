import { 
  BusinessRole, 
  PrincipalContext, 
  SecurityClassificationRank,
  CLASSIFICATION_CODE_TO_RANK,
  SecurityClassificationCode
} from '../../auth/src/index.ts';
import { UnauthorizedError, ForbiddenError } from './errors.ts';

export interface RequestAuthContext {
  principal: PrincipalContext;
  token?: string;
}

export class ApiAuthenticator {
  public static extractPrincipal(headers: Record<string, string | string[] | undefined>): PrincipalContext {
    const authHeader = (headers['authorization'] || headers['Authorization']) as string | undefined;
    const principalIdHeader = (headers['x-principal-id'] || headers['X-Principal-Id']) as string | undefined;
    const rolesHeader = (headers['x-principal-roles'] || headers['X-Principal-Roles'] || headers['x-role'] || headers['X-Role']) as string | undefined;
    const tenantIdHeader = (headers['x-tenant-id'] || headers['X-Tenant-Id']) as string | undefined;
    const classificationHeader = (headers['x-max-classification'] || headers['X-Max-Classification']) as string | undefined;

    // Default anonymous principal if no auth credentials, principal ID, or roles provided
    if (!authHeader && !principalIdHeader && !rolesHeader) {
      return {
        principal_id: 'anonymous',
        is_authenticated: false,
        is_service: false,
        roles: ['anonymous'],
        accessible_scope_ids: ['public'],
        max_classification_rank: SecurityClassificationRank.PUBLIC_METADATA,
        grants: [],
      };
    }

    // Parse roles
    let roles: BusinessRole[] = ['user'];
    if (rolesHeader) {
      roles = rolesHeader.split(',').map((r) => r.trim() as BusinessRole);
    } else if (authHeader?.includes('admin')) {
      roles = ['admin'];
    } else if (authHeader?.includes('analyst')) {
      roles = ['analyst'];
    } else if (authHeader?.includes('approver')) {
      roles = ['release_approver'];
    } else if (authHeader?.includes('auditor')) {
      roles = ['auditor'];
    } else if (authHeader?.includes('service')) {
      roles = ['operator'];
    }

    // Max classification rank
    let maxRank = SecurityClassificationRank.INTERNAL;
    if (classificationHeader) {
      const code = classificationHeader.trim() as SecurityClassificationCode;
      if (code in CLASSIFICATION_CODE_TO_RANK) {
        maxRank = CLASSIFICATION_CODE_TO_RANK[code];
      }
    } else if (roles.includes('admin') || roles.includes('vault_reader')) {
      maxRank = SecurityClassificationRank.VAULT_RESTRICTED;
    } else if (roles.includes('analyst') || roles.includes('release_approver') || roles.includes('auditor')) {
      maxRank = SecurityClassificationRank.SENSITIVE;
    }

    const principalId = principalIdHeader || (authHeader ? `usr-${authHeader.replace('Bearer ', '').slice(0, 16)}` : `usr-${roles[0] || 'default'}`);
    const isService = principalId.startsWith('service-') || roles.includes('operator');

    return {
      principal_id: principalId,
      is_authenticated: true,
      is_service: isService,
      service_name: isService ? 'system_service' : undefined,
      roles,
      tenant_id: tenantIdHeader || 'tenant-default',
      accessible_scope_ids: ['public', 'scope-default', tenantIdHeader || 'tenant-default'],
      max_classification_rank: maxRank,
      grants: roles.includes('admin') ? ['grant:all'] : ['grant:standard'],
    };
  }

  /**
   * Enforce that the request is authenticated
   */
  public static requireAuthenticated(principal: PrincipalContext): void {
    if (!principal.is_authenticated || principal.roles.includes('anonymous')) {
      throw new UnauthorizedError('Authentication required. Missing or invalid authorization credentials.');
    }
  }

  /**
   * Enforce that the principal has at least one of the allowed roles
   */
  public static requireRoles(principal: PrincipalContext, allowedRoles: BusinessRole[]): void {
    this.requireAuthenticated(principal);
    if (principal.roles.includes('admin')) {
      return; // Admin bypasses standard role checks
    }
    const hasRole = principal.roles.some((r) => allowedRoles.includes(r));
    if (!hasRole) {
      throw new ForbiddenError(
        `Action requires one of the following roles: [${allowedRoles.join(', ')}]. Principal has: [${principal.roles.join(', ')}]`,
        { required_roles: allowedRoles, principal_roles: principal.roles }
      );
    }
  }

  /**
   * Enforce classification level clearance
   */
  public static requireClassification(principal: PrincipalContext, requiredClassification: SecurityClassificationRank): void {
    this.requireAuthenticated(principal);
    if (principal.max_classification_rank < requiredClassification) {
      throw new ForbiddenError('Insufficient security classification clearance for requested resource', {
        required_rank: requiredClassification,
        principal_rank: principal.max_classification_rank,
      });
    }
  }
}
