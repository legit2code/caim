import { 
  BusinessRole, 
  PrincipalContext, 
  SecurityClassificationRank, 
  ServiceIdentity 
} from './types.ts';

export interface ResolveClaimsInput {
  principal_id?: string;
  is_service?: boolean;
  service_name?: ServiceIdentity;
  roles?: BusinessRole[];
  tenant_id?: string | null;
  accessible_scope_ids?: string[];
  grants?: string[];
}

/**
 * Resolves maximum authorized security classification clearance for a principal based on their roles and grants.
 */
export function resolveClassificationClearance(roles: BusinessRole[], grants: string[] = []): SecurityClassificationRank {
  if (roles.includes('admin') || roles.includes('vault_reader') || grants.includes('vault_reader')) {
    return SecurityClassificationRank.VAULT_RESTRICTED;
  }
  if (roles.includes('reviewer') || roles.includes('release_approver') || roles.includes('analyst') || roles.includes('auditor') || roles.includes('operator')) {
    return SecurityClassificationRank.SENSITIVE;
  }
  if (roles.includes('user')) {
    return SecurityClassificationRank.INTERNAL;
  }
  return SecurityClassificationRank.PUBLIC_METADATA;
}

/**
 * Resolves full PrincipalContext from input identity claims and memberships.
 */
export function resolvePrincipalClaims(input: ResolveClaimsInput): PrincipalContext {
  const isService = Boolean(input.is_service || input.service_name);
  const rawRoles = input.roles || [];
  
  // Anonymous fallback
  if (!input.principal_id && !isService) {
    return {
      principal_id: 'anonymous',
      is_authenticated: false,
      is_service: false,
      roles: ['anonymous'],
      tenant_id: null,
      accessible_scope_ids: ['00000000-0000-0000-0000-000000000001'], // Platform scope
      max_classification_rank: SecurityClassificationRank.PUBLIC_METADATA,
      grants: [],
    };
  }

  const effectiveRoles: BusinessRole[] = isService 
    ? ['admin', 'operator'] 
    : (rawRoles.length > 0 ? rawRoles : ['user']);

  const grants = input.grants || [];
  const maxClearance = resolveClassificationClearance(effectiveRoles, grants);

  return {
    principal_id: input.principal_id || (input.service_name ? `service:${input.service_name}` : 'unknown'),
    is_authenticated: true,
    is_service: isService,
    service_name: input.service_name,
    roles: effectiveRoles,
    tenant_id: input.tenant_id || null,
    accessible_scope_ids: input.accessible_scope_ids || ['00000000-0000-0000-0000-000000000001'],
    max_classification_rank: maxClearance,
    grants,
  };
}
