import { 
  BusinessRole, 
  PrincipalContext, 
  SecurityClassificationRank, 
  ServiceIdentity, 
  UnauthorizedAccessError, 
  UnauthorizedVaultAccessError, 
  ScopeBoundaryViolationError 
} from './types.ts';
import { isAuthorizedForVault } from './vault.ts';

export function requireAuth(context: PrincipalContext): void {
  if (!context.is_authenticated) {
    throw new UnauthorizedAccessError('Authentication required: principal is anonymous.');
  }
}

export function requireRole(context: PrincipalContext, allowedRoles: BusinessRole[]): void {
  if (context.is_override_active || context.roles.includes('admin')) {
    return;
  }
  const hasRole = allowedRoles.some(r => context.roles.includes(r));
  if (!hasRole) {
    throw new UnauthorizedAccessError(
      `Role authorization failed: principal '${context.principal_id}' lacks required role (${allowedRoles.join(', ')}). Has: ${context.roles.join(', ')}`
    );
  }
}

export function requireClassification(context: PrincipalContext, requiredRank: SecurityClassificationRank): void {
  if (context.is_override_active) {
    return;
  }
  if (requiredRank >= SecurityClassificationRank.VAULT_RESTRICTED && !isAuthorizedForVault(context)) {
    throw new UnauthorizedVaultAccessError(
      `Vault boundary violation: principal '${context.principal_id}' cannot access VAULT_RESTRICTED records.`
    );
  }
  if (context.max_classification_rank < requiredRank) {
    throw new UnauthorizedAccessError(
      `Insufficient security clearance: principal rank is ${context.max_classification_rank}, required rank is ${requiredRank}.`
    );
  }
}

export function requireScope(context: PrincipalContext, targetScopeId: string): void {
  if (context.is_override_active || context.roles.includes('admin')) {
    return;
  }
  if (!context.accessible_scope_ids.includes(targetScopeId)) {
    throw new ScopeBoundaryViolationError(
      `Tenant/Scope violation: principal '${context.principal_id}' has no grant for scope '${targetScopeId}'.`
    );
  }
}

export function requireServiceIdentity(context: PrincipalContext, allowedServices: ServiceIdentity[]): void {
  if (context.is_override_active) {
    return;
  }
  if (!context.is_service || !context.service_name || !allowedServices.includes(context.service_name)) {
    throw new UnauthorizedAccessError(
      `Service identity violation: caller is not an authorized backend worker (${allowedServices.join(', ')}).`
    );
  }
}

export function requireGrant(context: PrincipalContext, grantType: string): void {
  if (context.is_override_active || context.roles.includes('admin')) {
    return;
  }
  if (!context.grants.includes(grantType)) {
    throw new UnauthorizedAccessError(
      `Access grant missing: principal '${context.principal_id}' lacks grant '${grantType}'.`
    );
  }
}

/**
 * Dedicated per-principal capability grant check (NON-ROLE-BASED).
 * Admin role alone does NOT confer capability access; must have an active grant row.
 */
export async function requireCapabilityGrant(
  context: PrincipalContext,
  capabilityKey: string | string[],
  options: {
    techniqueCategory?: string;
    grantService?: { checkComposerAccess: (id: string, cat?: string) => Promise<{ allowed: boolean; reason?: string }> };
  } = {}
): Promise<void> {
  if (!context.is_authenticated || !context.principal_id || context.principal_id === 'anonymous') {
    throw new UnauthorizedAccessError('Authentication required: principal is anonymous.');
  }

  // Capability grants are strictly per-principal and NEVER implicitly granted by admin role alone
  const { CapabilityGrantService } = await import('./capability.ts');
  const service = options.grantService || new CapabilityGrantService();

  const keys = Array.isArray(capabilityKey) ? capabilityKey : [capabilityKey];

  // If checking composer capability specifically
  if (keys.includes('composer:full_access') || keys.includes('composer:restricted_access')) {
    const access = await (service as any).checkComposerAccess(context.principal_id, options.techniqueCategory);
    if (!access.allowed) {
      throw new UnauthorizedAccessError(
        access.reason || `Principal '${context.principal_id}' lacks active capability grant for ${keys.join(' or ')}.`
      );
    }
    return;
  }

  // Generic capability key check
  const activeGrants = await (service as any).getActiveGrantsForPrincipal(context.principal_id);
  const hasKey = activeGrants.some((g: any) => keys.includes(g.capability_key));
  if (!hasKey) {
    throw new UnauthorizedAccessError(
      `Principal '${context.principal_id}' lacks active restricted capability grant for '${keys.join(', ')}'.`
    );
  }
}
