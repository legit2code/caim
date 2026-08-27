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
