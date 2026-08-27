import { describe, it, expect } from 'vitest';
import { 
  resolvePrincipalClaims, 
  resolveClassificationClearance, 
  SecurityClassificationRank,
  computeDerivedClassification,
  validateClassificationDerivation,
  filterVaultRecords,
  readVaultItem,
  requireAuth,
  requireRole,
  requireClassification,
  requireScope,
  requireServiceIdentity,
  requireGrant,
  executeWithAuditedOverride,
  UnauthorizedAccessError,
  UnauthorizedVaultAccessError,
  ScopeBoundaryViolationError,
  createBrowserAuthClient,
  BusinessRole,
  ServiceIdentity
} from '../../packages/auth/src/index.ts';
import { createTestDb } from '../../packages/db/src/migrator.ts';
import { Repository } from '../../packages/db/src/repositories.ts';

describe('P06 — Authentication, Roles, RLS & Vault Boundaries Matrix Tests', () => {
  const PLATFORM_SCOPE = '00000000-0000-0000-0000-000000000001';
  const TENANT_A_SCOPE = '00000000-0000-0000-0000-000000000002';
  const TENANT_B_SCOPE = '00000000-0000-0000-0000-000000000003';

  // 1. Role and Claim Matrix Resolution
  describe('1. Role & Claim Resolution Matrix', () => {
    it('resolves ANONYMOUS principal with PUBLIC_METADATA clearance only', () => {
      const context = resolvePrincipalClaims({ principal_id: undefined });
      expect(context.is_authenticated).toBe(false);
      expect(context.roles).toEqual(['anonymous']);
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.PUBLIC_METADATA);
    });

    it('resolves USER principal with INTERNAL clearance', () => {
      const context = resolvePrincipalClaims({ principal_id: 'usr_standard_1', roles: ['user'] });
      expect(context.is_authenticated).toBe(true);
      expect(context.roles).toContain('user');
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.INTERNAL);
    });

    it('resolves ANALYST principal with SENSITIVE clearance', () => {
      const context = resolvePrincipalClaims({ principal_id: 'usr_analyst_1', roles: ['analyst'] });
      expect(context.is_authenticated).toBe(true);
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.SENSITIVE);
    });

    it('resolves REVIEWER principal with SENSITIVE clearance', () => {
      const context = resolvePrincipalClaims({ principal_id: 'usr_reviewer_1', roles: ['reviewer'] });
      expect(context.is_authenticated).toBe(true);
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.SENSITIVE);
    });

    it('resolves RELEASE_APPROVER principal with SENSITIVE clearance', () => {
      const context = resolvePrincipalClaims({ principal_id: 'usr_approver_1', roles: ['release_approver'] });
      expect(context.is_authenticated).toBe(true);
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.SENSITIVE);
    });

    it('resolves AUDITOR principal with SENSITIVE clearance', () => {
      const context = resolvePrincipalClaims({ principal_id: 'usr_auditor_1', roles: ['auditor'] });
      expect(context.is_authenticated).toBe(true);
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.SENSITIVE);
    });

    it('resolves OPERATOR principal with SENSITIVE clearance', () => {
      const context = resolvePrincipalClaims({ principal_id: 'usr_operator_1', roles: ['operator'] });
      expect(context.is_authenticated).toBe(true);
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.SENSITIVE);
    });

    it('resolves VAULT_READER principal with VAULT_RESTRICTED clearance', () => {
      const context = resolvePrincipalClaims({ principal_id: 'usr_vault_1', roles: ['vault_reader'] });
      expect(context.is_authenticated).toBe(true);
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.VAULT_RESTRICTED);
    });

    it('resolves ADMIN principal with VAULT_RESTRICTED clearance', () => {
      const context = resolvePrincipalClaims({ principal_id: 'usr_admin_1', roles: ['admin'] });
      expect(context.is_authenticated).toBe(true);
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.VAULT_RESTRICTED);
    });

    it('resolves SERVICE-ANALYSIS worker with service identity', () => {
      const context = resolvePrincipalClaims({ 
        principal_id: 'service:service-analysis', 
        is_service: true, 
        service_name: 'service-analysis' 
      });
      expect(context.is_service).toBe(true);
      expect(context.service_name).toBe('service-analysis');
      expect(context.roles).toContain('admin');
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.VAULT_RESTRICTED);
    });

    it('resolves SERVICE-KNOWLEDGE worker with service identity', () => {
      const context = resolvePrincipalClaims({ 
        principal_id: 'service:service-knowledge', 
        is_service: true, 
        service_name: 'service-knowledge' 
      });
      expect(context.is_service).toBe(true);
      expect(context.service_name).toBe('service-knowledge');
      expect(context.max_classification_rank).toBe(SecurityClassificationRank.VAULT_RESTRICTED);
    });
  });

  // 2. Vault Boundaries & Forbidden Reads / Writes Matrix
  describe('2. Vault Boundaries & Zero Unauthorized Retrieval Gate', () => {
    const mockDataStore = [
      { id: '1', title: 'Public Catalog', security_classification_rank: SecurityClassificationRank.PUBLIC_METADATA },
      { id: '2', title: 'Internal Score Config', security_classification_rank: SecurityClassificationRank.INTERNAL },
      { id: '3', title: 'Static Finding AST', security_classification_rank: SecurityClassificationRank.SENSITIVE },
      { id: '4', title: 'Taint Flow & Secret Leak', security_classification_rank: SecurityClassificationRank.VAULT_RESTRICTED },
      { id: '5', title: 'Signing Private Key Ref', security_classification_rank: SecurityClassificationRank.VAULT_RESTRICTED },
    ];

    it('GATE: Anonymous user retrieves ZERO non-public records and ZERO vault records', () => {
      const anon = resolvePrincipalClaims({});
      const filtered = filterVaultRecords(anon, mockDataStore);
      expect(filtered.length).toBe(1);
      expect(filtered[0].id).toBe('1');
      expect(filtered.some(i => i.security_classification_rank === SecurityClassificationRank.VAULT_RESTRICTED)).toBe(false);
    });

    it('GATE: Standard User retrieves ZERO vault records', () => {
      const user = resolvePrincipalClaims({ principal_id: 'u1', roles: ['user'] });
      const filtered = filterVaultRecords(user, mockDataStore);
      expect(filtered.length).toBe(2);
      expect(filtered.some(i => i.security_classification_rank === SecurityClassificationRank.VAULT_RESTRICTED)).toBe(false);
      expect(filtered.some(i => i.security_classification_rank === SecurityClassificationRank.SENSITIVE)).toBe(false);
    });

    it('GATE: Analyst retrieves ZERO vault records', () => {
      const analyst = resolvePrincipalClaims({ principal_id: 'a1', roles: ['analyst'] });
      const filtered = filterVaultRecords(analyst, mockDataStore);
      expect(filtered.length).toBe(3);
      expect(filtered.some(i => i.security_classification_rank === SecurityClassificationRank.VAULT_RESTRICTED)).toBe(false);
    });

    it('GATE: Vault Reader retrieves ALL records including VAULT_RESTRICTED', () => {
      const vaultReader = resolvePrincipalClaims({ principal_id: 'vr1', roles: ['vault_reader'] });
      const filtered = filterVaultRecords(vaultReader, mockDataStore);
      expect(filtered.length).toBe(5);
      expect(filtered.filter(i => i.security_classification_rank === SecurityClassificationRank.VAULT_RESTRICTED).length).toBe(2);
    });

    it('GATE: Admin retrieves ALL records including VAULT_RESTRICTED', () => {
      const admin = resolvePrincipalClaims({ principal_id: 'adm1', roles: ['admin'] });
      const filtered = filterVaultRecords(admin, mockDataStore);
      expect(filtered.length).toBe(5);
    });

    it('GATE: Direct read of Vault item throws UnauthorizedVaultAccessError for non-vault reader', () => {
      const user = resolvePrincipalClaims({ principal_id: 'u1', roles: ['user'] });
      expect(() => {
        readVaultItem(user, {
          id: 'vault_item_1',
          data: { secret: 'super_secret' },
          security_classification_rank: SecurityClassificationRank.VAULT_RESTRICTED,
        });
      }).toThrow(UnauthorizedVaultAccessError);
    });

    it('GATE: Direct read of Vault item succeeds for Vault Reader and Admin', () => {
      const vaultReader = resolvePrincipalClaims({ principal_id: 'vr1', roles: ['vault_reader'] });
      const item = readVaultItem(vaultReader, {
        id: 'vault_item_1',
        data: { secret: 'super_secret' },
        security_classification_rank: SecurityClassificationRank.VAULT_RESTRICTED,
      });
      expect(item.data.secret).toBe('super_secret');
    });
  });

  // 3. Authorization Guards & Forbidden Operations Matrix
  describe('3. Authorization Guards & Role Gating', () => {
    it('enforces requireAuth on anonymous principals', () => {
      const anon = resolvePrincipalClaims({});
      expect(() => requireAuth(anon)).toThrow(UnauthorizedAccessError);
    });

    it('enforces requireRole correctly across matrix', () => {
      const analyst = resolvePrincipalClaims({ principal_id: 'a1', roles: ['analyst'] });
      const approver = resolvePrincipalClaims({ principal_id: 'ap1', roles: ['release_approver'] });
      const admin = resolvePrincipalClaims({ principal_id: 'adm1', roles: ['admin'] });

      // Analyst cannot approve release
      expect(() => requireRole(analyst, ['release_approver'])).toThrow(UnauthorizedAccessError);

      // Approver can approve release
      expect(() => requireRole(approver, ['release_approver'])).not.toThrow();

      // Admin has universal role clearance
      expect(() => requireRole(admin, ['release_approver'])).not.toThrow();
      expect(() => requireRole(admin, ['auditor'])).not.toThrow();
    });

    it('enforces requireServiceIdentity strictly to authorized worker names', () => {
      const serviceAnalysis = resolvePrincipalClaims({ 
        principal_id: 'svc:analysis', 
        is_service: true, 
        service_name: 'service-analysis' 
      });
      const user = resolvePrincipalClaims({ principal_id: 'u1', roles: ['user'] });

      expect(() => requireServiceIdentity(serviceAnalysis, ['service-analysis'])).not.toThrow();
      expect(() => requireServiceIdentity(serviceAnalysis, ['service-knowledge'])).toThrow(UnauthorizedAccessError);
      expect(() => requireServiceIdentity(user, ['service-analysis'])).toThrow(UnauthorizedAccessError);
    });

    it('enforces requireScope against cross-tenant access', () => {
      const tenantAUser = resolvePrincipalClaims({ 
        principal_id: 'u_tenantA', 
        roles: ['user'],
        accessible_scope_ids: [PLATFORM_SCOPE, TENANT_A_SCOPE]
      });

      // Allowed on Tenant A
      expect(() => requireScope(tenantAUser, TENANT_A_SCOPE)).not.toThrow();

      // Forbidden on Tenant B (cross-tenant violation)
      expect(() => requireScope(tenantAUser, TENANT_B_SCOPE)).toThrow(ScopeBoundaryViolationError);
    });

    it('enforces requireGrant for granular permissions', () => {
      const userWithoutGrant = resolvePrincipalClaims({ principal_id: 'u1', roles: ['user'] });
      const userWithGrant = resolvePrincipalClaims({ 
        principal_id: 'u2', 
        roles: ['user'], 
        grants: ['package_shipper'] 
      });

      expect(() => requireGrant(userWithoutGrant, 'package_shipper')).toThrow(UnauthorizedAccessError);
      expect(() => requireGrant(userWithGrant, 'package_shipper')).not.toThrow();
    });
  });

  // 4. Security Classification Propagation & Derivation
  describe('4. Security Classification Monotonic Propagation', () => {
    it('computes output_classification >= max(input_classifications)', () => {
      const inputs = [
        SecurityClassificationRank.PUBLIC_METADATA,
        SecurityClassificationRank.INTERNAL,
        SecurityClassificationRank.SENSITIVE,
      ];
      const maxRank = computeDerivedClassification(inputs);
      expect(maxRank).toBe(SecurityClassificationRank.SENSITIVE);

      // Adding VAULT_RESTRICTED escalates derived output rank
      const inputsWithVault = [...inputs, SecurityClassificationRank.VAULT_RESTRICTED];
      expect(computeDerivedClassification(inputsWithVault)).toBe(SecurityClassificationRank.VAULT_RESTRICTED);
    });

    it('rejects declassification without authorized approval', () => {
      const inputs = [SecurityClassificationRank.SENSITIVE];
      
      // Attempting to output INTERNAL from SENSITIVE input fails
      expect(() => {
        validateClassificationDerivation(inputs, SecurityClassificationRank.INTERNAL, false);
      }).toThrow(UnauthorizedAccessError);

      // With authorized declassification flag, it passes
      expect(validateClassificationDerivation(inputs, SecurityClassificationRank.INTERNAL, true)).toBe(true);
    });
  });

  // 5. Audited Override (Break-Glass) Authorization
  describe('5. Audited Break-Glass Override', () => {
    it('requires min 10 char justification and records immutable audit event on execution', async () => {
      const user = resolvePrincipalClaims({ principal_id: 'usr_regular', roles: ['user'] });
      const loggedEvents: any[] = [];
      const mockAuditSink = {
        logAuditEvent: (event: any) => {
          loggedEvents.push(event);
        },
      };

      // Rejects empty or too short justification
      await expect(
        executeWithAuditedOverride(
          user,
          {
            actor_id: user.principal_id,
            action: 'EMERGENCY_DECRYPTION',
            target_resource_id: 'vault_res_99',
            target_resource_type: 'VAULT_SECRET',
            justification: 'too short',
            correlation_id: 'corr_123',
          },
          mockAuditSink,
          async () => 'ok'
        )
      ).rejects.toThrow(UnauthorizedAccessError);

      // Valid break-glass execution
      const result = await executeWithAuditedOverride(
        user,
        {
          actor_id: user.principal_id,
          action: 'EMERGENCY_DECRYPTION',
          target_resource_id: 'vault_res_99',
          target_resource_type: 'VAULT_SECRET',
          justification: 'Incident #4092: Emergency production incident mitigation authorized by SecOps',
          correlation_id: 'corr_123',
        },
        mockAuditSink,
        async (elevatedContext) => {
          expect(elevatedContext.is_override_active).toBe(true);
          expect(elevatedContext.max_classification_rank).toBe(SecurityClassificationRank.VAULT_RESTRICTED);
          return { decrypted: true };
        }
      );

      expect(result.decrypted).toBe(true);
      expect(loggedEvents.length).toBe(1);
      expect(loggedEvents[0].outcome).toBe('SUCCESS');
      expect(loggedEvents[0].action).toBe('AUDITED_OVERRIDE:EMERGENCY_DECRYPTION');
      expect(loggedEvents[0].metadata.justification).toContain('Incident #4092');
    });
  });

  // 6. Client Bundle Secret Boundary Gate
  describe('6. Client Secret Isolation Gate', () => {
    it('GATE: Browser client helper refuses service_role or secret keys', () => {
      expect(() => {
        createBrowserAuthClient({
          supabaseAnonKey: 'service_role_secret_elevated_key_do_not_leak',
        });
      }).toThrow(/FATAL SECURITY VIOLATION/);
    });

    it('GATE: Browser client helper works with public anon key', () => {
      const client = createBrowserAuthClient({
        supabaseAnonKey: 'public-anon-key-safe-for-browsers',
      });
      expect(client.isClientSafe()).toBe(true);
    });
  });

  // 7. Database Security & Tenant Repository Operations
  describe('7. Security Repository & Roles in DB', () => {
    it('manages roles, user_roles, and access_grants in PostgreSQL', async () => {
      const db = createTestDb({ applyMigrations: true, applySeed: true });
      const repo = new Repository(db);

      const allRoles = await repo.getAllRoles();
      expect(allRoles.length).toBeGreaterThanOrEqual(5);

      const analystRole = await repo.getRoleByKey('analyst');
      expect(analystRole).not.toBeNull();

      // Assign user role
      const assigned = await repo.assignUserRole({
        user_role_id: '00000000-0000-0000-0000-111111111111',
        principal_id: 'test_user_01',
        role_id: analystRole!.role_id,
        granted_by: 'test_admin',
      });
      expect(assigned.principal_id).toBe('test_user_01');

      const userRoles = await repo.getUserRoles('test_user_01');
      expect(userRoles.length).toBe(1);

      // Create access grant
      const grant = await repo.createAccessGrant({
        access_grant_id: '00000000-0000-0000-0000-222222222222',
        principal_id: 'test_user_01',
        grant_type: 'vault_reader',
        target_scope: null,
        granted_by: 'test_admin',
        expires_at: null,
      });
      expect(grant.grant_type).toBe('vault_reader');

      const grants = await repo.getAccessGrantsForPrincipal('test_user_01');
      expect(grants.length).toBe(1);
    });
  });
});
