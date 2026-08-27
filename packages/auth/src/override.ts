import { 
  PrincipalContext, 
  AuditedOverrideRequest, 
  SecurityClassificationRank, 
  UnauthorizedAccessError 
} from './types.ts';

export interface AuditEventSink {
  logAuditEvent(event: {
    principal_or_service_id: string;
    action: string;
    target_entity_ref_id?: string | null;
    outcome: 'SUCCESS' | 'DENIED' | 'ERROR';
    correlation_id: string;
    metadata: Record<string, any>;
  }): Promise<any> | any;
}

/**
 * Executes a privileged / break-glass operation with mandatory audit logging and justification.
 * (Architecture V2.0.1 Document 13)
 */
export async function executeWithAuditedOverride<T>(
  context: PrincipalContext,
  request: AuditedOverrideRequest,
  auditSink: AuditEventSink,
  operation: (elevatedContext: PrincipalContext) => Promise<T> | T
): Promise<T> {
  // Validate justification
  if (!request.justification || request.justification.trim().length < 10) {
    throw new UnauthorizedAccessError('Break-glass override rejected: A valid justification (min 10 chars) is required.');
  }

  const elevatedContext: PrincipalContext = {
    ...context,
    is_override_active: true,
    override_justification: request.justification,
    correlation_id: request.correlation_id,
    max_classification_rank: SecurityClassificationRank.VAULT_RESTRICTED,
  };

  try {
    const result = await operation(elevatedContext);

    // Record immutable audit event
    await auditSink.logAuditEvent({
      principal_or_service_id: context.principal_id,
      action: `AUDITED_OVERRIDE:${request.action}`,
      target_entity_ref_id: request.target_resource_id,
      outcome: 'SUCCESS',
      correlation_id: request.correlation_id,
      metadata: {
        actor_id: request.actor_id,
        justification: request.justification,
        target_resource_type: request.target_resource_type,
        target_resource_id: request.target_resource_id,
        timestamp: new Date().toISOString(),
        ...request.metadata,
      },
    });

    return result;
  } catch (error: any) {
    await auditSink.logAuditEvent({
      principal_or_service_id: context.principal_id,
      action: `AUDITED_OVERRIDE:${request.action}`,
      target_entity_ref_id: request.target_resource_id,
      outcome: 'ERROR',
      correlation_id: request.correlation_id,
      metadata: {
        actor_id: request.actor_id,
        justification: request.justification,
        error: error?.message,
        timestamp: new Date().toISOString(),
      },
    });
    throw error;
  }
}
