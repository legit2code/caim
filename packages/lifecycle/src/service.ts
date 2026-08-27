import { LifecycleEntityKind, STATE_MACHINE_VERSION } from './registry.ts';
import { LifecycleStateEngine, TransitionRequest } from './engine.ts';
import { StateProjector, LifecycleTransitionRecord, StateProjectionResult } from './projection.ts';
import { StateTransitionConflictError } from './errors.ts';

function generateUuid(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  // Fallback UUID v4
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

export interface DatabaseClientLike {
  query: (sql: string, params?: any[]) => Promise<{ rows: any[]; rowCount?: number }>;
}

export interface TransitionStateOptions {
  readonly stateTransitionId?: string;
  readonly dbClient?: DatabaseClientLike;
  readonly expectedFromState?: string | null;
  readonly metadata?: Record<string, unknown>;
}

export interface TransitionExecutionResult {
  readonly transitionRecord: LifecycleTransitionRecord;
  readonly projection: StateProjectionResult;
  readonly stateMachineVersion: string;
}

export class LifecycleStateMachineService {
  /**
   * Authoritative entrypoint to transition lifecycle state.
   * Enforces: "No code path may mutate lifecycle state without recording a transition."
   */
  public static async transitionState(
    request: TransitionRequest,
    options: TransitionStateOptions = {}
  ): Promise<TransitionExecutionResult> {
    const { entityRefId, entityKind, fromState, toState, transitionReason, actorRef } = request;

    // 1. If dbClient is provided and expectedFromState was specified (or check current db state), verify concurrency
    if (options.dbClient && options.expectedFromState !== undefined) {
      if (options.expectedFromState !== fromState) {
        throw new StateTransitionConflictError({
          entityKind,
          entityRefId,
          expectedFromState: options.expectedFromState,
          actualCurrentState: fromState,
        });
      }
    }

    // 2. Validate legal transition via authoritative state engine
    await LifecycleStateEngine.assertLegalTransition(request);

    // 3. Build immutable transition record
    const transitionRecord: LifecycleTransitionRecord = {
      state_transition_id: options.stateTransitionId || generateUuid(),
      entity_ref_id: entityRefId,
      from_state: fromState,
      to_state: toState,
      transition_reason: transitionReason || `Transitioned to ${toState}`,
      actor_ref: actorRef,
      occurred_at: new Date().toISOString(),
      state_machine_version: STATE_MACHINE_VERSION,
      metadata: options.metadata || {},
    };

    // 4. If database client is provided, persist atomically to ops.lifecycle_state_transitions & update entity
    if (options.dbClient) {
      // 4a. Append to transitions ledger
      await options.dbClient.query(`
        INSERT INTO ops.lifecycle_state_transitions (
          state_transition_id, entity_ref_id, from_state, to_state, transition_reason, actor_ref
        )
        VALUES ($1, $2, $3, $4, $5, $6);
      `, [
        transitionRecord.state_transition_id,
        transitionRecord.entity_ref_id,
        transitionRecord.from_state || null,
        transitionRecord.to_state,
        transitionRecord.transition_reason,
        transitionRecord.actor_ref || null,
      ]);

      // 4b. Mutate current status on entity table
      await this.updateEntityStatusInDb(options.dbClient, entityKind, entityRefId, toState);
    }

    // 5. Build projection
    const projection = StateProjector.project(entityKind, [transitionRecord]);

    return {
      transitionRecord,
      projection,
      stateMachineVersion: STATE_MACHINE_VERSION,
    };
  }

  /**
   * Internal helper to update the entity table's status column synchronously with the transition.
   */
  private static async updateEntityStatusInDb(
    client: DatabaseClientLike,
    entityKind: LifecycleEntityKind,
    entityRefId: string,
    toState: string
  ): Promise<void> {
    switch (entityKind) {
      case 'ANALYSIS_RUN':
        await client.query(`
          UPDATE analysis.analysis_runs
          SET status = $2, completed_at = CASE WHEN $2 IN ('COMPLETED', 'FAILED', 'CANCELLED') THEN now() ELSE completed_at END
          WHERE analysis_run_id = $1;
        `, [entityRefId, toState]);
        break;

      case 'ANALYSIS_STAGE_RUN':
        await client.query(`
          UPDATE analysis.analysis_stage_runs
          SET status = $2, completed_at = CASE WHEN $2 IN ('COMPLETED', 'FAILED', 'SKIPPED', 'TIMED_OUT', 'CANCELLED') THEN now() ELSE completed_at END
          WHERE stage_run_id = $1;
        `, [entityRefId, toState]);
        break;

      case 'VALIDATION_RUN':
        await client.query(`
          UPDATE lifecycle.validation_runs
          SET status = $2
          WHERE validation_run_id = $1;
        `, [entityRefId, toState]);
        break;

      case 'MODIFICATION_WORKSPACE':
        await client.query(`
          UPDATE lifecycle.modification_workspaces
          SET status = $2
          WHERE modification_workspace_id = $1;
        `, [entityRefId, toState]);
        break;

      case 'PACKAGE':
        await client.query(`
          UPDATE lifecycle.packages
          SET status = $2
          WHERE package_id = $1;
        `, [entityRefId, toState]);
        break;

      case 'SHIPMENT':
        await client.query(`
          UPDATE lifecycle.shipments
          SET status = $2
          WHERE shipment_id = $1;
        `, [entityRefId, toState]);
        break;

      case 'WORKFLOW_RUN':
        await client.query(`
          UPDATE ops.workflow_runs
          SET status = $2, completed_at = CASE WHEN $2 IN ('COMPLETED', 'FAILED', 'CANCELLED') THEN now() ELSE completed_at END
          WHERE workflow_run_id = $1;
        `, [entityRefId, toState]);
        break;

      case 'JOB':
        await client.query(`
          UPDATE ops.jobs
          SET status = $2, completed_at = CASE WHEN $2 IN ('COMPLETED', 'FAILED', 'DEAD_LETTER', 'CANCELLED') THEN now() ELSE completed_at END
          WHERE job_id = $1;
        `, [entityRefId, toState]);
        break;

      case 'AGENT_VERSION':
      default:
        // No status column on base agent_versions; status tracked via lifecycle_state_transitions
        break;
    }
  }

  /**
   * Projects the authoritative current state and history metrics for an entity given all its historical transitions.
   */
  public static projectEntityHistory(
    entityKind: LifecycleEntityKind,
    transitions: LifecycleTransitionRecord[]
  ): StateProjectionResult {
    return StateProjector.project(entityKind, transitions);
  }

  /**
   * Helper to execute a genesis/creation transition.
   */
  public static async createGenesisTransition(
    entityKind: LifecycleEntityKind,
    entityRefId: string,
    initialState: string,
    actorRef: string,
    correlationId: string,
    reason: string = 'Initial creation genesis transition',
    options: TransitionStateOptions = {}
  ): Promise<TransitionExecutionResult> {
    return this.transitionState({
      entityRefId,
      entityKind,
      fromState: null,
      toState: initialState,
      action: 'INITIALIZE',
      transitionReason: reason,
      actorRef,
      correlationId,
    }, options);
  }
}
