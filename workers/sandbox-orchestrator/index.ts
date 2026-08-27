/**
 * Sandbox Orchestration Worker Module (P19)
 * Export surface for dynamic sandbox execution, scenarios, telemetry, and evasion detection.
 */

export * from './types.ts';
export * from './providers/sandbox-provider.interface.ts';
export * from './providers/simulated-provider.ts';
export * from './providers/e2b-provider.ts';
export * from './security/secret-sanitizer.ts';
export * from './security/canary-generator.ts';
export * from './security/network-policy.ts';
export * from './scenarios/registry.ts';
export * from './evasion/detector.ts';
export * from './lifecycle/manager.ts';
export * from './engine.ts';

import { SandboxOrchestrationEngine, RunSandboxScenarioOptions } from './engine.ts';
import { DynamicSandboxRunResult } from './types.ts';

export interface DynamicSandboxJob {
  artifactId: string;
  scenarioId?: string;
  options?: RunSandboxScenarioOptions;
}

export async function runDynamicSandboxJob(job: DynamicSandboxJob): Promise<DynamicSandboxRunResult> {
  return SandboxOrchestrationEngine.runScenario({
    artifactId: job.artifactId,
    scenarioId: job.scenarioId,
    ...(job.options || {}),
  });
}
