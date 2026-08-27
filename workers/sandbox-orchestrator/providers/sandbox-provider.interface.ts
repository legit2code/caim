/**
 * Sandbox Provider Interface
 * Standard abstraction for isolated execution providers (E2B, Simulated Container, Isolated VM).
 */

import { 
  SandboxCommand, 
  SandboxExecutionResult, 
  ResourceQuota, 
  NetworkPolicy, 
  NonfunctionalCanary, 
  TeardownSummary, 
  RuntimeEvent 
} from '../types.ts';

export interface SandboxSessionOptions {
  sessionId: string;
  scenarioId: string;
  scenarioVersion: string;
  resourceQuota: ResourceQuota;
  networkPolicy: NetworkPolicy;
  canaries: NonfunctionalCanary[];
  envVars: Record<string, string>;
  files: Record<string, string>;
}

export interface ISandboxProvider {
  readonly providerType: 'E2B' | 'SIMULATED' | 'DOCKER_ISOLATED';
  
  provision(options: SandboxSessionOptions): Promise<string>;
  
  writeFile(sessionId: string, path: string, content: string): Promise<void>;
  
  readFile(sessionId: string, path: string): Promise<string>;
  
  executeCommand(sessionId: string, command: SandboxCommand): Promise<SandboxExecutionResult>;
  
  collectRuntimeEvents(sessionId: string): Promise<RuntimeEvent[]>;
  
  destroy(sessionId: string): Promise<TeardownSummary>;
}
