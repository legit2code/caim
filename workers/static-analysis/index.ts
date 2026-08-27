/**
 * Static Analysis Worker & Engine Entrypoint
 * P15 — Static Analysis & Control Flow
 */

import { StaticAnalysisJobInput, StaticAnalysisReport } from './types.ts';
import { StaticAnalysisEngine } from './engine.ts';

export * from './types.ts';
export * from './file-selector.ts';
export * from './symbol-graph.ts';
export * from './call-graph.ts';
export * from './cfg-builder.ts';
export * from './rules/catalog.ts';
export * from './rules/evaluator.ts';
export * from './taint/index.ts';
export * from './engine.ts';

export interface StaticAnalysisJob {
  artifactId: string;
  files?: Array<{ path: string; content: string }>;
  entrypoints?: string[];
  pipelineRunId?: string;
  customMetadata?: Record<string, unknown>;
}

export async function runStaticAnalysisJob(job: StaticAnalysisJob): Promise<StaticAnalysisReport> {
  const files = job.files || [
    {
      path: 'index.ts',
      content: `// Sample entrypoint\nexport function main() { console.log("Ready"); }`,
    }
  ];

  const report = StaticAnalysisEngine.analyze({
    artifactId: job.artifactId,
    files,
    entrypoints: job.entrypoints,
    pipelineRunId: job.pipelineRunId,
    customMetadata: job.customMetadata,
  });

  return report;
}
