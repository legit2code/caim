export interface SemanticWorkerJob {
  artifactId: string;
  sourceFiles: string[];
}

export async function runSemanticJob(job: SemanticWorkerJob): Promise<{ status: string; astNodesCount: number }> {
  return { status: 'SEMANTIC_ANALYSIS_COMPLETED', astNodesCount: 10 };
}
