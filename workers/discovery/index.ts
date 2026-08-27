export interface DiscoveryWorkerJob {
  sourceId: string;
  sourceType: 'GIT_REPO' | 'HUGGINGFACE_MODEL' | 'WEB_PACKAGE' | 'DIRECT_UPLOAD';
  targetUrl: string;
}

export async function runDiscoveryJob(job: DiscoveryWorkerJob): Promise<{ status: string; artifactsCount: number }> {
  return { status: 'DISCOVERY_COMPLETED', artifactsCount: 1 };
}
