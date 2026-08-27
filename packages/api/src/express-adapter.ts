import { Request, Response, Router } from 'express';
import { ApplicationApiRouter, ApiRequestContext } from './router.ts';

export function createApiExpressRouter(apiRouter: ApplicationApiRouter = new ApplicationApiRouter()): Router {
  const router = Router();

  const toRequestContext = (req: Request): ApiRequestContext => ({
    headers: req.headers,
    params: req.params,
    query: req.query,
    body: req.body,
    requestId: (req.headers['x-request-id'] as string) || `req-${crypto.randomUUID()}`,
    url: req.originalUrl || req.url,
    method: req.method,
  });

  const sendResponse = (res: Response, result: { statusCode: number; body: any; headers?: Record<string, string> }) => {
    if (result.headers) {
      for (const [key, val] of Object.entries(result.headers)) {
        res.setHeader(key, val);
      }
    }
    res.status(result.statusCode).json(result.body);
  };

  // System & Health
  router.get('/health', async (req, res) => {
    const result = await apiRouter.getHealth(toRequestContext(req));
    sendResponse(res, result);
  });

  router.get('/ready', async (req, res) => {
    const result = await apiRouter.getReadiness(toRequestContext(req));
    sendResponse(res, result);
  });

  router.get('/openapi.json', async (req, res) => {
    const result = await apiRouter.getOpenApiSpec(toRequestContext(req));
    sendResponse(res, result);
  });

  // Agent Registry
  router.get('/agents', async (req, res) => {
    const result = await apiRouter.listAgents(toRequestContext(req));
    sendResponse(res, result);
  });

  router.post('/agents', async (req, res) => {
    const result = await apiRouter.createAgent(toRequestContext(req));
    sendResponse(res, result);
  });

  router.get('/agents/:agentId', async (req, res) => {
    const result = await apiRouter.getAgent(toRequestContext(req));
    sendResponse(res, result);
  });

  router.post('/agents/:agentId/versions', async (req, res) => {
    const result = await apiRouter.registerAgentVersion(toRequestContext(req));
    sendResponse(res, result);
  });

  router.get('/agents/:agentId/versions/:versionId', async (req, res) => {
    const result = await apiRouter.getAgentVersion(toRequestContext(req));
    sendResponse(res, result);
  });

  // Analysis Runs
  router.post('/analysis/runs', async (req, res) => {
    const result = await apiRouter.createAnalysisRun(toRequestContext(req));
    sendResponse(res, result);
  });

  router.get('/analysis/runs/:runId', async (req, res) => {
    const result = await apiRouter.getAnalysisRun(toRequestContext(req));
    sendResponse(res, result);
  });

  router.get('/analysis/runs/:runId/findings', async (req, res) => {
    const result = await apiRouter.getAnalysisFindings(toRequestContext(req));
    sendResponse(res, result);
  });

  // Policy & Approvals
  router.post('/policy/evaluations', async (req, res) => {
    const result = await apiRouter.evaluatePolicyGate(toRequestContext(req));
    sendResponse(res, result);
  });

  router.post('/approvals', async (req, res) => {
    const result = await apiRouter.submitApproval(toRequestContext(req));
    sendResponse(res, result);
  });

  // Queues & DLQ
  router.get('/queues', async (req, res) => {
    const result = await apiRouter.listQueues(toRequestContext(req));
    sendResponse(res, result);
  });

  router.post('/dlq/jobs/:dlqId/replay', async (req, res) => {
    const result = await apiRouter.replayDlqJob(toRequestContext(req));
    sendResponse(res, result);
  });

  return router;
}
