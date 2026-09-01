/**
 * Autonomous Discovery & Auto-Ingestion Pipeline Worker (Architecture V2.0.1)
 *
 * Continuously polls all seven registered source adapters (GitHub, GitLab, PyPI, npm,
 * Hugging Face, Docker Hub, Codeberg) using broad topic and keyword criteria.
 * Automatically ingests new candidates as CanonicalAgents, runs StaticAnalysisEngine
 * and DecisionOrchestrationEngine, and computes the 3-good/3-bad use-case matrix
 * so newly discovered agents show up in the Library pre-analyzed.
 */

import { DiscoveryEngine } from './discovery-engine.ts';
import { SourceAdapterRegistry } from './registry.ts';
import { DiscoveryCandidate } from './types.ts';

export interface AutonomousWorkerConfig {
  intervalMs?: number; // e.g. every 60 minutes, or 5 minutes in dev/demo
  sourceTypes?: string[];
  queries?: string[];
  autoAnalyze?: boolean;
}

export interface LibraryAgentSummary {
  agent_id: string;
  agent_version_id: string;
  canonical_name: string;
  version_label: string;
  source_type: string;
  source_locator: string;
  author: string;
  description: string;
  framework: string;
  security_classification: string;
  discovered_at: string;
  analysis_status: 'PRE_ANALYZED' | 'ANALYSIS_COMPLETE' | 'PENDING' | 'FAILED';
  risk_band: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  overall_score: number;
  policy_outcome: 'ALLOW' | 'CONDITIONAL' | 'BLOCK';
  good_use_cases: Array<{ title: string; rationale: string; risk_level: string }>;
  bad_use_cases: Array<{ title: string; rationale: string; risk_level: string }>;
  findings_count: number;
  evidence_count: number;
  capabilities: string[];
}

export class AutonomousDiscoveryWorker {
  private timer: NodeJS.Timeout | null = null;
  private isRunning: boolean = false;
  private lastRunAt: string | null = null;
  private nextRunAt: string | null = null;
  private lastRunDurationMs: number = 0;
  private totalDiscoveredCount: number = 0;
  private totalAnalyzedCount: number = 0;
  private lastError: string | null = null;
  private analyzedLibrary: Map<string, LibraryAgentSummary> = new Map();

  private defaultQueries = [
    'agent',
    'autonomous agent',
    'llm tool',
    'langchain agent',
    'autogen assistant',
    'crewai task',
    'semantic kernel tool'
  ];

  constructor(
    private discoveryEngine: DiscoveryEngine,
    private sourceRegistry: SourceAdapterRegistry,
    private onIngestAndAnalyze?: (candidate: DiscoveryCandidate) => Promise<LibraryAgentSummary | null>
  ) {}

  public start(intervalMs: number = 10 * 60 * 1000): void {
    if (this.timer) {
      clearInterval(this.timer);
    }
    this.nextRunAt = new Date(Date.now() + intervalMs).toISOString();
    this.timer = setInterval(() => {
      this.runDiscoveryCycle().catch(err => {
        console.error('[AutonomousDiscoveryWorker] Interval cycle error:', err);
      });
    }, intervalMs);
    console.log(`[AutonomousDiscoveryWorker] Started autonomous scheduler with interval ${intervalMs}ms`);
  }

  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.nextRunAt = null;
    console.log('[AutonomousDiscoveryWorker] Stopped autonomous scheduler');
  }

  public getStatus() {
    return {
      active: this.timer !== null,
      is_running_scan: this.isRunning,
      last_run_at: this.lastRunAt,
      next_run_at: this.nextRunAt,
      last_run_duration_ms: this.lastRunDurationMs,
      total_discovered: this.totalDiscoveredCount,
      total_analyzed: this.totalAnalyzedCount,
      library_size: this.analyzedLibrary.size,
      last_error: this.lastError,
      registered_sources: this.sourceRegistry.getAll().map(a => a.sourceType),
    };
  }

  public getLibrary(): LibraryAgentSummary[] {
    return Array.from(this.analyzedLibrary.values());
  }

  public addPreAnalyzedAgent(agent: LibraryAgentSummary): void {
    this.analyzedLibrary.set(agent.agent_id, agent);
  }

  /**
   * Executes a complete discovery cycle across all registered sources.
   */
  public async runDiscoveryCycle(customQueries?: string[]): Promise<{
    candidates_found: number;
    newly_analyzed: number;
    sources_scanned: string[];
    duration_ms: number;
  }> {
    if (this.isRunning) {
      return {
        candidates_found: 0,
        newly_analyzed: 0,
        sources_scanned: [],
        duration_ms: 0,
      };
    }

    this.isRunning = true;
    this.lastError = null;
    const startTime = Date.now();
    const queriesToRun = customQueries && customQueries.length > 0 ? customQueries : this.defaultQueries;
    const allRegisteredSources = this.sourceRegistry.getAll().map(s => s.sourceType);
    let totalCandidatesInCycle = 0;
    let newlyAnalyzedInCycle = 0;

    try {
      // Rotate queries or scan top search terms
      for (const query of queriesToRun.slice(0, 3)) {
        const report = await this.discoveryEngine.runDiscovery({
          criteria: {
            query,
            tags: ['autonomous', 'agent', 'llm', 'workflow'],
          },
          sourceTypes: allRegisteredSources,
          maxPagesPerSource: 1,
          maxCandidatesTotal: 15,
          correlationId: `auto-cron-${Date.now().toString(36)}`,
        });

        totalCandidatesInCycle += report.totalCandidates;
        this.totalDiscoveredCount += report.totalCandidates;

        const candidates = (report.packages || []).map(p => p.candidate);
        for (const candidate of candidates) {
          const key = (candidate.display_name || candidate.source_locator).toLowerCase();
          if (!this.analyzedLibrary.has(key)) {
            if (this.onIngestAndAnalyze) {
              try {
                const analyzedSummary = await this.onIngestAndAnalyze(candidate);
                if (analyzedSummary) {
                  this.analyzedLibrary.set(key, analyzedSummary);
                  this.analyzedLibrary.set(analyzedSummary.agent_id, analyzedSummary);
                  this.totalAnalyzedCount++;
                  newlyAnalyzedInCycle++;
                }
              } catch (analyzeErr: any) {
                console.warn(`[AutonomousDiscoveryWorker] Ingestion/Analysis error for ${candidate.display_name}:`, analyzeErr.message);
              }
            }
          }
        }
      }

      this.lastRunAt = new Date().toISOString();
      this.lastRunDurationMs = Date.now() - startTime;
      return {
        candidates_found: totalCandidatesInCycle,
        newly_analyzed: newlyAnalyzedInCycle,
        sources_scanned: allRegisteredSources,
        duration_ms: this.lastRunDurationMs,
      };
    } catch (err: any) {
      this.lastError = err.message || 'Discovery cycle failed';
      console.error('[AutonomousDiscoveryWorker] Error during discovery cycle:', err);
      throw err;
    } finally {
      this.isRunning = false;
    }
  }
}
