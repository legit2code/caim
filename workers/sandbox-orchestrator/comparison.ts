/**
 * Static vs Dynamic Analysis Comparator (P19)
 * Correlates static AST/CFG/Taint findings against live dynamic runtime events,
 * identifying confirmed predictions, dormant code paths, and runtime evasion divergences.
 */

import { DynamicSandboxRunResult, RuntimeEvent } from './types.ts';
import { StaticFinding, StaticAnalysisReport } from '../static-analysis/types.ts';

export interface StaticDynamicFindingMatch {
  finding_id: string;
  rule_id: string;
  category: string;
  severity: string;
  static_prediction: string;
  dynamic_evidence: {
    matched_event_ids: string[];
    summary: string;
    events: RuntimeEvent[];
  };
  concordance: 'CONFIRMED' | 'PARTIAL' | 'CONDITIONAL';
}

export interface UntriggeredStaticFinding {
  finding_id: string;
  rule_id: string;
  category: string;
  severity: string;
  predicted_behavior: string;
  reason_not_triggered: 'DORMANT_BRANCH' | 'EVASION_SUPPRESSED' | 'TEST_INPUT_LIMITED' | 'GUARD_PREVENTED';
}

export interface UnpredictedDynamicBehavior {
  category: string;
  severity: string;
  observed_action: string;
  event_ids: string[];
  description: string;
  possible_cause: 'DYNAMIC_CODE_EVAL' | 'RUNTIME_EVASION' | 'ENVIRONMENT_AWARENESS' | 'CANARY_HARVEST';
}

export interface EvasionDivergence {
  evasion_type: string;
  detected_at_runtime: boolean;
  static_risk_prediction: string;
  divergence_detail: string;
}

export interface StaticDynamicComparisonReport {
  comparison_id: string;
  artifact_id: string;
  timestamp: string;
  summary: {
    total_static_findings: number;
    total_dynamic_events: number;
    confirmed_matches_count: number;
    untriggered_static_count: number;
    unpredicted_dynamic_count: number;
    evasion_divergences_count: number;
    overall_concordance_rate: number; // 0.0 - 1.0
    risk_assessment_delta: 'ELEVATED_BY_DYNAMIC' | 'CONFIRMED_HIGH' | 'CONCORDANT_BENIGN' | 'INDETERMINATE_EVASION';
  };
  confirmed_matches: StaticDynamicFindingMatch[];
  untriggered_static_findings: UntriggeredStaticFinding[];
  unpredicted_dynamic_behaviors: UnpredictedDynamicBehavior[];
  evasion_divergences: EvasionDivergence[];
  narrative_report: string;
}

export class StaticDynamicComparator {
  /**
   * Compares static analysis findings against dynamic sandbox execution telemetry.
   */
  public static compare(
    staticInput: StaticFinding[] | StaticAnalysisReport,
    dynamicResult: DynamicSandboxRunResult
  ): StaticDynamicComparisonReport {
    const comparisonId = `cmp-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const timestamp = new Date().toISOString();
    const artifactId = dynamicResult.artifact_id || 'unknown-artifact';

    const staticFindings: StaticFinding[] = Array.isArray(staticInput) 
      ? staticInput 
      : (staticInput.findings || []);

    const dynamicEvents = dynamicResult.runtime_events || [];
    const confirmedMatches: StaticDynamicFindingMatch[] = [];
    const untriggeredFindings: UntriggeredStaticFinding[] = [];
    const matchedEventIds = new Set<string>();

    // 1. Match static findings against dynamic events
    for (const finding of staticFindings) {
      const relevantEvents: RuntimeEvent[] = [];

      switch (finding.category) {
        case 'NETWORK': {
          const netEvents = dynamicEvents.filter(e => e.category === 'NETWORK' || e.action.includes('EGRESS') || e.action.includes('HTTP'));
          relevantEvents.push(...netEvents);
          break;
        }
        case 'FILESYSTEM': {
          const fsEvents = dynamicEvents.filter(e => e.category === 'FILESYSTEM' || e.action.includes('FILE') || e.action.includes('PERSIST'));
          relevantEvents.push(...fsEvents);
          break;
        }
        case 'PROCESS_EXECUTION': {
          const procEvents = dynamicEvents.filter(e => e.category === 'PROCESS' || e.category === 'TOOL' || e.action.includes('PROCESS'));
          relevantEvents.push(...procEvents);
          break;
        }
        case 'CREDENTIAL_ACCESS': {
          const credEvents = dynamicEvents.filter(e => e.category === 'CANARY' || e.action.includes('CANARY') || e.action.includes('KEY'));
          relevantEvents.push(...credEvents);
          break;
        }
        case 'CONTROL_FLOW_ANOMALY':
        case 'UNSUPPORTED_SYNTAX': {
          const secEvents = dynamicEvents.filter(e => e.category === 'SECURITY' || e.category === 'ENVIRONMENT' || e.action.includes('EVASION') || e.action.includes('FINGERPRINT'));
          relevantEvents.push(...secEvents);
          break;
        }
        default: {
          const genericEvents = dynamicEvents.filter(e => e.category === 'SECURITY' || e.status === 'FLAGGED');
          relevantEvents.push(...genericEvents);
          break;
        }
      }

      if (relevantEvents.length > 0) {
        for (const ev of relevantEvents) {
          matchedEventIds.add(ev.event_id);
        }

        confirmedMatches.push({
          finding_id: finding.finding_id,
          rule_id: finding.rule_id,
          category: finding.category,
          severity: finding.severity,
          static_prediction: finding.title || finding.description,
          dynamic_evidence: {
            matched_event_ids: relevantEvents.map(e => e.event_id),
            summary: `Observed ${relevantEvents.length} runtime event(s) in category ${finding.category} confirming static hypothesis.`,
            events: relevantEvents,
          },
          concordance: 'CONFIRMED',
        });
      } else {
        const isEvasionDetected = dynamicResult.anti_analysis_detected || dynamicResult.evasion_risk_score > 0.5;
        untriggeredFindings.push({
          finding_id: finding.finding_id,
          rule_id: finding.rule_id,
          category: finding.category,
          severity: finding.severity,
          predicted_behavior: finding.title || finding.description,
          reason_not_triggered: isEvasionDetected ? 'EVASION_SUPPRESSED' : 'DORMANT_BRANCH',
        });
      }
    }

    // 2. Identify unpredicted dynamic behaviors (events not tied to static findings)
    const unpredictedDynamic: UnpredictedDynamicBehavior[] = [];
    const significantUnmatchedEvents = dynamicEvents.filter(e => 
      !matchedEventIds.has(e.event_id) && 
      (e.severity === 'HIGH' || e.severity === 'CRITICAL' || e.status === 'FLAGGED' || e.category === 'CANARY')
    );

    for (const unpredEv of significantUnmatchedEvents) {
      let cause: UnpredictedDynamicBehavior['possible_cause'] = 'RUNTIME_EVASION';
      if (unpredEv.category === 'CANARY') cause = 'CANARY_HARVEST';
      else if (unpredEv.category === 'ENVIRONMENT') cause = 'ENVIRONMENT_AWARENESS';
      else if (unpredEv.action.includes('FUZZ') || unpredEv.action.includes('EVAL')) cause = 'DYNAMIC_CODE_EVAL';

      unpredictedDynamic.push({
        category: unpredEv.category,
        severity: unpredEv.severity,
        observed_action: unpredEv.action,
        event_ids: [unpredEv.event_id],
        description: `Runtime action '${unpredEv.action}' on target '${unpredEv.target}' was not predicted by static AST analysis.`,
        possible_cause: cause,
      });
    }

    // 3. Evaluate evasion divergences
    const evasionDivergences: EvasionDivergence[] = [];
    const hasStaticEvasionWarning = staticFindings.some(f => f.category === 'CONTROL_FLOW_ANOMALY' || f.rule_id.includes('EVASION'));

    for (const indicator of dynamicResult.evasion_indicators || []) {
      if (indicator.detected) {
        evasionDivergences.push({
          evasion_type: indicator.type,
          detected_at_runtime: true,
          static_risk_prediction: hasStaticEvasionWarning ? 'STATIC_FLAGGED' : 'STATIC_MISSED',
          divergence_detail: `Dynamic sandbox observed '${indicator.name}' with confidence ${indicator.confidence.toFixed(2)}. ${indicator.description}`,
        });
      }
    }

    // 4. Compute Concordance & Risk Assessment Delta
    const totalStatic = staticFindings.length;
    const totalDynamic = dynamicEvents.length;
    const confirmedCount = confirmedMatches.length;
    const untriggeredCount = untriggeredFindings.length;
    const unpredictedCount = unpredictedDynamic.length;
    const evasionCount = evasionDivergences.length;

    const concordanceRate = totalStatic > 0 
      ? Math.round((confirmedCount / totalStatic) * 100) / 100 
      : (unpredictedCount === 0 ? 1.0 : 0.0);

    let riskAssessmentDelta: StaticDynamicComparisonReport['summary']['risk_assessment_delta'] = 'CONCORDANT_BENIGN';
    if (evasionCount > 0 && dynamicResult.evasion_risk_score >= 0.7) {
      riskAssessmentDelta = 'INDETERMINATE_EVASION';
    } else if (unpredictedCount > 0 || dynamicResult.canaries_tripped?.length > 0) {
      riskAssessmentDelta = 'ELEVATED_BY_DYNAMIC';
    } else if (confirmedCount > 0 && staticFindings.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')) {
      riskAssessmentDelta = 'CONFIRMED_HIGH';
    }

    // 5. Generate human-readable narrative report
    const narrativeLines: string[] = [
      `=== Static vs Dynamic Analysis Correlation Report ===`,
      `Artifact ID: ${artifactId} | Comparison ID: ${comparisonId}`,
      `Execution Mode: ${dynamicResult.provider_type} (Session: ${dynamicResult.session_id})`,
      `Outcome: ${riskAssessmentDelta} (Concordance Rate: ${(concordanceRate * 100).toFixed(1)}%)`,
      ``,
      `[1. Static Predictions vs Dynamic Confirmation]`,
      `  - Total Static Findings: ${totalStatic}`,
      `  - Confirmed at Runtime: ${confirmedCount}`,
      `  - Untriggered/Dormant: ${untriggeredCount}`,
    ];

    if (confirmedMatches.length > 0) {
      narrativeLines.push(`  Matches:`);
      for (const m of confirmedMatches) {
        narrativeLines.push(`    * [${m.category}] Rule ${m.rule_id} (${m.severity}): "${m.static_prediction}" -> Confirmed by ${m.dynamic_evidence.matched_event_ids.length} runtime event(s)`);
      }
    }

    if (untriggeredFindings.length > 0) {
      narrativeLines.push(`  Untriggered Static Findings:`);
      for (const u of untriggeredFindings) {
        narrativeLines.push(`    * [${u.category}] Rule ${u.rule_id}: "${u.predicted_behavior}" (Reason: ${u.reason_not_triggered})`);
      }
    }

    narrativeLines.push(``, `[2. Dynamic Anomalies Not Predicted Statically]`);
    if (unpredictedDynamic.length === 0) {
      narrativeLines.push(`  - None. All observed high-severity runtime behaviors were accounted for by static AST findings.`);
    } else {
      for (const u of unpredictedDynamic) {
        narrativeLines.push(`  * [${u.category}] Action: ${u.observed_action} (${u.severity}) -> Cause: ${u.possible_cause}. ${u.description}`);
      }
    }

    narrativeLines.push(``, `[3. Evasion & Anti-Analysis Discrepancies]`);
    if (evasionDivergences.length === 0) {
      narrativeLines.push(`  - No runtime evasion anomalies detected.`);
    } else {
      for (const ed of evasionDivergences) {
        narrativeLines.push(`  * Type: ${ed.evasion_type} (Static Prediction: ${ed.static_risk_prediction}) -> ${ed.divergence_detail}`);
      }
    }

    const narrativeReport = narrativeLines.join('\n');

    return {
      comparison_id: comparisonId,
      artifact_id: artifactId,
      timestamp,
      summary: {
        total_static_findings: totalStatic,
        total_dynamic_events: totalDynamic,
        confirmed_matches_count: confirmedCount,
        untriggered_static_count: untriggeredCount,
        unpredicted_dynamic_count: unpredictedCount,
        evasion_divergences_count: evasionCount,
        overall_concordance_rate: concordanceRate,
        risk_assessment_delta: riskAssessmentDelta,
      },
      confirmed_matches: confirmedMatches,
      untriggered_static_findings: untriggeredFindings,
      unpredicted_dynamic_behaviors: unpredictedDynamic,
      evasion_divergences: evasionDivergences,
      narrative_report: narrativeReport,
    };
  }
}
