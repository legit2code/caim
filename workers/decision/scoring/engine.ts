/**
 * Scoring Engine (Architecture V2.0.1)
 * Evaluates multi-dimensional scores with explicit deductions, risk-band mapping, and explanations.
 */

import {
  ScoreResult,
  ScoreDimensionValue,
  ScoreExplanation,
  ScoreRiskBand,
  RiskRecord,
} from '../types.ts';
import { ScoreModelRegistry } from './registry.ts';

export interface ScoreCalculationInput {
  analysisRunId: string;
  modelKey?: string;
  modelVersion?: string;
  risks: RiskRecord[];
  promptInjectionScore?: number; // 0.0 to 1.0 (1.0 = highly resilient)
}

export class ScoringEngine {
  /**
   * Computes the multi-dimensional score result according to the specified model version.
   */
  public static computeScore(input: ScoreCalculationInput): ScoreResult {
    const modelKey = input.modelKey || 'SCORE-MODEL-V1-ARCH';
    const modelVersion = input.modelVersion || '1.0.0';
    const model = ScoreModelRegistry.getModel(modelKey, modelVersion);
    const runId = input.analysisRunId;

    const dimensionValues: ScoreDimensionValue[] = [];
    const keyDeductions: string[] = [];

    // Map risks by category for dimensional evaluation
    for (const dim of model.dimensions) {
      let rawScore = 100.0;
      const deductions: Array<{ reason: string; points: number; evidence_ids?: string[] }> = [];

      switch (dim.dimension_key) {
        case 'SECURITY_POSTURE': {
          for (const risk of input.risks) {
            if (risk.risk_type === 'CODE_EXECUTION' || risk.risk_type === 'CREDENTIAL_EXPOSURE' || risk.risk_type === 'PROMPT_INJECTION') {
              let penalty = risk.severity === 'CRITICAL' ? 35 : risk.severity === 'HIGH' ? 20 : 10;
              if (model.formula_type === 'NON_LINEAR_PENALTY') {
                penalty = Math.round(penalty * 1.3);
              }
              rawScore -= penalty;
              const evidenceIds = risk.evidence_links.map((e) => e.evidence_id);
              deductions.push({
                reason: `${risk.severity} Risk: ${risk.title}`,
                points: penalty,
                evidence_ids: evidenceIds,
              });
              keyDeductions.push(`[Security] -${penalty}pts: ${risk.title}`);
            }
          }
          break;
        }

        case 'RUNTIME_SAFETY': {
          for (const risk of input.risks) {
            if (risk.risk_type === 'HONEYTOKEN_COMPROMISE' || risk.risk_type === 'DATA_EXFILTRATION' || risk.risk_type === 'DEFENSIVE_EVASION') {
              const penalty = risk.severity === 'CRITICAL' ? 40 : risk.severity === 'HIGH' ? 25 : 10;
              rawScore -= penalty;
              const evidenceIds = risk.evidence_links.map((e) => e.evidence_id);
              deductions.push({
                reason: `${risk.severity} Runtime Threat: ${risk.title}`,
                points: penalty,
                evidence_ids: evidenceIds,
              });
              keyDeductions.push(`[Runtime] -${penalty}pts: ${risk.title}`);
            }
          }
          break;
        }

        case 'DEPENDENCY_HEALTH': {
          for (const risk of input.risks) {
            if (risk.risk_type === 'SUPPLY_CHAIN') {
              const penalty = risk.severity === 'CRITICAL' ? 30 : risk.severity === 'HIGH' ? 20 : 10;
              rawScore -= penalty;
              const evidenceIds = risk.evidence_links.map((e) => e.evidence_id);
              deductions.push({
                reason: `Reachable Dependency Vulnerability: ${risk.title}`,
                points: penalty,
                evidence_ids: evidenceIds,
              });
              keyDeductions.push(`[Supply Chain] -${penalty}pts: ${risk.title}`);
            }
          }
          break;
        }

        case 'CODE_QUALITY': {
          for (const risk of input.risks) {
            if (risk.risk_type === 'DATA_INTEGRITY' || risk.risk_type === 'FILE_SYSTEM' || risk.risk_type === 'GOVERNANCE') {
              const penalty = risk.severity === 'HIGH' ? 15 : risk.severity === 'MEDIUM' ? 10 : 5;
              rawScore -= penalty;
              const evidenceIds = risk.evidence_links.map((e) => e.evidence_id);
              deductions.push({
                reason: `${risk.severity} Quality Defect: ${risk.title}`,
                points: penalty,
                evidence_ids: evidenceIds,
              });
              keyDeductions.push(`[Quality] -${penalty}pts: ${risk.title}`);
            }
          }
          break;
        }

        case 'PROMPT_RESILIENCE': {
          if (input.promptInjectionScore !== undefined) {
            const shortfall = Math.max(0, (1.0 - input.promptInjectionScore) * 100);
            if (shortfall > 0) {
              const penalty = Math.round(shortfall);
              rawScore -= penalty;
              deductions.push({
                reason: `Prompt injection safety resilience shortfall (${Math.round(input.promptInjectionScore * 100)}% resilience)`,
                points: penalty,
              });
              keyDeductions.push(`[Prompt] -${penalty}pts: Prompt injection vulnerability probe`);
            }
          }
          break;
        }
      }

      rawScore = Math.max(0, Math.min(100, rawScore));
      const weightedScore = parseFloat((rawScore * dim.weight).toFixed(4));

      dimensionValues.push({
        dimension_key: dim.dimension_key,
        display_name: dim.display_name,
        raw_score: rawScore,
        weight: dim.weight,
        weighted_score: weightedScore,
        deductions,
      });
    }

    // Aggregate overall score
    let overallScore = 0;
    for (const d of dimensionValues) {
      overallScore += d.weighted_score;
    }
    overallScore = parseFloat(Math.max(0, Math.min(100, overallScore)).toFixed(2));
    const normalizedScore = parseFloat((overallScore / 100.0).toFixed(4));

    // Grade assignment
    let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
    if (overallScore >= 95) grade = 'A+';
    else if (overallScore >= 85) grade = 'A';
    else if (overallScore >= 70) grade = 'B';
    else if (overallScore >= 50) grade = 'C';
    else if (overallScore >= 30) grade = 'D';
    else grade = 'F';

    // Risk band mapping
    let riskBand: ScoreRiskBand;
    if (overallScore >= 85) riskBand = 'MINIMAL';
    else if (overallScore >= 70) riskBand = 'LOW';
    else if (overallScore >= 50) riskBand = 'MODERATE';
    else if (overallScore >= 30) riskBand = 'ELEVATED';
    else riskBand = 'SEVERE';

    // Identify strongest and weakest dimensions
    const sortedDims = [...dimensionValues].sort((a, b) => b.raw_score - a.raw_score);
    const strongest = sortedDims[0]?.display_name || 'N/A';
    const weakest = sortedDims[sortedDims.length - 1]?.display_name || 'N/A';

    const explanation: ScoreExplanation = {
      summary: `Overall score ${overallScore}/100 (Grade ${grade}, Risk Band ${riskBand}) computed via ${model.name} (${model.version}).`,
      strongest_dimension: strongest,
      weakest_dimension: weakest,
      key_deductions: keyDeductions.length > 0 ? keyDeductions : ['No deductions; flawless evaluation posture.'],
    };

    return {
      score_result_id: `score-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      analysis_run_id: runId,
      model_key: model.model_key,
      model_version: model.version,
      overall_score: overallScore,
      normalized_score: normalizedScore,
      grade,
      risk_band: riskBand,
      dimension_values: dimensionValues,
      explanation,
      calibration_version: model.calibration_version,
      created_at: new Date().toISOString(),
    };
  }
}
