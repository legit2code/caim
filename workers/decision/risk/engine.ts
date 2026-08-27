/**
 * Risk Engine (Architecture V2.0.1)
 * Evaluates observations, findings, runtime telemetry, and taint flows into structured RiskRecords
 * with deterministic likelihood, impact, severity, and evidence links.
 */

import { RiskRecord, RiskEvidenceLink, RiskSeverity } from '../types.ts';
import { RISK_TAXONOMY_V1 } from './rules.ts';

export interface RiskEvaluationInput {
  analysisRunId: string;
  entityRefId?: string;
  findings?: Array<{
    finding_id?: string;
    rule_id?: string;
    finding_type?: string;
    category?: string;
    severity?: string;
    title?: string;
    description?: string;
    confidence?: number;
    evidence_ids?: string[];
  }>;
  staticFindings?: Array<{
    finding_id?: string;
    rule_id?: string;
    finding_type?: string;
    category?: string;
    severity?: string;
    title?: string;
    description?: string;
    confidence?: number;
    evidence_ids?: string[];
  }>;
  taintFlows?: Array<{
    flow_id?: string;
    source_type?: string;
    sink_type?: string;
    severity?: string;
    evidence_id?: string;
  }>;
  runtimeEvents?: Array<{
    event_id?: string;
    event_type?: string;
    severity?: string;
    details?: string;
    evidence_id?: string;
  }>;
  dynamicEvents?: Array<{
    event_id?: string;
    event_type?: string;
    severity?: string;
    details?: string;
    evidence_id?: string;
  }>;
  canariesTripped?: Array<{
    canary_id?: string;
    name?: string;
    location?: string;
    tripped_timestamp?: string;
    evidence_id?: string;
  }>;
  reachableCVEs?: Array<{
    package_name?: string;
    cve_id?: string;
    severity?: string;
    evidence_id?: string;
  }>;
  evidenceList?: Array<{
    evidence_id: string;
    evidence_type?: string;
    summary?: string;
  }>;
}

export class RiskEngine {
  /**
   * Evaluates all input artifacts into normalized, evidence-linked RiskRecords.
   */
  public static evaluateRisks(input: RiskEvaluationInput): RiskRecord[] {
    const risks: RiskRecord[] = [];
    const runId = input.analysisRunId;
    const entityRefId = input.entityRefId;

    const allFindings = [...(input.findings || []), ...(input.staticFindings || [])];
    const allRuntimeEvents = [...(input.runtimeEvents || []), ...(input.dynamicEvents || [])];

    // 1. Canaries Tripped (Critical)
    if (input.canariesTripped && input.canariesTripped.length > 0) {
      for (const canary of input.canariesTripped) {
        const rule = RISK_TAXONOMY_V1.CANARY_HONEYTOKEN_LEAK;
        const evidenceLinks: RiskEvidenceLink[] = [];
        if (canary.evidence_id) {
          evidenceLinks.push({ evidence_id: canary.evidence_id, relevance_score: 1.0, notes: 'Direct canary exfiltration telemetry' });
        } else if (input.evidenceList && input.evidenceList.length > 0) {
          evidenceLinks.push({ evidence_id: input.evidenceList[0].evidence_id, relevance_score: 0.9, notes: 'Associated runtime trace' });
        }

        risks.push({
          risk_id: `risk-canary-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          analysis_run_id: runId,
          entity_ref_id: entityRefId,
          risk_type: rule.category,
          title: `${rule.title_template} (${canary.name || canary.location || 'Synthetic Secret'})`,
          description: rule.description_template,
          severity: rule.severity,
          likelihood: rule.base_likelihood,
          impact: rule.base_impact,
          risk_score: parseFloat((rule.base_likelihood * rule.base_impact).toFixed(4)),
          mitigated: false,
          remediation_guidance: rule.remediation_template,
          evidence_links: evidenceLinks,
          created_at: new Date().toISOString(),
        });
      }
    }

    // 2. Taint Flows (Injection Sinks)
    if (input.taintFlows && input.taintFlows.length > 0) {
      for (const flow of input.taintFlows) {
        let rule = RISK_TAXONOMY_V1.CODE_INJECTION_SINK;
        if (flow.sink_type === 'COMMAND_INJECTION' || flow.sink_type === 'EXEC_COMMAND') {
          rule = RISK_TAXONOMY_V1.COMMAND_INJECTION_SINK;
        } else if (flow.sink_type === 'FILE_SYSTEM' || flow.sink_type === 'PATH_TRAVERSAL') {
          rule = RISK_TAXONOMY_V1.PATH_TRAVERSAL;
        }

        const evidenceLinks: RiskEvidenceLink[] = [];
        if (flow.evidence_id) {
          evidenceLinks.push({ evidence_id: flow.evidence_id, relevance_score: 0.95, notes: `Taint path to ${flow.sink_type}` });
        } else if (input.evidenceList && input.evidenceList.length > 0) {
          evidenceLinks.push({ evidence_id: input.evidenceList[0].evidence_id, relevance_score: 0.85, notes: 'Dataflow trace evidence' });
        }

        risks.push({
          risk_id: `risk-taint-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          analysis_run_id: runId,
          entity_ref_id: entityRefId,
          risk_type: rule.category,
          title: `${rule.title_template} [${flow.source_type || 'SOURCE'} -> ${flow.sink_type || 'SINK'}]`,
          description: rule.description_template,
          severity: rule.severity,
          likelihood: rule.base_likelihood,
          impact: rule.base_impact,
          risk_score: parseFloat((rule.base_likelihood * rule.base_impact).toFixed(4)),
          mitigated: false,
          remediation_guidance: rule.remediation_template,
          evidence_links: evidenceLinks,
          created_at: new Date().toISOString(),
        });
      }
    }

    // 3. Runtime Events (Egress violations & Evasion)
    if (allRuntimeEvents.length > 0) {
      for (const event of allRuntimeEvents) {
        if (event.event_type === 'NETWORK_EGRESS_BLOCKED' || event.event_type === 'EGRESS_VIOLATION') {
          const rule = RISK_TAXONOMY_V1.EGRESS_POLICY_VIOLATION;
          const evidenceLinks: RiskEvidenceLink[] = [];
          if (event.evidence_id) {
            evidenceLinks.push({ evidence_id: event.evidence_id, relevance_score: 0.95, notes: 'Egress monitor violation event' });
          }

          risks.push({
            risk_id: `risk-egress-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
            analysis_run_id: runId,
            entity_ref_id: entityRefId,
            risk_type: rule.category,
            title: rule.title_template,
            description: event.details || rule.description_template,
            severity: rule.severity,
            likelihood: rule.base_likelihood,
            impact: rule.base_impact,
            risk_score: parseFloat((rule.base_likelihood * rule.base_impact).toFixed(4)),
            mitigated: false,
            remediation_guidance: rule.remediation_template,
            evidence_links: evidenceLinks,
            created_at: new Date().toISOString(),
          });
        } else if (event.event_type === 'EVASION_PROBE' || event.event_type === 'ANTI_ANALYSIS') {
          const rule = RISK_TAXONOMY_V1.SANDBOX_EVASION_BEHAVIOR;
          const evidenceLinks: RiskEvidenceLink[] = [];
          if (event.evidence_id) {
            evidenceLinks.push({ evidence_id: event.evidence_id, relevance_score: 0.9, notes: 'Anti-analysis trigger trace' });
          }

          risks.push({
            risk_id: `risk-evasion-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
            analysis_run_id: runId,
            entity_ref_id: entityRefId,
            risk_type: rule.category,
            title: rule.title_template,
            description: event.details || rule.description_template,
            severity: rule.severity,
            likelihood: rule.base_likelihood,
            impact: rule.base_impact,
            risk_score: parseFloat((rule.base_likelihood * rule.base_impact).toFixed(4)),
            mitigated: false,
            remediation_guidance: rule.remediation_template,
            evidence_links: evidenceLinks,
            created_at: new Date().toISOString(),
          });
        }
      }
    }

    // 4. Reachable CVE Dependencies
    if (input.reachableCVEs && input.reachableCVEs.length > 0) {
      for (const cve of input.reachableCVEs) {
        const rule = RISK_TAXONOMY_V1.REACHABLE_CVE_DEPENDENCY;
        const evidenceLinks: RiskEvidenceLink[] = [];
        if (cve.evidence_id) {
          evidenceLinks.push({ evidence_id: cve.evidence_id, relevance_score: 0.9, notes: `Callgraph reachability proof for ${cve.cve_id}` });
        }

        risks.push({
          risk_id: `risk-cve-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          analysis_run_id: runId,
          entity_ref_id: entityRefId,
          risk_type: rule.category,
          title: `${rule.title_template} (${cve.package_name || 'dependency'} / ${cve.cve_id || 'CVE'})`,
          description: rule.description_template,
          severity: (cve.severity as RiskSeverity) || rule.severity,
          likelihood: rule.base_likelihood,
          impact: rule.base_impact,
          risk_score: parseFloat((rule.base_likelihood * rule.base_impact).toFixed(4)),
          mitigated: false,
          remediation_guidance: rule.remediation_template,
          evidence_links: evidenceLinks,
          created_at: new Date().toISOString(),
        });
      }
    }

    // 5. Static AST Findings
    if (allFindings.length > 0) {
      for (const f of allFindings) {
        let rule = RISK_TAXONOMY_V1.MISSING_INPUT_VALIDATION;
        if (f.finding_type === 'HARDCODED_SECRET' || f.finding_type === 'API_KEY' || f.category === 'SECRET_EXPOSURE' || f.rule_id?.includes('SECRET')) {
          rule = RISK_TAXONOMY_V1.HARDCODED_API_KEY;
        } else if (f.finding_type === 'DANGEROUS_EVAL' || f.finding_type === 'CODE_INJECTION' || f.category === 'CODE_EXECUTION') {
          rule = RISK_TAXONOMY_V1.CODE_INJECTION_SINK;
        } else if (f.finding_type === 'COMMAND_INJECTION') {
          rule = RISK_TAXONOMY_V1.COMMAND_INJECTION_SINK;
        } else if (f.finding_type === 'PROMPT_INJECTION' || f.category === 'PROMPT_INJECTION') {
          rule = RISK_TAXONOMY_V1.PROMPT_INJECTION_VULNERABILITY;
        } else if (f.finding_type === 'AMBIGUOUS_SPEC') {
          rule = RISK_TAXONOMY_V1.AMBIGUOUS_SPECIFICATION;
        }

        const evidenceLinks: RiskEvidenceLink[] = [];
        if (f.evidence_ids && f.evidence_ids.length > 0) {
          for (const eid of f.evidence_ids) {
            evidenceLinks.push({ evidence_id: eid, relevance_score: 0.85, notes: 'Static AST finding evidence' });
          }
        } else if (input.evidenceList && input.evidenceList.length > 0) {
          evidenceLinks.push({ evidence_id: input.evidenceList[0].evidence_id, relevance_score: 0.85, notes: 'Linked static evidence' });
        }

        risks.push({
          risk_id: `risk-finding-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          analysis_run_id: runId,
          entity_ref_id: entityRefId,
          risk_type: rule.category,
          title: f.title || rule.title_template,
          description: f.description || rule.description_template,
          severity: (f.severity as RiskSeverity) || rule.severity,
          likelihood: rule.base_likelihood,
          impact: rule.base_impact,
          risk_score: parseFloat((rule.base_likelihood * rule.base_impact).toFixed(4)),
          mitigated: false,
          remediation_guidance: rule.remediation_template,
          evidence_links: evidenceLinks,
          created_at: new Date().toISOString(),
        });
      }
    }

    return risks;
  }
}
