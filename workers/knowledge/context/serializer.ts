import { RetrievedDocument } from '../retrieval/types.ts';
import { SerializedFact } from './types.ts';
import { SecurityClassificationCode, SecurityClassificationRank, CLASSIFICATION_CODE_TO_RANK } from '../../../packages/auth/src/types.ts';
import crypto from 'crypto';

export class StructuredFactSerializer {
  /**
   * Converts a raw retrieved document into a strongly-typed, sanitized, and verifiable SerializedFact.
   */
  public static serialize(doc: RetrievedDocument): SerializedFact {
    const rawContent = doc.full_content || '';
    
    // Hash content to provide integrity checksum
    const checksum = crypto.createHash('sha256').update(`${doc.object_type}:${doc.entity_ref_id}:${rawContent}`).digest('hex').substring(0, 16);

    const classification = (doc.security_classification || 'INTERNAL') as SecurityClassificationCode;
    const rank = CLASSIFICATION_CODE_TO_RANK[classification] ?? SecurityClassificationRank.INTERNAL;

    const formatted = this.formatFactContent(doc, checksum);
    const token_estimate = Math.ceil(formatted.length / 4);

    return {
      fact_id: `fact-${doc.object_type}-${doc.entity_ref_id}`,
      entity_ref_id: doc.entity_ref_id,
      entity_type: doc.object_type,
      security_classification: classification,
      security_rank: rank,
      agent_id: doc.agent_id,
      agent_version_id: doc.agent_version_id,
      analysis_run_id: doc.analysis_run_id,
      token_estimate,
      formatted_content: formatted,
      source_retriever: doc.retriever_source || 'VECTOR_SEMANTIC',
      checksum,
      vault_restricted: Boolean(doc.vault_restricted),
    };
  }

  private static formatFactContent(doc: RetrievedDocument, checksum: string): string {
    const lines: string[] = [];
    lines.push(`<knowledge_fact type="${doc.object_type}" id="${doc.entity_ref_id}" checksum="${checksum}" class="${doc.security_classification}">`);

    if (doc.agent_id) lines.push(`  <scope agent_id="${doc.agent_id}" ${doc.agent_version_id ? `version_id="${doc.agent_version_id}"` : ''} ${doc.analysis_run_id ? `run_id="${doc.analysis_run_id}"` : ''} />`);

    if (doc.exact_keywords && Object.keys(doc.exact_keywords).length > 0) {
      const keys = Object.entries(doc.exact_keywords)
        .filter(([_, v]) => Boolean(v))
        .map(([k, v]) => `${k}="${Array.isArray(v) ? v.join(',') : v}"`)
        .join(' ');
      if (keys) {
        lines.push(`  <exact_identifiers ${keys} />`);
      }
    }

    if (doc.lineage_trail) {
      lines.push(`  <lineage_trail claim_id="${doc.lineage_trail.claim_id || ''}" evidence_id="${doc.lineage_trail.evidence_id || ''}" confidence="${doc.lineage_trail.confidence || 1.0}" />`);
    }

    lines.push(`  <content>`);
    // Indent content lines
    const contentLines = doc.full_content.split('\n');
    for (const cl of contentLines) {
      lines.push(`    ${cl.trimEnd()}`);
    }
    lines.push(`  </content>`);
    lines.push(`</knowledge_fact>`);

    return lines.join('\n');
  }
}
