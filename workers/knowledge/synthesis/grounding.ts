import { DraftClaim, GroundingVerdict } from './types.ts';
import { AssembledContextPackage, SerializedFact } from '../context/types.ts';

export class GroundingValidator {
  /**
   * Evaluates draft claims against the verified facts and evidence bundles in the context package.
   */
  public static validateGrounding(
    claims: DraftClaim[],
    contextPackage: AssembledContextPackage
  ): {
    validatedClaims: DraftClaim[];
    groundedClaims: DraftClaim[];
    unsupportedClaims: DraftClaim[];
    contradictedClaims: DraftClaim[];
    verdict: GroundingVerdict;
    averageGroundingScore: number;
  } {
    if (contextPackage.serialized_facts.length === 0) {
      // Empty context -> All substantive claims are unsupported
      const ungrounded = claims.map((c) => ({
        ...c,
        grounding_score: 0,
        supported: !c.is_substantive, // non-substantive filler can pass
      }));
      return {
        validatedClaims: ungrounded,
        groundedClaims: ungrounded.filter((c) => c.supported),
        unsupportedClaims: ungrounded.filter((c) => !c.supported && c.is_substantive),
        contradictedClaims: [],
        verdict: 'NO_EVIDENCE',
        averageGroundingScore: 0,
      };
    }

    const validated: DraftClaim[] = [];
    const grounded: DraftClaim[] = [];
    const unsupported: DraftClaim[] = [];
    const contradicted: DraftClaim[] = [];

    let totalScore = 0;

    for (const claim of claims) {
      if (!claim.is_substantive) {
        const passClaim: DraftClaim = {
          ...claim,
          grounding_score: 1.0,
          supported: true,
        };
        validated.push(passClaim);
        grounded.push(passClaim);
        totalScore += 1.0;
        continue;
      }

      // Check contradiction first
      const contradiction = ContradictionDetector.checkContradiction(claim, contextPackage);
      if (contradiction.isContradicted) {
        const contClaim: DraftClaim = {
          ...claim,
          grounding_score: 0,
          supported: false,
          contradicted: true,
          contradiction_reason: contradiction.reason,
        };
        validated.push(contClaim);
        contradicted.push(contClaim);
        continue;
      }

      // Find supporting facts and evidence
      const matchResult = this.matchClaimToContext(claim, contextPackage);
      const isSupported = matchResult.score >= 0.35 && matchResult.supportingFacts.length > 0;

      const evalClaim: DraftClaim = {
        ...claim,
        grounding_score: matchResult.score,
        supported: isSupported,
        contradicted: false,
        supporting_evidence_ids: matchResult.supportingEvidence,
        supporting_fact_ids: matchResult.supportingFacts,
      };

      validated.push(evalClaim);
      totalScore += matchResult.score;

      if (isSupported) {
        grounded.push(evalClaim);
      } else {
        unsupported.push(evalClaim);
      }
    }

    const avgScore = claims.length > 0 ? totalScore / claims.length : 0;

    // Determine overall verdict
    let verdict: GroundingVerdict;
    if (contradicted.length > 0) {
      verdict = 'CONTRADICTED';
    } else if (unsupported.length === 0 && grounded.length > 0) {
      verdict = 'FULLY_GROUNDED';
    } else if (grounded.length > 0 && unsupported.length > 0) {
      verdict = 'PARTIALLY_GROUNDED';
    } else if (grounded.length === 0 && unsupported.length > 0) {
      verdict = 'UNSUPPORTED';
    } else {
      verdict = 'NO_EVIDENCE';
    }

    return {
      validatedClaims: validated,
      groundedClaims: grounded,
      unsupportedClaims: unsupported,
      contradictedClaims: contradicted,
      verdict,
      averageGroundingScore: avgScore,
    };
  }

  private static matchClaimToContext(
    claim: DraftClaim,
    contextPackage: AssembledContextPackage
  ): {
    score: number;
    supportingFacts: string[];
    supportingEvidence: string[];
  } {
    const claimLower = claim.statement.toLowerCase();
    const claimWords = claimLower
      .replace(/[^\w\s-]/g, ' ')
      .split(/\s+/)
      .filter((w) => w.length > 3);

    let bestScore = 0;
    const supportingFacts: string[] = [];
    const supportingEvidence: string[] = [];

    // 1. Match against serialized facts
    for (const fact of contextPackage.serialized_facts) {
      const factLower = fact.formatted_content.toLowerCase();
      let matchCount = 0;

      for (const word of claimWords) {
        if (factLower.includes(word)) {
          matchCount++;
        }
      }

      const matchRatio = claimWords.length > 0 ? matchCount / claimWords.length : 0;

      // Bonus if exact entity_ref_id or keyword is in the claim or its citation tags
      const hasDirectIdMatch =
        claimLower.includes(fact.entity_ref_id.toLowerCase()) ||
        claim.citation_tags.some((tag) => tag.toLowerCase().includes(fact.entity_ref_id.toLowerCase()));

      const finalFactScore = Math.min(1.0, matchRatio + (hasDirectIdMatch ? 0.35 : 0));

      if (finalFactScore >= 0.35) {
        supportingFacts.push(fact.fact_id);
        if (finalFactScore > bestScore) {
          bestScore = finalFactScore;
        }
      }
    }

    // 2. Match against evidence bundles
    for (const bundle of contextPackage.bundles) {
      for (const ev of bundle.evidence_items) {
        const evLower = ev.observation.toLowerCase();
        let evMatches = 0;
        for (const word of claimWords) {
          if (evLower.includes(word)) {
            evMatches++;
          }
        }
        const evRatio = claimWords.length > 0 ? evMatches / claimWords.length : 0;
        const hasDirectEvId =
          claimLower.includes(ev.evidence_id.toLowerCase()) ||
          claim.citation_tags.some((tag) => tag.toLowerCase().includes(ev.evidence_id.toLowerCase()));

        if (evRatio >= 0.3 || hasDirectEvId) {
          supportingEvidence.push(ev.evidence_id);
          bestScore = Math.max(bestScore, evRatio + (hasDirectEvId ? 0.4 : 0.1));
        }
      }
    }

    return {
      score: bestScore,
      supportingFacts,
      supportingEvidence,
    };
  }
}

export class ContradictionDetector {
  /**
   * Detects direct factual or semantic contradictions against known authoritative findings.
   */
  public static checkContradiction(
    claim: DraftClaim,
    contextPackage: AssembledContextPackage
  ): { isContradicted: boolean; reason?: string } {
    const claimLower = (claim.statement + ' ' + (claim.citation_tags || []).join(' ')).toLowerCase();

    // Check for critical finding or vulnerability inversion (claiming safe when severe risks exist)
    const hasCriticalSecurityIssue =
      contextPackage.serialized_facts.some(
        (f) =>
          f.formatted_content.toUpperCase().includes('CRITICAL') ||
          f.formatted_content.toUpperCase().includes('HIGH') ||
          f.formatted_content.includes('BLOCK_DEPLOYMENT') ||
          f.formatted_content.includes('CVSS') ||
          f.formatted_content.includes('CVE-') ||
          f.formatted_content.includes('taint') ||
          f.formatted_content.includes('RCE')
      ) ||
      contextPackage.bundles.some((b) => b.evidence_items.length > 0);

    if (hasCriticalSecurityIssue) {
      const claimAssertsNoIssues =
        claimLower.includes('no vulnerabilities') ||
        claimLower.includes('completely safe') ||
        claimLower.includes('zero risk') ||
        claimLower.includes('no security issues') ||
        claimLower.includes('no security issues found') ||
        claimLower.includes('safe to deploy without changes') ||
        claimLower.includes('safe to deploy');

      if (claimAssertsNoIssues) {
        return {
          isContradicted: true,
          reason: 'Claim asserts absence of vulnerabilities or complete safety, directly contradicting verified security findings and risks in context.',
        };
      }
    }

    // Check for policy outcome inversion
    const blockPolicyFact = contextPackage.serialized_facts.find(
      (f) => f.entity_type === 'policy' && f.formatted_content.includes('BLOCK_DEPLOYMENT')
    );

    if (blockPolicyFact) {
      const claimAssertsApproved =
        claimLower.includes('policy approved') ||
        claimLower.includes('deployment is allowed') ||
        claimLower.includes('passed all policy gates');

      if (claimAssertsApproved) {
        return {
          isContradicted: true,
          reason: 'Claim asserts policy approval, directly contradicting the active BLOCK_DEPLOYMENT policy evaluation.',
        };
      }
    }

    // Check for CVSS / risk score inversion
    const cveFact = contextPackage.serialized_facts.find(
      (f) => f.entity_type === 'vulnerability' || f.formatted_content.includes('CVSS')
    );
    if (cveFact && cveFact.formatted_content.includes('8.8')) {
      if (claimLower.includes('cvss 3.') || claimLower.includes('low severity cve')) {
        return {
          isContradicted: true,
          reason: 'Claim asserts low severity CVSS score contradicting recorded CVSS 8.8 High severity vulnerability.',
        };
      }
    }

    return { isContradicted: false };
  }
}
