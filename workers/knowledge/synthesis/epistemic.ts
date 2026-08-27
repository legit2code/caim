import { DraftClaim, EpistemicDecision, GroundingVerdict } from './types.ts';
import { AssembledContextPackage } from '../context/types.ts';

export class EpistemicDecisionEngine {
  public static readonly ABSTENTION_MESSAGE =
    'I do not have sufficient authorized evidence to answer this inquiry based on verified platform knowledge.';

  /**
   * Evaluates the grounding results and decides whether to accept, revise, strip unsupported claims, or abstain.
   */
  public static evaluateDecision(
    rawDraft: string,
    claims: DraftClaim[],
    groundingVerdict: GroundingVerdict,
    contextPackage: AssembledContextPackage
  ): {
    decision: EpistemicDecision;
    finalAnswer: string;
    abstentionReason?: string;
  } {
    // 1. If no evidence was retrieved in the context package -> ABSTAIN
    if (contextPackage.serialized_facts.length === 0 || groundingVerdict === 'NO_EVIDENCE') {
      return {
        decision: 'ABSTAIN',
        finalAnswer: this.ABSTENTION_MESSAGE,
        abstentionReason: 'Zero authorized facts or evidence available in context for this query.',
      };
    }

    // 2. If severe contradiction detected -> ABSTAIN (or REJECT)
    if (groundingVerdict === 'CONTRADICTED') {
      return {
        decision: 'ABSTAIN',
        finalAnswer: this.ABSTENTION_MESSAGE,
        abstentionReason: 'Draft answer contains factual assertions that contradict verified platform findings.',
      };
    }

    // 3. If all claims are unsupported -> ABSTAIN
    if (groundingVerdict === 'UNSUPPORTED') {
      return {
        decision: 'ABSTAIN',
        finalAnswer: this.ABSTENTION_MESSAGE,
        abstentionReason: 'None of the substantive claims in the draft answer could be grounded in context.',
      };
    }

    // 4. If fully grounded -> ACCEPT
    if (groundingVerdict === 'FULLY_GROUNDED') {
      return {
        decision: 'ACCEPT',
        finalAnswer: rawDraft,
      };
    }

    // 5. Partially Grounded -> REMOVE_UNSUPPORTED or REVISE
    const supportedSentences: string[] = [];

    // Reconstruct answer containing ONLY supported claims and safe discourse markers
    for (const claim of claims) {
      if (claim.supported) {
        // Re-attach citation tags if present
        let stmt = claim.statement;
        if (claim.citation_tags.length > 0) {
          stmt = `${stmt} ${claim.citation_tags.join(' ')}`;
        }
        supportedSentences.push(stmt);
      }
    }

    if (supportedSentences.length === 0) {
      return {
        decision: 'ABSTAIN',
        finalAnswer: this.ABSTENTION_MESSAGE,
        abstentionReason: 'No grounded substantive statements remained after unsupported claim removal.',
      };
    }

    const revisedAnswer = supportedSentences.join(' ');

    return {
      decision: 'REMOVE_UNSUPPORTED',
      finalAnswer: revisedAnswer,
      abstentionReason: undefined,
    };
  }
}
