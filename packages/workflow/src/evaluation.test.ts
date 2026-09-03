/**
 * Golden Corpus, Evaluation & CI Regression Gate Test Suite
 * Conforming to P31 specification
 */

import { describe, it, expect } from 'vitest';
import { runEvaluationVerificationTests } from './evaluation.ts';

export { runEvaluationVerificationTests };

describe('Golden Corpus & Regression Evaluation Verification', () => {
  const res = runEvaluationVerificationTests();

  it.each(res.testResults)('$name', (check) => {
    expect(
      check.status,
      `Verification check "${check.name}" failed: ${check.details}`
    ).toBe('PASS');
  });
});
