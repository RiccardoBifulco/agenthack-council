import type { EvaluatedFinding, StaticEvidence } from '../types.js';

export function inspectStaticEvidence(finding: EvaluatedFinding): StaticEvidence {
  const text = finding.snippet + '\n' + finding.evidence;
  const inspection = { method: 'static', executed: false, triggeredCanary: false } as const;

  if (/(?:\.env|process\.env|os\.environ|aws\/credentials)/i.test(text) && /(?:curl|wget|fetch|http|exfil)/i.test(text)) {
    return {
      ...inspection,
      signal: 'network-reference',
      details: 'The snippet references both a credential source and a network operation.',
    };
  }
  if (/(?:\.ssh\/id_rsa|ssh_key)/i.test(text)) {
    return {
      ...inspection,
      signal: 'credential-reference',
      details: 'The snippet references an SSH credential.',
    };
  }
  if (['AHC-001', 'AHC-003', 'AHC-007'].includes(finding.ruleId)) {
    return {
      ...inspection,
      signal: 'suspicious-directive',
      details: 'The scanner matched a suspicious directive or obfuscation pattern.',
    };
  }
  return { ...inspection, details: 'No additional static signal identified.' };
}
