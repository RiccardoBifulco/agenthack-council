export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type VerdictStatus = 'CONFIRMED' | 'UNCERTAIN' | 'DISMISSED';
export type FindingVerdict = VerdictStatus | 'UNREVIEWED';

export interface ScanIssue {
  path: string;
  reason: 'missing-target' | 'unsupported-target' | 'unreadable' | 'file-too-large' | 'file-limit';
}

export type TargetCategory =
  | 'mcp-config'
  | 'mcp-server-code'
  | 'skill-markdown'
  | 'agent-instructions'
  | 'agent-settings'
  | 'agent-hook';

export interface RuleMetadata {
  id: string;
  name: string;
  cwe: string;
  defaultSeverity: Severity;
  securitySeverityScore: string;
  shortDescription: string;
  fullDescription: string;
}

export interface CandidateFinding {
  id: string;
  ruleId: string;
  ruleName: string;
  category: TargetCategory;
  initialSeverity: Severity;
  filePath: string;
  relativePath: string;
  line: number;
  snippet: string;
  contextWindow: string;
  evidence: string;
  cwe: string;
  inCodeFence?: boolean;
  isPlaceholderHint?: boolean;
}

export interface CouncilReview {
  advocate: {
    exploitScenario: string;
    attackerControl: string;
    blastRadius: string;
    confidence: number;
    modelUsed?: string;
  };
  skeptic: {
    counterArgument: string;
    mitigatingFactors: string[];
    falsePositiveLikelihood: number;
    modelUsed?: string;
  };
  judge: {
    verdict: VerdictStatus;
    finalSeverity: Severity;
    confidence: number;
    rationale: string;
    minimalPatch?: string;
    modelUsed?: string;
  };
  mode: 'llm' | 'heuristic';
  modelUsed: string;
  durationMs: number;
  fallbackReason?: string;
}

export interface StaticEvidence {
  method: 'static';
  signal?: 'credential-reference' | 'network-reference' | 'suspicious-directive';
  details: string;
  /** @deprecated No code is executed during static inspection. */
  executed: false;
  /** @deprecated Static inspection never triggers a canary. */
  triggeredCanary: false;
}

export type CanaryProof = StaticEvidence;

export interface EvaluatedFinding extends CandidateFinding {
  verdict: FindingVerdict;
  council?: CouncilReview;
  proof?: StaticEvidence;
}

export interface ScanReport {
  version: string;
  targetPath: string;
  scannedAt: string;
  durationMs: number;
  filesScanned: number;
  coverage: 'complete' | 'partial' | 'empty';
  scanIssues: ScanIssue[];
  councilMode: 'llm' | 'heuristic' | 'off';
  modelName: string;
  fallbackWarning?: string;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' | null;
  score: number | null;
  summary: {
    totalCandidates: number;
    confirmed: number;
    unreviewed: number;
    uncertain: number;
    dismissed: number;
    bySeverity: Record<Severity, number>;
  };
  findings: EvaluatedFinding[];
}
