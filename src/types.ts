export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type VerdictStatus = 'CONFIRMED' | 'UNCERTAIN' | 'DISMISSED';

export type TargetCategory =
  | 'mcp-config'
  | 'mcp-server-code'
  | 'skill-markdown'
  | 'agent-instructions'
  | 'agent-settings'
  | 'agent-hook';

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
}

export interface CouncilReview {
  advocate: {
    exploitScenario: string;
    attackerControl: string;
    blastRadius: string;
    confidence: number;
  };
  skeptic: {
    counterArgument: string;
    mitigatingFactors: string[];
    falsePositiveLikelihood: number;
  };
  judge: {
    verdict: VerdictStatus;
    finalSeverity: Severity;
    confidence: number;
    rationale: string;
    minimalPatch?: string;
  };
  mode: 'llm' | 'heuristic';
  modelUsed: string;
  durationMs: number;
}

export interface CanaryProof {
  executed: boolean;
  triggeredCanary: boolean;
  canaryType?: 'env-secret' | 'ssh-key' | 'network-exfil' | 'filesystem-escape';
  details: string;
}

export interface EvaluatedFinding extends CandidateFinding {
  council?: CouncilReview;
  proof?: CanaryProof;
}

export interface ScanReport {
  targetPath: string;
  scannedAt: string;
  durationMs: number;
  filesScanned: number;
  councilMode: 'llm' | 'heuristic' | 'off';
  modelName: string;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  score: number;
  summary: {
    totalCandidates: number;
    confirmed: number;
    uncertain: number;
    dismissed: number;
    bySeverity: Record<Severity, number>;
  };
  findings: EvaluatedFinding[];
}
