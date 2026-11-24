import { deliberateFinding } from './council/index.js';
import { runCanaryProof } from './prover/index.js';
import { discoverLocalAgentPaths, runStaticScan } from './scanner/index.js';
import type { EvaluatedFinding, ScanReport, Severity } from './types.js';

export interface AuditOptions {
  targets?: string[];
  councilMode?: 'auto' | 'llm' | 'heuristic' | 'off';
  model?: string;
  prove?: boolean;
}

function computeScoreAndGrade(findings: EvaluatedFinding[]): {
  score: number;
  grade: ScanReport['grade'];
} {
  let penalty = 0;
  for (const f of findings) {
    const verdict = f.council?.judge.verdict ?? 'CONFIRMED';
    if (verdict === 'DISMISSED') continue;
    const mult = verdict === 'UNCERTAIN' ? 0.35 : 1;
    const sev = f.council?.judge.finalSeverity ?? f.initialSeverity;
    const weight = sev === 'critical' ? 28 : sev === 'high' ? 16 : sev === 'medium' ? 8 : 3;
    penalty += Math.round(weight * mult);
  }
  const score = Math.max(0, 100 - penalty);
  const grade: ScanReport['grade'] =
    score >= 97 ? 'A+' : score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 65 ? 'C' : score >= 50 ? 'D' : 'F';
  return { score, grade };
}

export async function runAudit(options: AuditOptions = {}): Promise<ScanReport> {
  const t0 = Date.now();
  const targets =
    options.targets && options.targets.length > 0 ? options.targets : await discoverLocalAgentPaths();

  const { filesScanned, candidates } = await runStaticScan(targets);
  const councilModePref = options.councilMode ?? 'auto';

  const evaluated: EvaluatedFinding[] = [];
  let actualMode: ScanReport['councilMode'] = councilModePref === 'off' ? 'off' : 'heuristic';
  let modelName = councilModePref === 'off' ? 'none' : 'council-heuristic-v1';

  for (const c of candidates) {
    const council = await deliberateFinding(c, { mode: councilModePref, model: options.model });
    if (council) {
      actualMode = council.mode;
      modelName = council.modelUsed;
    }
    const item: EvaluatedFinding = { ...c, council };
    if (options.prove && (council?.judge.verdict ?? 'CONFIRMED') === 'CONFIRMED') {
      item.proof = await runCanaryProof(item);
    }
    evaluated.push(item);
  }

  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let confirmed = 0;
  let uncertain = 0;
  let dismissed = 0;

  for (const f of evaluated) {
    const v = f.council?.judge.verdict ?? 'CONFIRMED';
    if (v === 'CONFIRMED') {
      confirmed += 1;
      const sev = f.council?.judge.finalSeverity ?? f.initialSeverity;
      bySeverity[sev] += 1;
    } else if (v === 'UNCERTAIN') {
      uncertain += 1;
    } else {
      dismissed += 1;
    }
  }

  const { score, grade } = computeScoreAndGrade(evaluated);

  return {
    targetPath: targets.join(', ') || '(no agent paths found)',
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - t0,
    filesScanned,
    councilMode: actualMode,
    modelName,
    grade,
    score,
    summary: {
      totalCandidates: evaluated.length,
      confirmed,
      uncertain,
      dismissed,
      bySeverity,
    },
    findings: evaluated,
  };
}

export * from './types.js';
