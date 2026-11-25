import {
  isFastDismissableCandidate,
  resolveCouncilRoles,
  runHeuristicCouncil,
  runLLMCouncilBatch,
  wantsLlmCouncil,
} from './council/index.js';
import { closeActiveProviderSessions, type ProviderName } from './council/providers.js';
import { inspectStaticEvidence } from './prover/index.js';
import { discoverLocalAgentPaths, runStaticScan } from './scanner/index.js';
import { RULES_CATALOG } from './scanner/rules.js';
import type { CandidateFinding, EvaluatedFinding, FindingVerdict, ScanReport, Severity } from './types.js';
import { buildSarifReport } from './ui/sarif.js';
import { VERSION } from './version.js';

export interface AuditOptions {
  targets?: string[];
  councilMode?: 'auto' | 'llm' | 'heuristic' | 'off';
  provider?: ProviderName;
  model?: string;
  advocateSpec?: string;
  skepticSpec?: string;
  judgeSpec?: string;
  strictLlm?: boolean;
  prove?: boolean;
  maxLlmFindings?: number;
  onProgress?: (message: string) => void;
}

const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const VERDICT_RANK: Record<FindingVerdict, number> = { CONFIRMED: 0, UNREVIEWED: 1, UNCERTAIN: 2, DISMISSED: 3 };

function sortEvaluatedFindings(list: EvaluatedFinding[]): EvaluatedFinding[] {
  return [...list].sort((a, b) => {
    const va = VERDICT_RANK[a.verdict];
    const vb = VERDICT_RANK[b.verdict];
    if (va !== vb) return va - vb;
    const sa = SEV_RANK[a.council?.judge.finalSeverity ?? a.initialSeverity] ?? 3;
    const sb = SEV_RANK[b.council?.judge.finalSeverity ?? b.initialSeverity] ?? 3;
    if (sa !== sb) return sa - sb;
    return a.relativePath.localeCompare(b.relativePath) || a.line - b.line;
  });
}

function computeScoreAndGrade(findings: EvaluatedFinding[]): {
  score: number;
  grade: ScanReport['grade'];
} {
  let penalty = 0;
  for (const f of findings) {
    const verdict = f.verdict;
    if (verdict === 'DISMISSED') continue;
    const mult = verdict === 'CONFIRMED' ? 1 : 0.35;
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
  const progress = options.onProgress;

  const targets =
    options.targets && options.targets.length > 0 ? options.targets : await discoverLocalAgentPaths();

  progress?.(`Scanning ${targets.length} target path(s) across 10 agent security rules...`);
  const scanStart = Date.now();
  const { filesScanned, candidates, scanIssues } = await runStaticScan(targets);
  const scanMs = Date.now() - scanStart;
  progress?.(`Scanned ${filesScanned} agent/MCP files in ${scanMs}ms -> ${candidates.length} candidate(s)`);

  const councilModePref = options.councilMode ?? 'auto';
  const wantsLlm = wantsLlmCouncil({ ...options, mode: councilModePref });

  const maxLlm = options.maxLlmFindings ?? 15;
  let actualMode: ScanReport['councilMode'] = councilModePref === 'off' ? 'off' : 'heuristic';
  let modelName = councilModePref === 'off' ? 'none' : 'council-heuristic-v1';
  let fallbackWarning: string | undefined;

  // The CI policy uses the same local rules and context checks in every Council mode.
  const policyById = new Map(candidates.map((candidate) => [candidate.id, runHeuristicCouncil(candidate)]));
  const councilById = new Map<string, EvaluatedFinding['council']>();

  try {
    if (councilModePref !== 'off') {
      const llmQueue: CandidateFinding[] = [];

      for (const c of candidates) {
        if (!wantsLlm || (!options.strictLlm && isFastDismissableCandidate(c)) || llmQueue.length >= maxLlm) {
          councilById.set(c.id, policyById.get(c.id));
        } else {
          llmQueue.push(c);
        }
      }

      if (llmQueue.length > 0) {
        try {
          const roles = resolveCouncilRoles({
            mode: councilModePref,
            provider: options.provider,
            model: options.model,
            advocateSpec: options.advocateSpec,
            skepticSpec: options.skepticSpec,
            judgeSpec: options.judgeSpec,
            strictLlm: options.strictLlm,
          });
          if (!roles) throw new Error('No configured LLM provider or CLI found');
          const batchReviews = await runLLMCouncilBatch(llmQueue, roles, progress);
          const unevaluatedCount = llmQueue.length - batchReviews.size;
          if (unevaluatedCount > 0) {
            const reason = 'Incomplete or invalid LLM evaluation for ' + unevaluatedCount + ' finding(s)';
            if (options.strictLlm) throw new Error(reason);
            fallbackWarning = reason + '; used council-heuristic-v1 for those findings';
            progress?.('⚠ ' + fallbackWarning);
          }
          for (const c of llmQueue) {
            const review = batchReviews.get(c.id);
            if (review) {
              actualMode = 'llm';
              modelName = review.modelUsed;
              councilById.set(c.id, review);
            } else {
              const fallback = { ...policyById.get(c.id)!, fallbackReason: fallbackWarning };
              councilById.set(c.id, fallback);
            }
          }
        } catch (err) {
          const reason = err instanceof Error ? err.message : String(err);
          if (options.strictLlm) {
            throw new Error('LLM Council failed (' + reason + ')');
          }
          fallbackWarning = 'LLM provider unavailable (' + reason + '); fell back to council-heuristic-v1';
          progress?.('⚠ ' + fallbackWarning);
          for (const c of llmQueue) {
            const fb = { ...policyById.get(c.id)!, fallbackReason: fallbackWarning };
            councilById.set(c.id, fb);
          }
        }
      }
    }
  } finally {
    if (wantsLlm) closeActiveProviderSessions();
  }

  const rawEvaluated: EvaluatedFinding[] = [];
  for (const c of candidates) {
    const council = councilById.get(c.id);
    const verdict = council?.judge.verdict ?? 'UNREVIEWED';
    const ciBlocking = policyById.get(c.id)?.judge.verdict === 'CONFIRMED';
    const item: EvaluatedFinding = { ...c, verdict, ciBlocking, council };
    if (options.prove && ciBlocking) {
      item.proof = inspectStaticEvidence(item);
    }
    rawEvaluated.push(item);
  }

  const evaluated = sortEvaluatedFindings(rawEvaluated);

  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let confirmed = 0;
  let unreviewed = 0;
  let uncertain = 0;
  let dismissed = 0;

  for (const f of evaluated) {
    const v = f.verdict;
    if (v === 'CONFIRMED') {
      confirmed += 1;
      const sev = f.council?.judge.finalSeverity ?? f.initialSeverity;
      bySeverity[sev] += 1;
    } else if (v === 'UNREVIEWED') {
      unreviewed += 1;
    } else if (v === 'UNCERTAIN') {
      uncertain += 1;
    } else {
      dismissed += 1;
    }
  }

  const coverage = filesScanned === 0 ? 'empty' : scanIssues.length ? 'partial' : 'complete';
  const { score, grade } = coverage === 'complete' && actualMode !== 'off'
    ? computeScoreAndGrade(evaluated)
    : { score: null, grade: null };

  return {
    version: VERSION,
    targetPath: targets.join(', ') || '(no agent paths found)',
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - t0,
    filesScanned,
    coverage,
    scanIssues,
    councilMode: actualMode,
    modelName,
    fallbackWarning,
    grade,
    score,
    summary: {
      totalCandidates: evaluated.length,
      ciBlocking: evaluated.filter((finding) => finding.ciBlocking).length,
      confirmed,
      unreviewed,
      uncertain,
      dismissed,
      bySeverity,
    },
    findings: evaluated,
  };
}

export { RULES_CATALOG, buildSarifReport, VERSION };
export * from './types.js';
