import {
  isFastDismissableCandidate,
  resolveCouncilRoles,
  runHeuristicCouncil,
  runLLMCouncilBatch,
} from './council/index.js';
import { closeActiveProviderSessions, type ProviderName } from './council/providers.js';
import { runCanaryProof } from './prover/index.js';
import { discoverLocalAgentPaths, runStaticScan } from './scanner/index.js';
import { RULES_CATALOG } from './scanner/rules.js';
import type { CandidateFinding, EvaluatedFinding, ScanReport, Severity } from './types.js';
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
const VERDICT_RANK: Record<string, number> = { CONFIRMED: 0, UNCERTAIN: 1, DISMISSED: 2 };

function sortEvaluatedFindings(list: EvaluatedFinding[]): EvaluatedFinding[] {
  return [...list].sort((a, b) => {
    const va = VERDICT_RANK[a.council?.judge.verdict ?? 'CONFIRMED'] ?? 0;
    const vb = VERDICT_RANK[b.council?.judge.verdict ?? 'CONFIRMED'] ?? 0;
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
  const progress = options.onProgress;

  const targets =
    options.targets && options.targets.length > 0 ? options.targets : await discoverLocalAgentPaths();

  progress?.(`Scanning ${targets.length} target path(s) across 10 agent security rules...`);
  const scanStart = Date.now();
  const { filesScanned, candidates } = await runStaticScan(targets);
  const scanMs = Date.now() - scanStart;
  progress?.(`Scanned ${filesScanned} agent/MCP files in ${scanMs}ms -> ${candidates.length} candidate(s)`);

  const councilModePref = options.councilMode ?? 'auto';
  const hasExplicitProvider = Boolean(
    options.provider || options.advocateSpec || options.skepticSpec || options.judgeSpec,
  );
  const wantsLlm =
    councilModePref === 'llm' ||
    hasExplicitProvider ||
    (councilModePref === 'auto' &&
      Boolean(
        process.env.ANTHROPIC_API_KEY ||
          process.env.OPENAI_API_KEY ||
          process.env.GEMINI_API_KEY ||
          process.env.OPENROUTER_API_KEY ||
          process.env.OLLAMA_MODEL,
      ));

  const maxLlm = options.maxLlmFindings ?? 15;
  let actualMode: ScanReport['councilMode'] = councilModePref === 'off' ? 'off' : 'heuristic';
  let modelName = councilModePref === 'off' ? 'none' : 'council-heuristic-v1';
  let fallbackWarning: string | undefined;

  const councilById = new Map<string, EvaluatedFinding['council']>();

  try {
    if (councilModePref !== 'off') {
      const llmQueue: CandidateFinding[] = [];

      for (const c of candidates) {
        if (!wantsLlm || isFastDismissableCandidate(c) || llmQueue.length >= maxLlm) {
          councilById.set(c.id, runHeuristicCouncil(c));
        } else {
          llmQueue.push(c);
        }
      }

      if (llmQueue.length > 0) {
        const roles = resolveCouncilRoles({
          mode: councilModePref,
          provider: options.provider,
          model: options.model,
          advocateSpec: options.advocateSpec,
          skepticSpec: options.skepticSpec,
          judgeSpec: options.judgeSpec,
          strictLlm: options.strictLlm,
        });

        if (!roles) {
          const msg =
            'No LLM provider or CLI found. Pass --provider antigravity | claude-cli | codex-cli | gemini-cli | ollama, or set an API key.';
          if (councilModePref === 'llm' || hasExplicitProvider || options.strictLlm) {
            throw new Error(msg);
          }
          for (const c of llmQueue) {
            councilById.set(c.id, runHeuristicCouncil(c));
          }
        } else {
          try {
            const batchReviews = await runLLMCouncilBatch(llmQueue, roles, progress);
            for (const c of llmQueue) {
              const rev = batchReviews.get(c.id) ?? runHeuristicCouncil(c);
              councilById.set(c.id, rev);
              if (rev.mode === 'llm') {
                actualMode = 'llm';
                modelName = rev.modelUsed;
              }
            }
          } catch (err) {
            const reason = err instanceof Error ? err.message : String(err);
            if (options.strictLlm) {
              throw new Error(`LLM Council failed (${reason})`);
            }
            fallbackWarning = `LLM provider unavailable (${reason}); fell back to council-heuristic-v1`;
            progress?.(`⚠ ${fallbackWarning}`);
            for (const c of llmQueue) {
              const fb = runHeuristicCouncil(c);
              fb.fallbackReason = fallbackWarning;
              councilById.set(c.id, fb);
            }
          }
        }
      }
    }
  } finally {
    closeActiveProviderSessions();
  }

  const rawEvaluated: EvaluatedFinding[] = [];
  for (const c of candidates) {
    const council = councilById.get(c.id);
    const item: EvaluatedFinding = { ...c, council };
    if (options.prove && (council?.judge.verdict ?? 'CONFIRMED') === 'CONFIRMED') {
      item.proof = await runCanaryProof(item);
    }
    rawEvaluated.push(item);
  }

  const evaluated = sortEvaluatedFindings(rawEvaluated);

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
    version: VERSION,
    targetPath: targets.join(', ') || '(no agent paths found)',
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - t0,
    filesScanned,
    councilMode: actualMode,
    modelName,
    fallbackWarning,
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

export { RULES_CATALOG, buildSarifReport, VERSION };
export * from './types.js';
