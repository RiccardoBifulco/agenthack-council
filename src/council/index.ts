import type { CandidateFinding, CouncilReview, Severity, VerdictStatus } from '../types.js';
import { callLLMJson, detectLLMProvider, type LLMProviderConfig } from './providers.js';

function isInsideMarkdownCodeExample(contextWindow: string): boolean {
  return /```|\b(?:anti-pattern|do not do|never do in production|example of bad|for example)\b/i.test(
    contextWindow,
  );
}

function isPlaceholderSecret(snippet: string): boolean {
  return /(?:YOUR_|EXAMPLE|PLACEHOLDER|xxxx|000000|123456|changeme|dummy|test_key|fake)/i.test(snippet);
}

function buildMinimalPatch(c: CandidateFinding): string {
  const file = c.relativePath;
  if (c.ruleId === 'AHC-004') {
    const redacted = c.snippet.replace(
      /(sk-[A-Za-z0-9_-]+|ghp_[A-Za-z0-9]+|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]+|:\/\/[^:\s]+:[^@\s]+@)/g,
      '${ENV_SECRET_REF}',
    );
    return `--- a/${file}\n+++ b/${file}\n@@ -${c.line},1 +${c.line},1 @@\n-${c.snippet}\n+${redacted}`;
  }
  if (c.ruleId === 'AHC-005') {
    const pinned = c.snippet.replace(/npx\s+(-y|--yes)\s+([@\w./-]+)/, 'npx $2@<pinned-version>');
    return `--- a/${file}\n+++ b/${file}\n@@ -${c.line},1 +${c.line},1 @@\n-${c.snippet}\n+${pinned}`;
  }
  if (c.ruleId === 'AHC-001') {
    const stripped = c.snippet.replace(
      /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u{E0000}-\u{E007F}]/gu,
      '',
    );
    return `--- a/${file}\n+++ b/${file}\n@@ -${c.line},1 +${c.line},1 @@\n-${c.snippet}  # [contains hidden Unicode]\n+${stripped}`;
  }
  return `--- a/${file}\n+++ b/${file}\n@@ -${c.line},1 +${c.line},0 @@\n-${c.snippet}\n+# Removed unsafe agent directive (${c.ruleId})`;
}

export function runHeuristicCouncil(c: CandidateFinding): CouncilReview {
  const t0 = Date.now();
  const docContext = isInsideMarkdownCodeExample(c.contextWindow);
  const placeholder = isPlaceholderSecret(c.snippet);
  const isTestFile = /(?:^|\/)(?:tests?|__tests__|spec|testdata|fixtures)\/|\.(?:test|spec)\.[a-z]+$/i.test(
    c.relativePath.replace(/\\/g, '/'),
  );

  // Advocate always builds the strongest offensive case
  const advocate = {
    exploitScenario:
      c.ruleId === 'AHC-003'
        ? `An agent loading ${c.relativePath} ingests the poisoned tool/skill directive into its system context, coercing the LLM into reading sensitive host files and passing them as tool arguments without user consent.`
        : c.ruleId === 'AHC-001' || c.ruleId === 'AHC-002' || c.ruleId === 'AHC-007'
          ? `Covert instructions smuggled in ${c.relativePath}:${c.line} are invisible to human PR reviewers in GitHub/IDE diffs but tokenized directly by the coding agent's LLM.`
          : c.ruleId === 'AHC-004'
            ? `Hardcoded credentials in ${c.relativePath} are exposed to local agent context windows, repo clones, and diagnostic telemetry.`
            : c.ruleId === 'AHC-005'
              ? `Unpinned dynamic execution in ${c.relativePath} pulls mutable upstream code on every agent startup, enabling silent supply-chain RCE.`
              : `Unsafe capability or exfiltration sink in ${c.relativePath}:${c.line} allows untrusted prompt input to reach host shell/network boundaries.`,
    attackerControl:
      c.category === 'mcp-config' || c.category === 'agent-settings'
        ? 'Local config / upstream package maintainer control'
        : 'Indirect prompt injection via repository / skill / MCP metadata',
    blastRadius:
      c.initialSeverity === 'critical'
        ? 'Full credential theft (~/.ssh, ~/.aws, .env) or arbitrary host command execution'
        : 'Privilege escalation or silent policy bypass inside the agent session',
    confidence: docContext || placeholder ? 0.58 : 0.91,
  };

  // Skeptic tries to disprove false positives
  const mitigatingFactors: string[] = [];
  if (isTestFile) {
    mitigatingFactors.push('Finding resides inside a test suite or fixture file rather than an active runtime agent path.');
  }
  if (docContext && (c.category === 'skill-markdown' || c.category === 'agent-instructions')) {
    mitigatingFactors.push('Snippet appears adjacent to documentation/example markers or fenced code blocks.');
  }
  if (placeholder) {
    mitigatingFactors.push('Matched value resembles a documentation placeholder or dummy token.');
  }
  if (c.ruleId === 'AHC-005' && c.category === 'skill-markdown') {
    mitigatingFactors.push('Command appears in markdown prose rather than an auto-executed .mcp.json or hook.');
  }

  const fpLikelihood =
    isTestFile
      ? 0.86
      : placeholder && c.ruleId === 'AHC-004'
        ? 0.88
        : docContext && c.ruleId !== 'AHC-001' && c.ruleId !== 'AHC-007'
          ? 0.79
          : c.ruleId === 'AHC-005' && c.category === 'skill-markdown'
            ? 0.62
            : 0.14;

  const skeptic = {
    counterArgument:
      mitigatingFactors.length > 0
        ? mitigatingFactors.join(' ')
        : `No sandboxing, allowlist, or documentation fence surrounds ${c.relativePath}:${c.line}; the directive sits in an active agent ingestion path.`,
    mitigatingFactors,
    falsePositiveLikelihood: fpLikelihood,
  };

  // Judge weighs Advocate vs Skeptic (withholds confirmation when ambiguous!)
  let verdict: VerdictStatus = 'CONFIRMED';
  let finalSeverity: Severity = c.initialSeverity;
  let confidence = 0.9;
  let rationale = '';

  if (fpLikelihood >= 0.75) {
    verdict = 'DISMISSED';
    confidence = 0.85;
    rationale = `Skeptic demonstrated high likelihood of benign documentation/placeholder context (${Math.round(fpLikelihood * 100)}%). Dismissed to prevent alert fatigue.`;
  } else if (fpLikelihood >= 0.5) {
    verdict = 'UNCERTAIN';
    finalSeverity = c.initialSeverity === 'critical' ? 'high' : 'medium';
    confidence = 0.55;
    rationale =
      'Advocate and Skeptic disagree on whether this line is automatically executed or purely instructional. Withholding confirmation per council policy.';
  } else {
    verdict = 'CONFIRMED';
    confidence = Math.round(((advocate.confidence + (1 - fpLikelihood)) / 2) * 100) / 100;
    rationale = `Advocate established direct agent reachability in ${c.category} (${c.relativePath}:${c.line}) and Skeptic found no mitigating fence or sandbox guard.`;
  }

  return {
    advocate,
    skeptic,
    judge: {
      verdict,
      finalSeverity,
      confidence,
      rationale,
      minimalPatch: verdict !== 'DISMISSED' ? buildMinimalPatch(c) : undefined,
    },
    mode: 'heuristic',
    modelUsed: 'council-heuristic-v1',
    durationMs: Math.max(1, Date.now() - t0),
  };
}

export async function runLLMCouncil(
  c: CandidateFinding,
  cfg: LLMProviderConfig,
): Promise<CouncilReview> {
  const t0 = Date.now();
  const baseContext = [
    `Rule: ${c.ruleId} (${c.ruleName}) [${c.cwe}]`,
    `File: ${c.relativePath}:${c.line} (category: ${c.category})`,
    `Evidence: ${c.evidence}`,
    `Code Context:\n${c.contextWindow}`,
  ].join('\n');

  const [advocate, skeptic] = await Promise.all([
    callLLMJson<CouncilReview['advocate']>(
      cfg,
      'You are ADVOCATE on an AI Agent Security Model Council. Build the strongest realistic exploit case supported by the source, checking attacker control, agent context ingestion, reachability, and blast radius. Return JSON with keys: exploitScenario (string), attackerControl (string), blastRadius (string), confidence (number 0..1).',
      baseContext,
    ),
    callLLMJson<CouncilReview['skeptic']>(
      cfg,
      'You are SKEPTIC on an AI Agent Security Model Council. Try to disprove false positives by checking if this is benign documentation, a fenced example, a dummy placeholder secret, or unreachable without user intent. Return JSON with keys: counterArgument (string), mitigatingFactors (string[]), falsePositiveLikelihood (number 0..1).',
      baseContext,
    ),
  ]);

  const judge = await callLLMJson<CouncilReview['judge']>(
    cfg,
    'You are JUDGE on an AI Agent Security Model Council. Read the source evidence, Advocate brief, and Skeptic brief. If Skeptic proves it is a benign example or placeholder, output verdict="DISMISSED". If Advocate and Skeptic reasonably disagree without clear proof, output verdict="UNCERTAIN". Otherwise output verdict="CONFIRMED". Return JSON with keys: verdict ("CONFIRMED"|"UNCERTAIN"|"DISMISSED"), finalSeverity ("critical"|"high"|"medium"|"low"), confidence (number 0..1), rationale (string), minimalPatch (optional unified diff string).',
    `${baseContext}\n\nADVOCATE BRIEF:\n${JSON.stringify(advocate)}\n\nSKEPTIC BRIEF:\n${JSON.stringify(skeptic)}`,
  );

  return {
    advocate,
    skeptic,
    judge: {
      ...judge,
      minimalPatch: judge.minimalPatch || (judge.verdict !== 'DISMISSED' ? buildMinimalPatch(c) : undefined),
    },
    mode: 'llm',
    modelUsed: `${cfg.provider}:${cfg.model}`,
    durationMs: Date.now() - t0,
  };
}

export async function deliberateFinding(
  c: CandidateFinding,
  options: { mode?: 'auto' | 'llm' | 'heuristic' | 'off'; model?: string } = {},
): Promise<CouncilReview | undefined> {
  const mode = options.mode ?? 'auto';
  if (mode === 'off') return undefined;
  if (mode === 'heuristic') return runHeuristicCouncil(c);

  const llmCfg = detectLLMProvider(options.model);
  if (!llmCfg) {
    if (mode === 'llm') {
      throw new Error(
        'Council mode "llm" requested, but no API key found (set ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY, OPENROUTER_API_KEY, or OLLAMA_MODEL).',
      );
    }
    return runHeuristicCouncil(c);
  }

  try {
    return await runLLMCouncil(c, llmCfg);
  } catch {
    return runHeuristicCouncil(c);
  }
}
