import type { CandidateFinding, CouncilReview, Severity, VerdictStatus } from '../types.js';
import {
  callLLMJson,
  parseProviderSpec,
  resolveProvider,
  type LLMProviderConfig,
  type ProviderName,
} from './providers.js';

export interface DeliberationOptions {
  mode?: 'auto' | 'llm' | 'heuristic' | 'off';
  provider?: ProviderName;
  model?: string;
  advocateSpec?: string;
  skepticSpec?: string;
  judgeSpec?: string;
  strictLlm?: boolean;
}

function isInsideMarkdownCodeExample(c: CandidateFinding): boolean {
  if (c.inCodeFence) return true;
  return /```|~~~|\b(?:anti-pattern|do not do|never do in production|example of bad|for example)\b/i.test(
    c.contextWindow,
  );
}

function isPlaceholderSecret(c: CandidateFinding): boolean {
  if (c.isPlaceholderHint) return true;
  return /(?:YOUR_|EXAMPLE|PLACEHOLDER|xxxx|000000|123456|changeme|dummy|test_key|fake)/i.test(c.snippet);
}

export function isTestFilePath(relativePath: string): boolean {
  const norm = relativePath.replace(/\\/g, '/');
  return /(?:^|\/)(?:tests?|__tests__|__mocks__|spec|testdata|fixtures)\/|(?:_test\.go|_test\.py|(?:^|\/)test_[^/]+\.py|\.(?:test|spec)\.[a-z0-9]+)$/i.test(
    norm,
  );
}

export function isFastDismissableCandidate(c: CandidateFinding): boolean {
  if (isTestFilePath(c.relativePath)) return true;
  if (c.isPlaceholderHint && c.ruleId === 'AHC-004') return true;
  if (
    isInsideMarkdownCodeExample(c) &&
    (c.category === 'skill-markdown' || c.category === 'agent-instructions') &&
    c.ruleId !== 'AHC-001' &&
    c.ruleId !== 'AHC-007'
  ) {
    return true;
  }
  return false;
}

function buildMinimalPatch(c: CandidateFinding): string {
  const file = c.relativePath;
  if (c.ruleId === 'AHC-004') {
    const redacted = c.snippet.replace(
      /([A-Za-z0-9_-]{4,}…\[REDACTED\]…[A-Za-z0-9_-]{2,}|\[REDACTED\]|sk-[A-Za-z0-9_-]+|ghp_[A-Za-z0-9]+|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]+|:\/\/[^:\s]+:[^@\s]+@)/g,
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
      /[\u200B\u200C\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u{E0000}-\u{E007F}]/gu,
      '',
    );
    return `--- a/${file}\n+++ b/${file}\n@@ -${c.line},1 +${c.line},1 @@\n-${c.snippet}  # [contains hidden Unicode]\n+${stripped}`;
  }
  if (c.ruleId === 'AHC-009') {
    const tlsFixed = c.snippet
      .replace(/http:\/\//i, 'https://')
      .replace(/(?:[a-z0-9-]+\.)?(?:ngrok-free\.app|ngrok\.io|trycloudflare\.com|localtunnel\.me|loca\.lt|serveo\.net)/i, 'mcp.internal.example');
    return `--- a/${file}\n+++ b/${file}\n@@ -${c.line},1 +${c.line},1 @@\n-${c.snippet}\n+${tlsFixed}`;
  }
  return `--- a/${file}\n+++ b/${file}\n@@ -${c.line},1 +${c.line},0 @@\n-${c.snippet}\n+# Removed unsafe agent directive (${c.ruleId})`;
}

export function runHeuristicCouncil(c: CandidateFinding): CouncilReview {
  const t0 = Date.now();
  const docContext = isInsideMarkdownCodeExample(c);
  const placeholder = isPlaceholderSecret(c);
  const isTestFile = isTestFilePath(c.relativePath);

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
              : c.ruleId === 'AHC-009'
                ? `Remote MCP transport in ${c.relativePath}:${c.line} sends tool invocations over unencrypted HTTP or an ephemeral public tunnel susceptible to interception or subdomain takeover.`
                : c.ruleId === 'AHC-010'
                  ? `Directive or script in ${c.relativePath}:${c.line} modifies persistent agent config, git hooks, or scheduled tasks to survive beyond the current session.`
                  : `Unsafe capability or exfiltration sink in ${c.relativePath}:${c.line} allows untrusted prompt input to reach host shell/network boundaries.`,
    attackerControl:
      c.category === 'mcp-config' || c.category === 'agent-settings'
        ? 'Local config / upstream package or remote endpoint operator control'
        : 'Indirect prompt injection via repository / skill / MCP metadata',
    blastRadius:
      c.initialSeverity === 'critical'
        ? 'Full credential theft (~/.ssh, ~/.aws, .env), persistent backdoor, or arbitrary host command execution'
        : 'Privilege escalation, traffic interception, or silent policy bypass inside the agent session',
    confidence: docContext || placeholder || isTestFile ? 0.45 : 0.91,
    modelUsed: 'council-heuristic-v1',
  };

  const mitigatingFactors: string[] = [];
  if (isTestFile) {
    mitigatingFactors.push('Finding resides inside a test suite or fixture file rather than an active runtime agent path.');
  }
  if (docContext && (c.category === 'skill-markdown' || c.category === 'agent-instructions')) {
    mitigatingFactors.push('Snippet resides inside a fenced Markdown code block or anti-pattern documentation example.');
  }
  if (placeholder) {
    mitigatingFactors.push('Matched value is a localhost/example connection string, dummy token, or documentation placeholder.');
  }
  if (c.ruleId === 'AHC-005' && c.category === 'skill-markdown') {
    mitigatingFactors.push('Command appears in markdown prose rather than an auto-executed .mcp.json or hook.');
  }

  const fpLikelihood =
    isTestFile
      ? 0.88
      : placeholder && c.ruleId === 'AHC-004'
        ? 0.9
        : docContext && c.ruleId !== 'AHC-001' && c.ruleId !== 'AHC-007'
          ? 0.84
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
    modelUsed: 'council-heuristic-v1',
  };

  let verdict: VerdictStatus = 'CONFIRMED';
  let finalSeverity: Severity = c.initialSeverity;
  let confidence = 0.9;
  let rationale = '';

  if (fpLikelihood >= 0.75) {
    verdict = 'DISMISSED';
    confidence = 0.86;
    rationale = `Skeptic demonstrated high likelihood of benign documentation/placeholder/test context (${Math.round(fpLikelihood * 100)}%). Dismissed to prevent alert fatigue.`;
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
      modelUsed: 'council-heuristic-v1',
    },
    mode: 'heuristic',
    modelUsed: 'council-heuristic-v1',
    durationMs: Math.max(1, Date.now() - t0),
  };
}

function labelForCfg(cfg: LLMProviderConfig): string {
  return `${cfg.provider}:${cfg.model}`;
}

export async function runLLMCouncil(
  c: CandidateFinding,
  roles: { advocate: LLMProviderConfig; skeptic: LLMProviderConfig; judge: LLMProviderConfig },
): Promise<CouncilReview> {
  const t0 = Date.now();
  const baseContext = [
    `Rule: ${c.ruleId} (${c.ruleName}) [${c.cwe}]`,
    `File: ${c.relativePath}:${c.line} (category: ${c.category})`,
    `Inside Markdown Code Fence: ${c.inCodeFence ? 'yes' : 'no'}`,
    `Placeholder/Localhost Hint: ${c.isPlaceholderHint ? 'yes' : 'no'}`,
    `Evidence: ${c.evidence}`,
    `Code Context (secrets pre-redacted):\n${c.contextWindow}`,
  ].join('\n');

  const [advocate, skeptic] = await Promise.all([
    callLLMJson<CouncilReview['advocate']>(
      roles.advocate,
      'You are ADVOCATE on an AI Agent Security Model Council. Build the strongest realistic exploit case supported by the source, checking attacker control, agent context ingestion, reachability, and blast radius. Return JSON with keys: exploitScenario (string), attackerControl (string), blastRadius (string), confidence (number 0..1).',
      baseContext,
    ),
    callLLMJson<CouncilReview['skeptic']>(
      roles.skeptic,
      'You are SKEPTIC on an AI Agent Security Model Council. Try to disprove false positives by checking if this is benign documentation, a fenced example, a dummy placeholder secret, a test fixture, or an ordinary user-intended CLI step. Return JSON with keys: counterArgument (string), mitigatingFactors (string[]), falsePositiveLikelihood (number 0..1).',
      baseContext,
    ),
  ]);

  const judge = await callLLMJson<CouncilReview['judge']>(
    roles.judge,
    'You are JUDGE on an AI Agent Security Model Council. Read the source evidence, Advocate brief, and Skeptic brief. If Skeptic proves it is a benign example, test fixture, placeholder, or ordinary documentation, output verdict="DISMISSED". If Advocate and Skeptic reasonably disagree without clear proof, output verdict="UNCERTAIN". Otherwise output verdict="CONFIRMED". Return JSON with keys: verdict ("CONFIRMED"|"UNCERTAIN"|"DISMISSED"), finalSeverity ("critical"|"high"|"medium"|"low"), confidence (number 0..1), rationale (string), minimalPatch (optional unified diff string).',
    `${baseContext}\n\nADVOCATE BRIEF:\n${JSON.stringify(advocate)}\n\nSKEPTIC BRIEF:\n${JSON.stringify(skeptic)}`,
  );

  const advLabel = labelForCfg(roles.advocate);
  const skpLabel = labelForCfg(roles.skeptic);
  const jdgLabel = labelForCfg(roles.judge);
  const uniqueModels = new Set([advLabel, skpLabel, jdgLabel]);
  const summaryLabel =
    uniqueModels.size === 1 ? advLabel : `${advLabel} vs ${skpLabel} → ${jdgLabel}`;

  return {
    advocate: { ...advocate, modelUsed: advLabel },
    skeptic: { ...skeptic, modelUsed: skpLabel },
    judge: {
      ...judge,
      minimalPatch: judge.minimalPatch || (judge.verdict !== 'DISMISSED' ? buildMinimalPatch(c) : undefined),
      modelUsed: jdgLabel,
    },
    mode: 'llm',
    modelUsed: summaryLabel,
    durationMs: Date.now() - t0,
  };
}

function resolveRoleCfg(
  roleSpec: string | undefined,
  fallbackProvider: ProviderName | undefined,
  fallbackModel: string | undefined,
): LLMProviderConfig | null {
  if (roleSpec) {
    const parsed = parseProviderSpec(roleSpec);
    return resolveProvider(parsed.provider, parsed.model ?? fallbackModel);
  }
  return resolveProvider(fallbackProvider, fallbackModel);
}

export async function deliberateFinding(
  c: CandidateFinding,
  options: DeliberationOptions = {},
): Promise<CouncilReview | undefined> {
  const mode = options.mode ?? 'auto';
  if (mode === 'off') return undefined;

  const hasExplicitProvider = Boolean(
    options.provider || options.advocateSpec || options.skepticSpec || options.judgeSpec,
  );

  if (mode === 'heuristic' && !hasExplicitProvider) return runHeuristicCouncil(c);

  const hasEnvKey = Boolean(
    process.env.ANTHROPIC_API_KEY ||
      process.env.OPENAI_API_KEY ||
      process.env.GEMINI_API_KEY ||
      process.env.OPENROUTER_API_KEY ||
      process.env.OLLAMA_MODEL,
  );

  if (mode === 'auto' && !hasExplicitProvider && !hasEnvKey) {
    return runHeuristicCouncil(c);
  }

  // Fast-path deterministic dismissal for fenced code examples, test files, and localhost placeholders
  // so LLM calls are reserved for real ambiguous/active candidates.
  if (!options.strictLlm && isFastDismissableCandidate(c)) {
    return runHeuristicCouncil(c);
  }

  const advCfg = resolveRoleCfg(options.advocateSpec, options.provider, options.model);
  const skpCfg = resolveRoleCfg(options.skepticSpec, options.provider, options.model);
  const jdgCfg = resolveRoleCfg(options.judgeSpec, options.provider, options.model);

  if (!advCfg || !skpCfg || !jdgCfg) {
    const missingMsg =
      'No LLM provider or CLI found. Pass --provider claude-cli | codex-cli | gemini-cli | ollama, or set an API key.';
    if (mode === 'llm' || hasExplicitProvider || options.strictLlm) {
      throw new Error(missingMsg);
    }
    return runHeuristicCouncil(c);
  }

  try {
    return await runLLMCouncil(c, { advocate: advCfg, skeptic: skpCfg, judge: jdgCfg });
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    if (options.strictLlm) {
      throw new Error(`LLM Council failed (${reason})`);
    }
    const fallback = runHeuristicCouncil(c);
    fallback.fallbackReason = `LLM provider unavailable (${reason}); fell back to council-heuristic-v1`;
    return fallback;
  }
}
