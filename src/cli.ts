#!/usr/bin/env node
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { ProviderName } from './council/providers.js';
import { createDemoWorkspace } from './fixtures/demo.js';
import { runAudit, type AuditOptions } from './index.js';
import { renderCliReport, renderRulesCatalog } from './ui/cli-reporter.js';
import { buildSarifReport } from './ui/sarif.js';
import { startWebDashboard } from './ui/web-server.js';
import { VERSION } from './version.js';

function printHelp(): void {
  console.log(`
⚡ agenthack-council v${VERSION} — Adversarial AI Security Harness for Agents, MCP & Skills

Usage:
  npx agenthack-council [path...] [options]
  npx agenthack-council demo [--ui]
  npx agenthack-council rules

Options:
  --provider <name>       Zero-key CLI or API provider: antigravity (agy-cli) | claude-cli | codex-cli | gemini-cli | ollama | anthropic | openai | gemini | openrouter
  --model <name>          Override model name (e.g. sonnet, o4-mini, qwen2.5-coder:14b)
  --advocate <spec>       Per-role provider[:model] override (e.g. claude-cli:sonnet)
  --skeptic <spec>        Per-role provider[:model] override (e.g. codex-cli:o4-mini)
  --judge <spec>          Per-role provider[:model] override (e.g. ollama:qwen2.5-coder:14b)
  --council <mode>        Council mode: auto | llm | heuristic | off (auto is offline without a provider choice)
  --max-llm <number>      Max candidates sent to live LLM Council per scan (default: 15)
  --strict-llm            Fail instead of falling back to heuristic if LLM review fails or returns incomplete results
  --prove                 Add static evidence annotations to CI policy findings
  --ui                    Launch interactive dark-mode Web Dashboard (http://127.0.0.1:4317)
  --port <number>         Port for --ui dashboard (default: 4317)
  --json                  Output structured JSON report to stdout
  --sarif                 Output SARIF 2.1.0 report to stdout (for GitHub Code Scanning)
  -o, --output <file>     Write JSON or SARIF report to file (inferred from --sarif or .sarif ext)
  --fail-on-policy        Exit with code 1 for a deterministic CI policy finding
  --fail-on-confirmed     Alias for --fail-on-policy
  --verbose               Print all dismissed false-positive details in CLI output
  -v, --version           Print version
  -h, --help              Show this help
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const separator = args.indexOf('--');
  const flags = separator === -1 ? args : args.slice(0, separator);
  if (flags.includes('-h') || flags.includes('--help')) {
    printHelp();
    return;
  }
  if (flags.includes('-v') || flags.includes('--version')) {
    console.log(VERSION);
    return;
  }

  let councilMode: 'auto' | 'llm' | 'heuristic' | 'off' = 'auto';
  let provider: ProviderName | undefined;
  let model: string | undefined;
  let advocateSpec: string | undefined;
  let skepticSpec: string | undefined;
  let judgeSpec: string | undefined;
  let maxLlmFindings = 15;
  let strictLlm = false;
  let prove = false;
  let ui = false;
  let jsonOut = false;
  let sarifOut = false;
  let outputFile: string | undefined;
  let failOnPolicy = false;
  let verbose = false;
  let port = 4317;
  const positional: string[] = [];
  let subcommand: 'rules' | 'demo' | undefined;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') {
      positional.push(...args.slice(i + 1));
      break;
    }
    if (a === '--council') {
      const mode = args[++i];
      if (mode !== 'auto' && mode !== 'llm' && mode !== 'heuristic' && mode !== 'off') {
        throw new Error('--council expects auto, llm, heuristic, or off');
      }
      councilMode = mode;
    } else if (a === '--provider' && args[i + 1]) {
      provider = args[++i] as ProviderName;
    } else if (a === '--model' && args[i + 1]) {
      model = args[++i];
    } else if (a === '--advocate' && args[i + 1]) {
      advocateSpec = args[++i];
    } else if (a === '--skeptic' && args[i + 1]) {
      skepticSpec = args[++i];
    } else if (a === '--judge' && args[i + 1]) {
      judgeSpec = args[++i];
    } else if (a === '--max-llm' && args[i + 1]) {
      maxLlmFindings = Math.max(1, Number(args[++i]) || 15);
    } else if (a === '--strict-llm') {
      strictLlm = true;
    } else if (a === '--prove') {
      prove = true;
    } else if (a === '--ui') {
      ui = true;
    } else if (a === '--json') {
      jsonOut = true;
    } else if (a === '--sarif') {
      sarifOut = true;
    } else if ((a === '-o' || a === '--output') && args[i + 1]) {
      outputFile = args[++i];
    } else if (a === '--fail-on-policy' || a === '--fail-on-confirmed') {
      failOnPolicy = true;
    } else if (a === '--verbose') {
      verbose = true;
    } else if (a === '--port' && args[i + 1]) {
      port = Number(args[++i]) || 4317;
    } else if (!a.startsWith('-')) {
      if (!subcommand && positional.length === 0 && (a === 'rules' || a === 'demo')) {
        subcommand = a;
      } else {
        positional.push(a);
      }
    }
  }

  if (subcommand === 'rules') {
    console.log(renderRulesCatalog());
    return;
  }

  let demoDir: string | null = null;
  let targets = positional;

  // Smart UX guard: if a user runs `agenthack-council .` directly from their OS home directory (`~`),
  // automatically route to `discoverLocalAgentPaths()` instead of crawling the entire home disk.
  if (
    targets.length === 1 &&
    path.resolve(targets[0]) === path.resolve(os.homedir())
  ) {
    if (!jsonOut && !sarifOut) {
      process.stderr.write(
        `  ℹ Detected home directory (~); targeting active local agent configs (~/.claude, ~/.cursor, ~/.codex, ~/.gemini/config)...\n`,
      );
    }
    targets = [];
  }

  if (subcommand === 'demo') {
    demoDir = await createDemoWorkspace();
    targets = [demoDir];
    prove = true;
  }

  const quietProgress = (jsonOut || sarifOut) && !outputFile;
  const onProgress = quietProgress
    ? undefined
    : (msg: string) => {
        process.stderr.write(`  \x1b[90m◇ ${msg}\x1b[0m\n`);
      };

  try {
    const auditOptions: AuditOptions = {
      targets,
      councilMode,
      provider,
      model,
      advocateSpec,
      skepticSpec,
      judgeSpec,
      maxLlmFindings,
      strictLlm: strictLlm && !failOnPolicy,
      prove,
      onProgress,
    };
    if (strictLlm && failOnPolicy) {
      process.stderr.write('LLM triage is best effort when the CI policy gate is enabled.\n');
    }
    const report = await runAudit(auditOptions);

    if (outputFile) {
      const writeAsSarif = sarifOut || outputFile.toLowerCase().endsWith('.sarif');
      const payload = writeAsSarif ? buildSarifReport(report) : report;
      await fs.writeFile(outputFile, JSON.stringify(payload, null, 2) + '\n', 'utf8');
    }

    if (sarifOut && !outputFile) {
      console.log(JSON.stringify(buildSarifReport(report), null, 2));
    } else if (jsonOut && !outputFile) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(renderCliReport(report, { showDismissed: verbose }));
      if (outputFile) {
        console.log(`  📄 Report saved to ${outputFile}\n`);
      }
    }

    if (ui) {
      const { url } = await startWebDashboard(report, port, auditOptions);
      console.log(`  🌐 Web UI live at \x1b[1m\x1b[36m${url}\x1b[0m (Press Ctrl+C to stop)\n`);
      await new Promise(() => {}); // keep server alive until SIGINT
    }

    if (report.coverage !== 'complete') {
      process.exitCode = 2;
    } else if (failOnPolicy && report.summary.ciBlocking > 0) {
      process.exitCode = 1;
    }
  } finally {
    if (demoDir && !ui) {
      await fs.rm(demoDir, { recursive: true, force: true });
    }
  }
}

main().catch((err) => {
  console.error('agenthack-council error:', err instanceof Error ? err.message : err);
  process.exit(1);
});
