#!/usr/bin/env node
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { ProviderName } from './council/providers.js';
import { createDemoWorkspace } from './fixtures/demo.js';
import { runAudit } from './index.js';
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
  --provider <name>       Zero-key CLI or API provider: claude-cli | codex-cli | gemini-cli | ollama | anthropic | openai | gemini | openrouter
  --model <name>          Override model name (e.g. sonnet, o4-mini, qwen2.5-coder:14b)
  --advocate <spec>       Per-role provider[:model] override (e.g. claude-cli:sonnet)
  --skeptic <spec>        Per-role provider[:model] override (e.g. codex-cli:o4-mini)
  --judge <spec>          Per-role provider[:model] override (e.g. ollama:qwen2.5-coder:14b)
  --council <mode>        Council mode: auto | llm | heuristic | off (default: auto)
  --max-llm <number>      Max candidates sent to live LLM Council per scan (default: 15)
  --strict-llm            Fail instead of falling back to heuristic if LLM provider is unavailable
  --prove                 Run ephemeral Canary Sandbox proof on confirmed findings
  --ui                    Launch interactive dark-mode Web Dashboard (http://127.0.0.1:4317)
  --port <number>         Port for --ui dashboard (default: 4317)
  --json                  Output structured JSON report to stdout
  --sarif                 Output SARIF 2.1.0 report to stdout (for GitHub Code Scanning)
  -o, --output <file>     Write JSON or SARIF report to file (inferred from --sarif or .sarif ext)
  --fail-on-confirmed     Exit with code 1 if any finding is CONFIRMED (for CI / GitHub Actions)
  -v, --version           Print version
  -h, --help              Show this help
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes('-h') || args.includes('--help')) {
    printHelp();
    return;
  }
  if (args.includes('-v') || args.includes('--version')) {
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
  let failOnConfirmed = false;
  let port = 4317;
  const positional: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--council' && args[i + 1]) {
      councilMode = args[++i] as typeof councilMode;
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
    } else if (a === '--fail-on-confirmed') {
      failOnConfirmed = true;
    } else if (a === '--port' && args[i + 1]) {
      port = Number(args[++i]) || 4317;
    } else if (!a.startsWith('-')) {
      positional.push(a);
    }
  }

  if (positional[0] === 'rules') {
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

  if (positional[0] === 'demo') {
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
    const report = await runAudit({
      targets,
      councilMode,
      provider,
      model,
      advocateSpec,
      skepticSpec,
      judgeSpec,
      maxLlmFindings,
      strictLlm,
      prove,
      onProgress,
    });

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
      console.log(renderCliReport(report));
      if (outputFile) {
        console.log(`  📄 Report saved to ${outputFile}\n`);
      }
    }

    if (ui) {
      const { url } = await startWebDashboard(report, port, prove);
      console.log(`  🌐 Web UI live at \x1b[1m\x1b[36m${url}\x1b[0m (Press Ctrl+C to stop)\n`);
      await new Promise(() => {}); // keep server alive until SIGINT
    }

    if (failOnConfirmed && report.summary.confirmed > 0) {
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
