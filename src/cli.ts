#!/usr/bin/env node
import fs from 'node:fs/promises';
import { createDemoWorkspace } from './fixtures/demo.js';
import { runAudit } from './index.js';
import { renderCliReport } from './ui/cli-reporter.js';
import { startWebDashboard } from './ui/web-server.js';

function printHelp(): void {
  console.log(`
⚡ agenthack-council — Adversarial AI Security Harness for Agents, MCP & Skills

Usage:
  npx agenthack-council [path...] [options]
  npx agenthack-council demo [--ui]

Options:
  --council <mode>   Council mode: auto | llm | heuristic | off (default: auto)
  --model <name>     Override LLM model (uses ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY, OPENROUTER_API_KEY, or OLLAMA_MODEL)
  --prove            Run ephemeral Canary Sandbox proof on confirmed findings
  --ui               Launch interactive dark-mode Web Dashboard (http://127.0.0.1:4317)
  --port <number>    Port for --ui dashboard (default: 4317)
  --json             Output structured JSON report
  --fail-on-confirmed Exit with code 1 if any finding is CONFIRMED (for CI / GitHub Actions)
  -h, --help         Show this help
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes('-h') || args.includes('--help')) {
    printHelp();
    return;
  }

  let councilMode: 'auto' | 'llm' | 'heuristic' | 'off' = 'auto';
  let model: string | undefined;
  let prove = false;
  let ui = false;
  let jsonOut = false;
  let failOnConfirmed = false;
  let port = 4317;
  const positional: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--council' && args[i + 1]) {
      councilMode = args[++i] as typeof councilMode;
    } else if (a === '--model' && args[i + 1]) {
      model = args[++i];
    } else if (a === '--prove') {
      prove = true;
    } else if (a === '--ui') {
      ui = true;
    } else if (a === '--json') {
      jsonOut = true;
    } else if (a === '--fail-on-confirmed') {
      failOnConfirmed = true;
    } else if (a === '--port' && args[i + 1]) {
      port = Number(args[++i]) || 4317;
    } else if (!a.startsWith('-')) {
      positional.push(a);
    }
  }

  let demoDir: string | null = null;
  let targets = positional;

  if (positional[0] === 'demo') {
    demoDir = await createDemoWorkspace();
    targets = [demoDir];
    prove = true;
  }

  try {
    const report = await runAudit({ targets, councilMode, model, prove });

    if (jsonOut) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(renderCliReport(report));
    }

    if (ui) {
      const url = await startWebDashboard(report, port, prove);
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
