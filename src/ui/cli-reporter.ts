import type { EvaluatedFinding, ScanReport, Severity } from '../types.js';

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[38;5;203m',
  orange: '\x1b[38;5;214m',
  yellow: '\x1b[38;5;221m',
  green: '\x1b[38;5;84m',
  cyan: '\x1b[38;5;81m',
  blue: '\x1b[38;5;75m',
  purple: '\x1b[38;5;141m',
  gray: '\x1b[38;5;245m',
  bgRed: '\x1b[48;5;52m',
  bgGreen: '\x1b[48;5;22m',
  bgYellow: '\x1b[48;5;58m',
};

function sevBadge(s: Severity): string {
  if (s === 'critical') return `${C.bgRed}${C.red}${C.bold} CRITICAL ${C.reset}`;
  if (s === 'high') return `${C.red}${C.bold}HIGH${C.reset}`;
  if (s === 'medium') return `${C.orange}MEDIUM${C.reset}`;
  return `${C.cyan}LOW${C.reset}`;
}

function gradeBadge(grade: ScanReport['grade'], score: number): string {
  const color = score >= 90 ? C.green : score >= 70 ? C.yellow : C.red;
  return `${color}${C.bold}${grade} (${score}/100)${C.reset}`;
}

function verdictPill(f: EvaluatedFinding): string {
  const v = f.council?.judge.verdict ?? 'CONFIRMED';
  if (v === 'CONFIRMED') return `${C.bgRed}${C.red}${C.bold} ⚖ CONFIRMED ${C.reset}`;
  if (v === 'UNCERTAIN') return `${C.bgYellow}${C.yellow}${C.bold} ⚖ UNCERTAIN ${C.reset}`;
  return `${C.bgGreen}${C.green}${C.bold} ⚖ DISMISSED (FP) ${C.reset}`;
}

export function renderCliReport(report: ScanReport): string {
  const lines: string[] = [];
  const bar = `${C.gray}${'─'.repeat(76)}${C.reset}`;

  lines.push('');
  lines.push(
    `${C.bold}${C.cyan}⚡ AGENTHACK COUNCIL${C.reset} ${C.gray}v0.1.0 — Adversarial Security Harness for AI Agents & MCP${C.reset}`,
  );
  lines.push(bar);
  lines.push(
    `  ${C.gray}Target:${C.reset}  ${report.targetPath}\n` +
      `  ${C.gray}Scanned:${C.reset} ${report.filesScanned} agent/MCP files in ${report.durationMs}ms  ${C.gray}|${C.reset}  ` +
      `${C.gray}Council:${C.reset} ${C.purple}${report.modelName}${C.reset}\n` +
      `  ${C.gray}Posture:${C.reset} ${gradeBadge(report.grade, report.score)}  ${C.gray}|${C.reset}  ` +
      `${C.red}${C.bold}${report.summary.confirmed} Confirmed${C.reset} · ` +
      `${C.yellow}${report.summary.uncertain} Uncertain${C.reset} · ` +
      `${C.green}${report.summary.dismissed} Dismissed FPs${C.reset}`,
  );
  lines.push(bar);

  if (report.findings.length === 0) {
    lines.push(`  ${C.green}${C.bold}✓ Clean scan.${C.reset} No suspicious directives, secrets, or poisoned MCP tools detected.`);
    lines.push('');
    return lines.join('\n');
  }

  for (const f of report.findings) {
    const sev = f.council?.judge.finalSeverity ?? f.initialSeverity;
    lines.push('');
    lines.push(
      `  ${verdictPill(f)} ${sevBadge(sev)} ${C.bold}${f.ruleId}${C.reset} ${f.ruleName} ${C.gray}(${f.cwe})${C.reset}`,
    );
    lines.push(`  ${C.cyan}${f.relativePath}:${f.line}${C.reset} ${C.gray}[${f.category}]${C.reset}`);
    lines.push(`  ${C.gray}│${C.reset} ${C.dim}${f.snippet}${C.reset}`);

    if (f.council) {
      lines.push(
        `  ${C.red}├─ 🔴 Advocate:${C.reset} ${f.council.advocate.exploitScenario}`,
      );
      lines.push(
        `  ${C.blue}├─ 🔵 Skeptic:${C.reset}  ${f.council.skeptic.counterArgument}`,
      );
      lines.push(
        `  ${C.purple}└─ ⚖  Judge:${C.reset}    ${f.council.judge.rationale}`,
      );
    }

    if (f.proof?.executed) {
      const icon = f.proof.triggeredCanary ? `${C.red}${C.bold}🧪 CANARY TRIGGERED${C.reset}` : `${C.green}🧪 Canary Safe${C.reset}`;
      lines.push(`     ${icon} ${C.gray}— ${f.proof.details}${C.reset}`);
    }
  }

  lines.push('');
  lines.push(bar);
  lines.push(
    `  ${C.gray}Tip: Run with ${C.cyan}--ui${C.gray} to inspect full Council debates & unified diff patches in the browser.${C.reset}`,
  );
  lines.push('');
  return lines.join('\n');
}
