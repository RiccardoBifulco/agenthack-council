import { RULES_CATALOG } from '../scanner/rules.js';
import type { EvaluatedFinding, ScanReport, Severity } from '../types.js';
import { VERSION } from '../version.js';

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

function gradeBadge(grade: ScanReport['grade'], score: ScanReport['score']): string {
  if (grade === null || score === null) return 'Not graded';
  const color = score >= 90 ? C.green : score >= 70 ? C.yellow : C.red;
  return `${color}${C.bold}${grade} (${score}/100)${C.reset}`;
}

function verdictPill(f: EvaluatedFinding): string {
  const v = f.verdict;
  if (v === 'CONFIRMED') return `${C.bgRed}${C.red}${C.bold} ⚖ CONFIRMED ${C.reset}`;
  if (v === 'UNREVIEWED') return C.gray + 'UNREVIEWED' + C.reset;
  if (v === 'UNCERTAIN') return `${C.bgYellow}${C.yellow}${C.bold} ⚖ UNCERTAIN ${C.reset}`;
  return `${C.bgGreen}${C.green}${C.bold} ⚖ DISMISSED (FP) ${C.reset}`;
}

export function renderRulesCatalog(): string {
  const lines: string[] = [];
  const bar = `${C.gray}${'─'.repeat(84)}${C.reset}`;
  lines.push('');
  lines.push(
    `${C.bold}${C.cyan}⚡ AGENTHACK COUNCIL${C.reset} ${C.gray}v${VERSION} — Built-in Detection Rules (${RULES_CATALOG.length})${C.reset}`,
  );
  lines.push(bar);
  for (const r of RULES_CATALOG) {
    lines.push(
      `  ${C.bold}${C.purple}${r.id}${C.reset}  ${sevBadge(r.defaultSeverity).padEnd(18)} ${C.bold}${r.name}${C.reset} ${C.gray}(${r.cwe} · CVSS ${r.securitySeverityScore})${C.reset}`,
    );
    lines.push(`           ${C.gray}${r.shortDescription}${C.reset}`);
  }
  lines.push(bar);
  lines.push('');
  return lines.join('\n');
}

export function renderCliReport(report: ScanReport, options?: { showDismissed?: boolean }): string {
  const showDismissed = options?.showDismissed ?? false;
  const lines: string[] = [];
  const bar = `${C.gray}${'─'.repeat(78)}${C.reset}`;

  lines.push('');
  lines.push(
    `${C.bold}${C.cyan}⚡ AGENTHACK COUNCIL${C.reset} ${C.gray}v${VERSION} — Adversarial Security Harness for AI Agents & MCP${C.reset}`,
  );
  lines.push(bar);
  lines.push(
    `  ${C.gray}Target:${C.reset}  ${report.targetPath}\n` +
      `  ${C.gray}Scanned:${C.reset} ${report.filesScanned} agent/MCP files in ${report.durationMs}ms  ${C.gray}|${C.reset}  ` +
      `${C.gray}Council:${C.reset} ${C.purple}${report.modelName}${C.reset}\n` +
      `  ${C.gray}Posture:${C.reset} ${gradeBadge(report.grade, report.score)}  ${C.gray}|${C.reset}  ` +
      `${C.red}${C.bold}${report.summary.confirmed} Council-confirmed${C.reset} · ` +
      `${C.yellow}${report.summary.uncertain} Uncertain${C.reset} · ` +
      `${C.green}${report.summary.dismissed} Dismissed FPs${C.reset}`,
  );
  lines.push('  Deterministic CI policy findings: ' + report.summary.ciBlocking);
  if (report.summary.unreviewed) lines.push('  Unreviewed candidates: ' + report.summary.unreviewed);
  if (report.coverage !== 'complete') {
    lines.push('  Coverage: ' + report.coverage);
    for (const issue of report.scanIssues) lines.push('  Skipped ' + issue.path + ' (' + issue.reason + ')');
  }
  if (report.fallbackWarning) {
    lines.push(`  ${C.yellow}⚠ Note:${C.reset}   ${C.gray}${report.fallbackWarning}${C.reset}`);
  }
  lines.push(bar);

  if (report.findings.length === 0) {
    if (report.coverage === 'complete') lines.push(`  ${C.green}${C.bold}✓ Clean scan.${C.reset} No suspicious directives, secrets, or poisoned MCP tools detected.`);
    lines.push('');
    return lines.join('\n');
  }

  const actionable = report.findings.filter((f) => f.ciBlocking || f.verdict !== 'DISMISSED');
  const dismissedCount = report.findings.length - actionable.length;
  // Show dismissed in full if `--verbose` is passed OR if demo/small report (`<= 6` total findings)
  const visibleFindings = showDismissed || report.findings.length <= 6 ? report.findings : actionable;

  if (visibleFindings.length === 0 && dismissedCount > 0) {
    lines.push(
      `  ${C.green}${C.bold}✓ Zero actionable threats.${C.reset} All ${dismissedCount} static candidates were dismissed as benign examples/placeholders by the Council.`,
    );
  }

  for (const f of visibleFindings) {
    const sev = f.council?.judge.finalSeverity ?? f.initialSeverity;
    lines.push('');
    lines.push(
      `  ${verdictPill(f)}${f.ciBlocking ? ' [CI policy]' : ''} ${sevBadge(sev)} ${C.bold}${f.ruleId}${C.reset} ${f.ruleName} ${C.gray}(${f.cwe})${C.reset}`,
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

    if (f.proof) {
      lines.push('     Static evidence: ' + f.proof.details);
    }
  }

  if (!showDismissed && report.findings.length > 6 && dismissedCount > 0) {
    lines.push('');
    lines.push(
      `  ${C.green}✓ ${dismissedCount} benign documentation/placeholder false positive(s) suppressed${C.reset} ${C.gray}(pass --verbose or --ui to inspect)${C.reset}`,
    );
  }

  lines.push('');
  lines.push(bar);
  lines.push(
    `  ${C.gray}Tip: Run with ${C.cyan}--ui${C.gray} for the Web Dashboard or ${C.cyan}--sarif${C.gray} for GitHub Security Code Scanning.${C.reset}`,
  );
  lines.push('');
  return lines.join('\n');
}
