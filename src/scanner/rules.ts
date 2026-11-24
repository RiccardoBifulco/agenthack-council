import path from 'node:path';
import type { CandidateFinding, Severity, TargetCategory } from '../types.js';

export function classifyFile(filePath: string): TargetCategory | null {
  const base = path.basename(filePath);
  const lower = base.toLowerCase();
  const normalized = filePath.replace(/\\/g, '/');

  if (
    lower === '.mcp.json' ||
    lower === 'mcp.json' ||
    lower === 'claude_desktop_config.json' ||
    lower === 'mcp_config.json' ||
    normalized.endsWith('/.cursor/mcp.json')
  ) {
    return 'mcp-config';
  }

  if (lower === 'skill.md' || normalized.includes('/skills/') && lower.endsWith('.md')) {
    return 'skill-markdown';
  }

  if (
    lower === 'claude.md' ||
    lower === 'agents.md' ||
    lower === '.cursorrules' ||
    lower === '.windsurfrules' ||
    lower === 'copilot-instructions.md' ||
    (normalized.includes('/rules/') && lower.endsWith('.md'))
  ) {
    return 'agent-instructions';
  }

  if (
    (normalized.includes('/.claude/') || normalized.includes('/.cursor/') || normalized.includes('/.gemini/')) &&
    (lower === 'settings.json' || lower === 'settings.local.json' || lower === 'config.json')
  ) {
    return 'agent-settings';
  }

  if (normalized.includes('/hooks/') && /\.(sh|bash|zsh|py|js|ts)$/.test(lower)) {
    return 'agent-hook';
  }

  if (/\.(ts|js|mjs|py|go)$/.test(lower)) {
    return 'mcp-server-code';
  }

  return null;
}

function getContextWindow(lines: string[], zeroIdx: number, radius = 3): string {
  const start = Math.max(0, zeroIdx - radius);
  const end = Math.min(lines.length - 1, zeroIdx + radius);
  const out: string[] = [];
  for (let i = start; i <= end; i++) {
    const marker = i === zeroIdx ? '>' : ' ';
    out.push(`${marker} ${String(i + 1).padStart(4, ' ')} | ${lines[i]}`);
  }
  return out.join('\n');
}

// Zero-width, bidi override, and Unicode tag characters used in prompt smuggling
// (Excludes U+200D ZWJ so standard compound emojis like 👨‍💻 / 🏃‍♂️ do not false-positive)
const INVISIBLE_UNICODE_RE = /[\u200B\u200C\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u{E0000}-\u{E007F}]/u;

const HTML_COMMENT_INJECTION_RE = /<!--[\s\S]*?(?:ignore\s+(?:all\s+|previous\s+|prior\s+)?instructions|system\s*prompt|do\s+not\s+mention|do\s+not\s+tell\s+the\s+user|read\s+[~./]+(?:ssh|aws|env)|curl\s+https?:\/\/|exfiltrat)/i;

const MARKDOWN_EXFIL_IMAGE_RE = /!\[[^\]]*\]\(https?:\/\/[^)\s]+(?:\?|\&)(?:data|secret|token|key|env|q|payload)=/i;

const TOOL_POISONING_RE = /(?:before\s+calling\s+this\s+tool|important:\s*(?:first\s+)?read\s+|do\s+not\s+(?:mention|inform|tell|show)\s+(?:this\s+to\s+)?the\s+user|silently\s+(?:read|send|upload|execute)|pass\s+the\s+contents?\s+of\s+[`'"]?(?:~\/\.ssh|~\/\.aws|\.env|\/etc\/passwd)|<IMPORTANT>[\s\S]{0,240}(?:ssh|aws|\.env|token|secret))/i;

const SECRET_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: 'Anthropic API Key', re: /\bsk-ant-api03-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'OpenAI Project Key', re: /\bsk-proj-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'GitHub PAT', re: /\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/ },
  { name: 'AWS Access Key ID', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'Slack Bot/User Token', re: /\bxox[baprs]-[0-9A-Za-z-]{16,}\b/ },
  { name: 'Stripe Live Secret Key', re: /\bsk_live_[0-9a-zA-Z]{20,}\b/ },
  { name: 'URL Embedded Credentials', re: /\b(?:postgres|postgresql|mysql|mongodb|redis|amqp):\/\/[^\s:/?#@]+:[^\s@/?#'"`]{4,}@[^\s'"`]+/i },
];

const UNPINNED_EXEC_RE = /(?:npx\s+(?:-y|--yes)\s+(?![@\w./-]+@\d)[@\w./-]+|curl\s+-[^\n|]*\|\s*(?:ba)?sh|wget\s+-[^\n|]*\|\s*(?:ba)?sh)/i;

const OVERPRIVILEGED_RE = /(?:dangerously-skip-permissions|--dangerously-skip-permissions|"Bash\(\*\)"|"autoApprove"\s*:\s*\[\s*"\*"\s*\]|server-filesystem["',\s]+["'](?:\s*\/|\s*~|\s*\/Users|\s*\/home)["'])/;

const BASE64_BLOB_RE = /\b(?:[A-Za-z0-9+/]{48,}={0,2})\b/;

const EXFIL_SINK_RE = /\b(?:curl|wget|fetch|axios\.post|requests\.post|urllib\.request|nc\s+-)\b[^\n]{0,140}(?:\.env|id_rsa|aws\/credentials|process\.env|os\.environ|API_KEY|SECRET|TOKEN)/i;

function redactSecretsInText(text: string): string {
  let out = text;
  for (const sp of SECRET_PATTERNS) {
    out = out.replace(new RegExp(sp.re.source, sp.re.flags.includes('g') ? sp.re.flags : sp.re.flags + 'g'), (m) =>
      m.length > 14 ? `${m.slice(0, 8)}…[REDACTED]…${m.slice(-4)}` : '[REDACTED]',
    );
  }
  return out;
}

export function scanFileContent(
  filePath: string,
  relativePath: string,
  content: string,
  category: TargetCategory,
): CandidateFinding[] {
  const findings: CandidateFinding[] = [];
  const lines = content.split(/\r?\n/);
  const safeLines = lines.map(redactSecretsInText);
  let seq = 0;

  const push = (
    ruleId: string,
    ruleName: string,
    initialSeverity: Severity,
    lineIdx: number,
    evidence: string,
    cwe: string,
  ) => {
    seq += 1;
    findings.push({
      id: `${ruleId}-${path.basename(filePath)}-${lineIdx + 1}-${seq}`,
      ruleId,
      ruleName,
      category,
      initialSeverity,
      filePath,
      relativePath,
      line: lineIdx + 1,
      snippet: (safeLines[lineIdx] ?? '').trim().slice(0, 220),
      contextWindow: getContextWindow(safeLines, lineIdx),
      evidence,
      cwe,
    });
  };

  // Multi-line HTML comment check on markdown / instructions
  if (category === 'skill-markdown' || category === 'agent-instructions') {
    const commentMatch = HTML_COMMENT_INJECTION_RE.exec(content);
    if (commentMatch && commentMatch.index !== undefined) {
      const lineIdx = content.slice(0, commentMatch.index).split(/\r?\n/).length - 1;
      push(
        'AHC-002',
        'Hidden HTML Comment Prompt Injection',
        'critical',
        lineIdx,
        `Hidden HTML comment contains covert agent directive: ${commentMatch[0].slice(0, 120).replace(/\s+/g, ' ')}`,
        'CWE-1427',
      );
    }
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // AHC-001: Invisible Unicode / Bidi Prompt Smuggling
    if (
      (category === 'skill-markdown' || category === 'agent-instructions' || category === 'mcp-server-code') &&
      INVISIBLE_UNICODE_RE.test(line)
    ) {
      // Ignore BOM at byte 0 of file
      if (!(i === 0 && line.startsWith('\uFEFF') && !INVISIBLE_UNICODE_RE.test(line.slice(1)))) {
        const codePoints = [...line]
          .filter((ch) => INVISIBLE_UNICODE_RE.test(ch))
          .map((ch) => `U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}`);
        push(
          'AHC-001',
          'Invisible Unicode / Bidi Prompt Smuggling',
          'critical',
          i,
          `Detected ${codePoints.length} invisible/bidi control characters (${[...new Set(codePoints)].slice(0, 4).join(', ')})`,
          'CWE-451',
        );
      }
    }

    // AHC-002b: Markdown image exfiltration
    if ((category === 'skill-markdown' || category === 'agent-instructions') && MARKDOWN_EXFIL_IMAGE_RE.test(line)) {
      push(
        'AHC-002',
        'Markdown Image Exfiltration Channel',
        'high',
        i,
        'Markdown image URL contains query parameter pattern commonly used for zero-click prompt data exfiltration',
        'CWE-200',
      );
    }

    // AHC-003: MCP Tool Poisoning / Covert Agent Directives
    if (TOOL_POISONING_RE.test(line)) {
      push(
        'AHC-003',
        'MCP Tool Poisoning / Shadow Agent Instruction',
        'critical',
        i,
        'Instruction directs the agent to covertly access sensitive files or hide behavior from the user',
        'CWE-1427',
      );
    }

    // AHC-004: Plaintext Secrets in Configs / Skills / Code
    if (category !== 'mcp-server-code' || !relativePath.includes('test')) {
      for (const sp of SECRET_PATTERNS) {
        const m = sp.re.exec(line);
        if (m) {
          const masked = m[0].slice(0, 8) + '...' + m[0].slice(-4);
          push(
            'AHC-004',
            `Plaintext Secret (${sp.name})`,
            category === 'mcp-config' || category === 'agent-settings' ? 'critical' : 'high',
            i,
            `Matched ${sp.name} pattern (${masked}) in ${category}`,
            'CWE-798',
          );
        }
      }
    }

    // AHC-005: Unpinned npx -y or curl | sh supply-chain execution
    if (
      (category === 'mcp-config' || category === 'agent-hook' || category === 'skill-markdown' || category === 'agent-settings') &&
      UNPINNED_EXEC_RE.test(line)
    ) {
      push(
        'AHC-005',
        'Unpinned Remote Package / Pipe-to-Shell Execution',
        category === 'mcp-config' || category === 'agent-hook' ? 'high' : 'medium',
        i,
        'Executes unpinned remote code (e.g. `npx -y` without version pin or `curl | sh`), exposing the agent host to supply-chain takeover',
        'CWE-829',
      );
    }

    // AHC-006: Over-privileged agent permissions
    if ((category === 'agent-settings' || category === 'mcp-config' || category === 'agent-hook') && OVERPRIVILEGED_RE.test(line)) {
      push(
        'AHC-006',
        'Over-Privileged Agent / Unrestricted Host Access',
        'high',
        i,
        'Grants unrestricted shell execution, wildcard auto-approval, or root/home filesystem mount to an agent or MCP server',
        'CWE-250',
      );
    }

    // AHC-007: Obfuscated Base64 payload in prompts/skills/hooks
    if (category === 'skill-markdown' || category === 'agent-instructions' || category === 'agent-hook') {
      const b64 = BASE64_BLOB_RE.exec(line);
      if (b64) {
        try {
          const decoded = Buffer.from(b64[0], 'base64').toString('utf8');
          if (/(?:curl|wget|bash|sh\s+-c|ignore\s+previous|eval\(|nc\s+|\.ssh|\.aws|\.env)/i.test(decoded)) {
            push(
              'AHC-007',
              'Obfuscated Base64 Command / Prompt Payload',
              'critical',
              i,
              `Base64 payload decodes to suspicious directive: "${decoded.slice(0, 90).replace(/\s+/g, ' ')}"`,
              'CWE-506',
            );
          }
        } catch {
          // ignore invalid base64
        }
      }
    }

    // AHC-008: Exfiltration sink paired with env/credential access
    if (EXFIL_SINK_RE.test(line)) {
      push(
        'AHC-008',
        'Credential / Environment Exfiltration Sink',
        'critical',
        i,
        'Outbound network call directly references environment variables or credential paths on the same line',
        'CWE-200',
      );
    }
  }

  return findings;
}
