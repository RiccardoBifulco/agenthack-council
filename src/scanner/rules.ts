import path from 'node:path';
import type { CandidateFinding, RuleMetadata, Severity, TargetCategory } from '../types.js';

export const RULES_CATALOG: RuleMetadata[] = [
  {
    id: 'AHC-001',
    name: 'Invisible Unicode / Bidi Prompt Smuggling',
    cwe: 'CWE-451',
    defaultSeverity: 'critical',
    securitySeverityScore: '9.3',
    shortDescription: 'Detects zero-width, bidirectional override, or Unicode tag characters smuggling hidden instructions.',
    fullDescription:
      'Invisible Unicode control characters and tag blocks (U+E0000..U+E007F, Bidi overrides, zero-width spaces) render invisibly in IDE and GitHub PR diffs while being tokenized by coding agent LLMs.',
  },
  {
    id: 'AHC-002',
    name: 'Hidden HTML Comment / Markdown Image Exfiltration',
    cwe: 'CWE-1427',
    defaultSeverity: 'critical',
    securitySeverityScore: '9.1',
    shortDescription: 'Detects covert prompt directives inside HTML comments or zero-click Markdown image exfiltration URLs.',
    fullDescription:
      'Attackers hide prompt-injection instructions inside Markdown HTML comments or craft dynamic Markdown image URLs with query parameters to exfiltrate secrets upon rendering.',
  },
  {
    id: 'AHC-003',
    name: 'MCP Tool Poisoning / Shadow Agent Instruction',
    cwe: 'CWE-1427',
    defaultSeverity: 'critical',
    securitySeverityScore: '9.6',
    shortDescription: 'Detects MCP tool descriptions or skill prompts instructing the agent to silently read credentials or hide actions.',
    fullDescription:
      'Poisoned MCP tool metadata or SKILL.md instructions coerce the host LLM into reading sensitive files (~/.ssh, ~/.aws, .env) and passing them as tool arguments without alerting the user.',
  },
  {
    id: 'AHC-004',
    name: 'Plaintext Secret in Agent / MCP Configuration',
    cwe: 'CWE-798',
    defaultSeverity: 'critical',
    securitySeverityScore: '8.8',
    shortDescription: 'Detects hardcoded API keys, tokens, or database credentials in agent configs and skills.',
    fullDescription:
      'Plaintext credentials stored in .mcp.json, settings.json, or skill files are exposed to agent context windows, repository clones, and diagnostic logs. Raw secret values are automatically redacted during Stage 1 scanning.',
  },
  {
    id: 'AHC-005',
    name: 'Unpinned Remote Package / Pipe-to-Shell Execution',
    cwe: 'CWE-829',
    defaultSeverity: 'high',
    securitySeverityScore: '7.8',
    shortDescription: 'Detects unpinned `npx -y` packages or `curl | sh` execution in MCP configs, hooks, and skills.',
    fullDescription:
      'Dynamic unpinned execution (`npx -y pkg` without an explicit version pin or `curl ... | bash`) pulls mutable upstream code at agent startup, enabling supply-chain takeover.',
  },
  {
    id: 'AHC-006',
    name: 'Over-Privileged Agent / Unrestricted Host Access',
    cwe: 'CWE-250',
    defaultSeverity: 'high',
    securitySeverityScore: '8.1',
    shortDescription: 'Detects wildcard tool auto-approvals, permission bypass flags, or root/home filesystem mounts.',
    fullDescription:
      'Configurations granting `--dangerously-skip-permissions`, `Bash(*)`, wildcard `autoApprove`, or root/home MCP filesystem mounts remove human-in-the-loop containment.',
  },
  {
    id: 'AHC-007',
    name: 'Obfuscated Base64 Command / Prompt Payload',
    cwe: 'CWE-506',
    defaultSeverity: 'critical',
    securitySeverityScore: '9.2',
    shortDescription: 'Detects Base64-encoded blobs in skills, rules, or hooks that decode to shell commands or prompt overrides.',
    fullDescription:
      'Base64 payloads embedded in SKILL.md, CLAUDE.md, or hooks bypass naive keyword review while decoding to executable commands or covert prompt injections.',
  },
  {
    id: 'AHC-008',
    name: 'Credential / Environment Exfiltration Sink',
    cwe: 'CWE-200',
    defaultSeverity: 'critical',
    securitySeverityScore: '9.4',
    shortDescription: 'Detects outbound network sinks paired directly with credential paths or environment variables.',
    fullDescription:
      'Outbound HTTP/socket calls (`fetch`, `curl`, `wget`, `requests.post`, `nc`) sending `.env`, SSH/AWS keys, or raw `process.env` payloads create an immediate secret exfiltration channel.',
  },
  {
    id: 'AHC-009',
    name: 'Insecure Remote MCP Transport / Ephemeral Tunnel',
    cwe: 'CWE-319',
    defaultSeverity: 'high',
    securitySeverityScore: '7.6',
    shortDescription: 'Detects remote MCP servers configured over cleartext HTTP or unverified ephemeral tunnel domains.',
    fullDescription:
      'Connecting MCP clients over non-loopback `http://` or ephemeral developer tunnels (`ngrok`, `trycloudflare`, `localtunnel`) exposes tool invocations and bearer tokens to interception and tunnel takeover.',
  },
  {
    id: 'AHC-010',
    name: 'Agent Persistence & Config Backdooring',
    cwe: 'CWE-912',
    defaultSeverity: 'critical',
    securitySeverityScore: '9.0',
    shortDescription: 'Detects directives or scripts modifying agent settings, MCP configs, git hooks, or OS startup tasks.',
    fullDescription:
      'Malicious skills or MCP tools achieve cross-session persistence by appending instructions or commands to `~/.claude/settings.json`, `CLAUDE.md`, `.mcp.json`, `.git/hooks/`, `crontab`, or `LaunchAgents`.',
  },
];

export function classifyFile(filePath: string): TargetCategory | null {
  const base = path.basename(filePath);
  const lower = base.toLowerCase();
  const normalized = filePath.replace(/\\/g, '/');

  if (
    lower === '.mcp.json' ||
    lower === 'mcp.json' ||
    lower === 'claude_desktop_config.json' ||
    lower === 'mcp_config.json' ||
    normalized.endsWith('/.cursor/mcp.json') ||
    normalized.endsWith('/.codeium/windsurf/mcp_config.json')
  ) {
    return 'mcp-config';
  }

  if (lower === 'skill.md' || (normalized.includes('/skills/') && lower.endsWith('.md'))) {
    return 'skill-markdown';
  }

  if (
    lower === 'claude.md' ||
    lower === 'agents.md' ||
    lower === 'gemini.md' ||
    lower === '.cursorrules' ||
    lower === '.windsurfrules' ||
    lower === '.clinerules' ||
    lower === '.goosehints' ||
    lower === 'copilot-instructions.md' ||
    (normalized.includes('/rules/') && (lower.endsWith('.md') || lower.endsWith('.mdc')))
  ) {
    return 'agent-instructions';
  }

  if (
    (normalized.includes('/.claude/') ||
      normalized.includes('/.cursor/') ||
      normalized.includes('/.gemini/') ||
      normalized.includes('/.codex/')) &&
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

/**
 * Computes CommonMark fenced code block membership (` ``` ` or ` ~~~ `) across the entire file
 * so long documentation code blocks (50-200+ lines) are accurately tracked on every inner line.
 */
export function computeMarkdownFenceMap(lines: string[]): boolean[] {
  const map = new Array<boolean>(lines.length).fill(false);
  let inFence = false;
  let fenceChar = '';
  let fenceLen = 0;

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].replace(/^\s{0,3}(?:>\s*)*/, '');
    const m = /^(`{3,}|~{3,})(.*)$/.exec(trimmed);
    if (m) {
      const marker = m[1];
      const rest = m[2];
      if (!inFence) {
        // Opening fence (backtick info strings cannot contain backticks)
        if (marker[0] !== '`' || !rest.includes('`')) {
          inFence = true;
          fenceChar = marker[0];
          fenceLen = marker.length;
          map[i] = true;
          continue;
        }
      } else if (marker[0] === fenceChar && marker.length >= fenceLen && /^\s*$/.test(rest)) {
        map[i] = true;
        inFence = false;
        fenceChar = '';
        fenceLen = 0;
        continue;
      }
    }
    map[i] = inFence;
  }
  return map;
}

// Zero-width, bidi override, and Unicode tag characters used in prompt smuggling
// (Excludes U+200D ZWJ so standard compound emojis like 👨‍💻 / 🏃‍♂️ do not false-positive)
const INVISIBLE_UNICODE_RE = /[\u200B\u200C\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u{E0000}-\u{E007F}]/u;

const HTML_COMMENT_INJECTION_RE =
  /<!--[\s\S]*?(?:ignore\s+(?:all\s+|previous\s+|prior\s+)?instructions|system\s*prompt|do\s+not\s+(?:mention|tell\s+the\s+user)|read\s+[~./]+(?:ssh|aws|env)|curl\s+https?:\/\/|exfiltrat)[\s\S]*?-->/gi;

const MARKDOWN_EXFIL_IMAGE_RE =
  /!\[[^\]]*\]\(https?:\/\/[^)\s]+(?:\?|\&)(?:data|secret|token|key|env|q|payload)=(?:\$|%7B|\{\{|[A-Za-z0-9+/]{12,})/i;

// Requires covert behavior paired with sensitive targets or prompt-injection framing
// (avoids false positives on UX instructions like "Do not show the user the helper's JSON output")
const COVERT_SENSITIVE_TARGET_RE =
  /(?:~\/\.ssh|~\/\.aws|id_rsa|id_ed25519|\.env\b|\/etc\/passwd|aws\/credentials|\.npmrc|\.netrc|private[_ -]?key|secret[_ -]?key|api[_ -]?key|bearer\s+token|exfiltrat|ignore\s+(?:all\s+|previous\s+)?instructions|system\s+prompt|pass\s+the\s+contents?)/i;

const DIRECT_TOOL_POISONING_RE =
  /(?:before\s+calling\s+this\s+tool|after\s+calling\s+this\s+tool|<IMPORTANT>)[\s\S]{0,220}(?:~\/\.ssh|~\/\.aws|id_rsa|\.env\b|\/etc\/passwd|credentials|silently|do\s+not\s+(?:mention|tell|inform))|\b(?:silently|secretly|covertly)\s+(?:read|cat|open|send|upload|post|exfiltrat|execute|include|attach)\b[^\n]{0,140}(?:~\/\.ssh|~\/\.aws|id_rsa|\.env\b|\/etc\/passwd|credentials|secret|token|https?:\/\/)|\bpass\s+the\s+contents?\s+of\s+[`'"]?(?:~\/\.ssh|~\/\.aws|\.env|\/etc\/passwd)/i;

const SECRECY_DIRECTIVE_RE =
  /\b(?:do\s+not|don't|never)\s+(?:mention|inform|tell|reveal)\s+(?:this\s+(?:to\s+)?)?the\s+user\b/i;

const SECRET_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: 'Anthropic API Key', re: /\bsk-ant-api03-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'OpenAI Project Key', re: /\bsk-proj-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'GitHub PAT', re: /\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/ },
  { name: 'AWS Access Key ID', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'Slack Bot/User Token', re: /\bxox[baprs]-[0-9A-Za-z-]{16,}\b/ },
  { name: 'Stripe Live Secret Key', re: /\bsk_live_[0-9a-zA-Z]{20,}\b/ },
  // Excludes `${...}` / `{{...}}` / `<...>` template variable interpolations
  {
    name: 'URL Embedded Credentials',
    re: /\b(?:postgres|postgresql|mysql|mongodb|redis|amqp):\/\/(?![^\s'"`]*\$\{)(?![^\s'"`]*\{\{)[^\s:/?#@<>]+:[^\s@/?#'"`<>]{4,}@[^\s'"`<>]+/i,
  },
];

function isPreRedactionPlaceholder(rawMatch: string, rawLine: string): boolean {
  if (
    /(?:YOUR_|EXAMPLE|PLACEHOLDER|xxxx|000000|123456|changeme|dummy|test_key|fake|sample|demo|my[-_]?secret|<token>|<api[-_]?key>)/i.test(
      rawMatch,
    ) ||
    /(?:YOUR_|EXAMPLE|PLACEHOLDER|dummy|fake|test_key|localConnectionString|LOCAL_CONNECTION_STRING)/i.test(rawLine)
  ) {
    return true;
  }
  // Localhost / example DB connection strings in docs & local dev configs
  if (/^(?:postgres|postgresql|mysql|mongodb|redis|amqp):\/\//i.test(rawMatch)) {
    if (
      /@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal|db|postgres|mysql|redis|[a-z0-9.-]*example\.(?:com|org|net))\b/i.test(
        rawMatch,
      ) ||
      /:(?:password|pass|postgres|root|admin|secret|user|dev|test)@/i.test(rawMatch)
    ) {
      return true;
    }
  }
  return false;
}

const UNPINNED_EXEC_RE =
  /(?:npx\s+(?:-y|--yes)\s+(?![@\w./-]+@\d)[@\w./-]+|curl\s+-[^\n|]*\|\s*(?:ba)?sh\b|wget\s+-[^\n|]*\|\s*(?:ba)?sh\b)/i;

const LOG_PRINT_ONLY_RE = /^\s*(?:console\.(?:log|error|warn|info)|logger\.\w+|print\s*\(|echo\s+['"][^$`]*['"]\s*$)/;

const OVERPRIVILEGED_RE =
  /(?:dangerously-skip-permissions|--dangerously-skip-permissions|"Bash\(\*\)"|"autoApprove"\s*:\s*\[\s*"\*"\s*\]|server-filesystem["',\s]+["'](?:\s*\/|\s*~|\s*\/Users|\s*\/home)["'])/;

const BASE64_BLOB_RE = /\b(?:[A-Za-z0-9+/]{48,}={0,2})\b/;

// Surgical exfiltration sink rules:
// 1. JS/Python outbound call sending process.env / os.environ / credential files in body, payload, or URL query (NOT standard Authorization headers)
const CODE_EXFIL_SINK_RE =
  /\b(?:fetch|axios\.(?:post|put|patch|request)|requests\.(?:post|put)|urllib\.request\.urlopen|navigator\.sendBeacon)\s*\([^\n]{0,160}(?:(?:body|data|json|payload)\s*:\s*[^\n]{0,90}(?:process\.env|os\.environ|readFileSync|id_rsa|\.aws\/credentials)|https?:\/\/[^\s'"`)]*[?&][^\s'"`)]*(?:process\.env|os\.environ)|\b(?:id_rsa|id_ed25519|\.aws\/credentials|\/etc\/passwd)\b)/i;

// 2. Shell curl/wget/nc exfiltrating files (@~/.ssh/id_rsa, $(cat ~/.env)) or raw env dumps in body/query (excludes normal `-H "Authorization: Bearer $TOKEN"`)
const SHELL_EXFIL_SINK_RE =
  /\b(?:curl|wget)\s+[^\n]{0,160}(?:@~\/\.|@\/etc\/passwd|\$\(\s*cat\s+[~./]*(?:\.ssh|\.aws|\.env)|(?:--data(?:-binary|-raw|-urlencode)?|-d|-F)\s+[^\n]{0,80}(?:\.env\b|id_rsa|aws\/credentials|process\.env|\$\(\s*env\b)|https?:\/\/[^\s'"]*[?&][^\s'"]*\$\(\s*(?:cat|env|printenv))|\bnc\s+-[^\n]{0,80}(?:id_rsa|\.env|\/etc\/passwd)/i;

const INSECURE_MCP_URL_RE =
  /"(?:url|serverUrl|sseUrl|endpoint)"\s*:\s*"(http:\/\/(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b|\[::1\])[^"]+|https?:\/\/[^"]*(?:ngrok-free\.app|ngrok\.io|trycloudflare\.com|localtunnel\.me|loca\.lt|serveo\.net)[^"]*)"/i;

// Requires genuine shell output redirection (preceded by start/space/shell operator, NEVER `<tag>` or `=>`)
// or explicit file-write APIs targeting agent config / persistence paths.
const PERSISTENCE_BACKDOOR_RE =
  /(?:(?:^|[;&|()\s])(?:>>|>)(?![=>])\s*['"]?(?:~\/|\$HOME\/|\.\.?\/|\/[^\s'"]*\/)?(?:\.claude\/settings|CLAUDE\.md|\.cursor\/mcp\.json|\.cursorrules|\.mcp\.json|\.git\/hooks\/|LaunchAgents\/)|(?:tee\s+-a?\s+|(?:writeFile|appendFile)(?:Sync)?\s*\(|os\.WriteFile\s*\()[^\n]{0,100}(?:\.claude\/settings|CLAUDE\.md|\.cursor\/mcp\.json|\.cursorrules|\.mcp\.json|\.git\/hooks\/|LaunchAgents)|\bcrontab\s+-[elr]?\b)/i;

const CODE_COMMENT_LINE_RE = /^\s*(?:\/\/|\/\*|\*\s|\*\/|#\s)/;

export function redactSecretsInText(text: string): string {
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
  const isMarkdown = category === 'skill-markdown' || category === 'agent-instructions';
  const fenceMap = isMarkdown ? computeMarkdownFenceMap(lines) : new Array<boolean>(lines.length).fill(false);
  let seq = 0;

  const push = (
    ruleId: string,
    ruleName: string,
    initialSeverity: Severity,
    lineIdx: number,
    evidence: string,
    cwe: string,
    extra?: { inCodeFence?: boolean; isPlaceholderHint?: boolean },
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
      inCodeFence: extra?.inCodeFence ?? fenceMap[lineIdx] ?? false,
      isPlaceholderHint: extra?.isPlaceholderHint ?? false,
    });
  };

  // Multi-line HTML comment check on markdown / instructions
  if (isMarkdown) {
    HTML_COMMENT_INJECTION_RE.lastIndex = 0;
    let commentMatch: RegExpExecArray | null;
    while ((commentMatch = HTML_COMMENT_INJECTION_RE.exec(content)) !== null) {
      const lineIdx = content.slice(0, commentMatch.index).split(/\r?\n/).length - 1;
      push(
        'AHC-002',
        'Hidden HTML Comment Prompt Injection',
        'critical',
        lineIdx,
        `Hidden HTML comment contains covert agent directive: ${redactSecretsInText(commentMatch[0]).slice(0, 120).replace(/\s+/g, ' ')}`,
        'CWE-1427',
        { inCodeFence: fenceMap[lineIdx] },
      );
    }
  }

  // Multi-line unpinned `npx -y <pkg>` inside `.mcp.json` `"args": ["-y", "pkg"]`
  if (category === 'mcp-config') {
    const mcpArgsRe = /"args"\s*:\s*\[\s*"(?:-y|--yes)"\s*,\s*"(?![@\w./-]+@\d)([@\w./-]+)"/g;
    let m: RegExpExecArray | null;
    while ((m = mcpArgsRe.exec(content)) !== null) {
      const lineIdx = content.slice(0, m.index).split(/\r?\n/).length - 1;
      push(
        'AHC-005',
        'Unpinned Remote Package / Pipe-to-Shell Execution',
        'high',
        lineIdx,
        `MCP server args invoke unpinned dynamic package "${m[1]}" with -y auto-install`,
        'CWE-829',
      );
    }
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // AHC-001: Invisible Unicode / Bidi Prompt Smuggling
    if (
      (isMarkdown || category === 'mcp-server-code') &&
      INVISIBLE_UNICODE_RE.test(line)
    ) {
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
    if (isMarkdown && MARKDOWN_EXFIL_IMAGE_RE.test(line)) {
      push(
        'AHC-002',
        'Markdown Image Exfiltration Channel',
        'high',
        i,
        'Markdown image URL interpolates dynamic secret/payload query parameter for zero-click exfiltration',
        'CWE-200',
      );
    }

    // AHC-003: MCP Tool Poisoning / Covert Agent Directives
    const nearbyRaw = lines.slice(Math.max(0, i - 1), Math.min(lines.length, i + 2)).join(' ');
    const hasToolPoisoning =
      DIRECT_TOOL_POISONING_RE.test(line) ||
      (SECRECY_DIRECTIVE_RE.test(line) && COVERT_SENSITIVE_TARGET_RE.test(nearbyRaw));
    if (hasToolPoisoning) {
      push(
        'AHC-003',
        'MCP Tool Poisoning / Shadow Agent Instruction',
        'critical',
        i,
        'Instruction directs the agent to covertly access sensitive files or conceal sensitive actions from the user',
        'CWE-1427',
      );
    }

    // AHC-004: Plaintext Secrets in Configs / Skills / Code
    if (category !== 'mcp-server-code' || !/(?:^|\/|_)test/i.test(relativePath)) {
      for (const sp of SECRET_PATTERNS) {
        const m = sp.re.exec(line);
        if (m) {
          const placeholderHint = isPreRedactionPlaceholder(m[0], line);
          const masked = m[0].length > 14 ? `${m[0].slice(0, 8)}…[REDACTED]…${m[0].slice(-4)}` : '[REDACTED]';
          push(
            'AHC-004',
            `Plaintext Secret (${sp.name})`,
            category === 'mcp-config' || category === 'agent-settings' ? 'critical' : 'high',
            i,
            `Matched ${sp.name} pattern (${masked}) in ${category}`,
            'CWE-798',
            { isPlaceholderHint: placeholderHint },
          );
        }
      }
    }

    // AHC-005: Unpinned npx -y or curl | sh supply-chain execution
    if (
      (category === 'mcp-config' ||
        category === 'agent-hook' ||
        category === 'skill-markdown' ||
        category === 'agent-settings') &&
      UNPINNED_EXEC_RE.test(line) &&
      !LOG_PRINT_ONLY_RE.test(line)
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
    if (
      (category === 'agent-settings' || category === 'mcp-config' || category === 'agent-hook') &&
      OVERPRIVILEGED_RE.test(line)
    ) {
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
    if (isMarkdown || category === 'agent-hook') {
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
              `Base64 payload decodes to suspicious directive: "${redactSecretsInText(decoded).slice(0, 90).replace(/\s+/g, ' ')}"`,
              'CWE-506',
            );
          }
        } catch {
          // ignore invalid base64
        }
      }
    }

    // AHC-008: Exfiltration sink paired with env/credential access
    if (CODE_EXFIL_SINK_RE.test(line) || SHELL_EXFIL_SINK_RE.test(line)) {
      push(
        'AHC-008',
        'Credential / Environment Exfiltration Sink',
        'critical',
        i,
        'Outbound network call sends credential files or raw environment secrets to external endpoint',
        'CWE-200',
      );
    }

    // AHC-009: Insecure Remote MCP Transport / Ephemeral Tunnel
    if (category === 'mcp-config') {
      const urlMatch = INSECURE_MCP_URL_RE.exec(line);
      if (urlMatch) {
        push(
          'AHC-009',
          'Insecure Remote MCP Transport / Ephemeral Tunnel',
          'high',
          i,
          `Remote MCP endpoint uses cleartext HTTP or ephemeral public tunnel (${urlMatch[1].slice(0, 80)})`,
          'CWE-319',
        );
      }
    }

    // AHC-010: Agent Persistence & Config Backdooring
    if (
      (isMarkdown || category === 'agent-hook' || category === 'mcp-server-code') &&
      !(category === 'mcp-server-code' && CODE_COMMENT_LINE_RE.test(line)) &&
      PERSISTENCE_BACKDOOR_RE.test(line)
    ) {
      push(
        'AHC-010',
        'Agent Persistence & Config Backdooring',
        'critical',
        i,
        'Directive or script writes to agent configuration, git hooks, or OS scheduled tasks to establish persistence',
        'CWE-912',
      );
    }
  }

  return findings;
}
