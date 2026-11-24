import { type ChildProcessWithoutNullStreams, execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export type ProviderName =
  | 'anthropic'
  | 'openai'
  | 'gemini'
  | 'openrouter'
  | 'ollama'
  | 'agy-cli'
  | 'antigravity'
  | 'claude-cli'
  | 'codex-cli'
  | 'gemini-cli';

const VALID_PROVIDERS = new Set<ProviderName>([
  'anthropic',
  'openai',
  'gemini',
  'openrouter',
  'ollama',
  'agy-cli',
  'antigravity',
  'claude-cli',
  'codex-cli',
  'gemini-cli',
]);

export interface LLMProviderConfig {
  provider: ProviderName;
  model: string;
  apiKey?: string;
  baseUrl?: string;
}

function normalizeProviderAlias(p: ProviderName): ProviderName {
  return p === 'antigravity' ? 'agy-cli' : p;
}

export function parseProviderSpec(spec: string): { provider: ProviderName; model?: string } {
  const trimmed = spec.trim();
  const colonIdx = trimmed.indexOf(':');
  const rawProvider = (colonIdx === -1 ? trimmed : trimmed.slice(0, colonIdx)) as ProviderName;
  const rawModel = colonIdx === -1 ? undefined : trimmed.slice(colonIdx + 1).trim() || undefined;
  if (!VALID_PROVIDERS.has(rawProvider)) {
    throw new Error(
      `Unknown provider "${rawProvider}". Expected one of: ${[...VALID_PROVIDERS].join(', ')}`,
    );
  }
  return { provider: normalizeProviderAlias(rawProvider), model: rawModel };
}

export function resolveBinaryPath(bin: string): string | null {
  const lookupCmd = process.platform === 'win32' ? 'where' : 'which';
  try {
    const out = execFileSync(lookupCmd, [bin], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
      .trim()
      .split(/\r?\n/)[0];
    if (out) return out;
  } catch {
    // check standard user-local fallback paths below
  }

  const home = os.homedir();
  const fallbackCandidates =
    process.platform === 'win32'
      ? [
          path.join(home, 'AppData', 'Local', 'agy', 'bin', `${bin}.exe`),
          path.join(home, '.local', 'bin', `${bin}.exe`),
        ]
      : [path.join(home, '.local', 'bin', bin), `/usr/local/bin/${bin}`, `/opt/homebrew/bin/${bin}`];

  for (const candidate of fallbackCandidates) {
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch {
      // continue
    }
  }
  return null;
}

function hasBinary(bin: string): boolean {
  return resolveBinaryPath(bin) !== null;
}

export function resolveProvider(
  preferredProvider?: ProviderName,
  preferredModel?: string,
): LLMProviderConfig | null {
  const normalizedPref = preferredProvider ? normalizeProviderAlias(preferredProvider) : undefined;

  if (normalizedPref === 'agy-cli') {
    if (!hasBinary('agy')) return null;
    return { provider: 'agy-cli', model: preferredModel || 'gemini-3.8-flash-low' };
  }
  if (normalizedPref === 'claude-cli') {
    return { provider: 'claude-cli', model: preferredModel || 'default' };
  }
  if (normalizedPref === 'codex-cli') {
    return { provider: 'codex-cli', model: preferredModel || 'default' };
  }
  if (normalizedPref === 'gemini-cli') {
    return { provider: 'gemini-cli', model: preferredModel || 'default' };
  }
  if (normalizedPref === 'ollama') {
    return {
      provider: 'ollama',
      model: preferredModel || process.env.OLLAMA_MODEL || 'qwen2.5-coder:7b',
      baseUrl: process.env.OLLAMA_HOST || 'http://127.0.0.1:11434',
    };
  }

  if ((!normalizedPref || normalizedPref === 'anthropic') && process.env.ANTHROPIC_API_KEY) {
    return {
      provider: 'anthropic',
      model: preferredModel || process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-5',
      apiKey: process.env.ANTHROPIC_API_KEY,
      baseUrl: (process.env.ANTHROPIC_BASE_URL || 'https://api.anthropic.com').replace(/\/+$/, ''),
    };
  }
  if ((!normalizedPref || normalizedPref === 'openai') && process.env.OPENAI_API_KEY) {
    return {
      provider: 'openai',
      model: preferredModel || process.env.OPENAI_MODEL || 'gpt-4o-mini',
      apiKey: process.env.OPENAI_API_KEY,
      baseUrl: (process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1').replace(/\/+$/, ''),
    };
  }
  if ((!normalizedPref || normalizedPref === 'gemini') && process.env.GEMINI_API_KEY) {
    return {
      provider: 'gemini',
      model: preferredModel || 'gemini-2.5-flash',
      apiKey: process.env.GEMINI_API_KEY,
    };
  }
  if ((!normalizedPref || normalizedPref === 'openrouter') && process.env.OPENROUTER_API_KEY) {
    return {
      provider: 'openrouter',
      model: preferredModel || 'anthropic/claude-3.5-sonnet',
      apiKey: process.env.OPENROUTER_API_KEY,
    };
  }
  if (!normalizedPref && process.env.OLLAMA_MODEL) {
    return {
      provider: 'ollama',
      model: preferredModel || process.env.OLLAMA_MODEL,
      baseUrl: process.env.OLLAMA_HOST || 'http://127.0.0.1:11434',
    };
  }

  // Zero-API-key subscription CLI auto-detection when explicitly running `--council llm`
  if (!normalizedPref) {
    if (hasBinary('agy')) return { provider: 'agy-cli', model: preferredModel || 'gemini-3.8-flash-low' };
    if (hasBinary('claude')) return { provider: 'claude-cli', model: preferredModel || 'default' };
    if (hasBinary('codex')) return { provider: 'codex-cli', model: preferredModel || 'default' };
    if (hasBinary('gemini')) return { provider: 'gemini-cli', model: preferredModel || 'default' };
  }

  return null;
}

/**
 * Persistent warm NDJSON session for Google Antigravity CLI (`agy --input-format stream-json --output-format stream-json`).
 * Amortizes initial CLI / MCP startup across the entire audit so subsequent Council turns complete in ~1s.
 */
class AgyStreamWorker {
  readonly model: string;
  dead = false;
  private initialized = false;
  private queue: Promise<unknown> = Promise.resolve();
  private child: ChildProcessWithoutNullStreams;
  private buffer = '';
  private stderrBuf = '';
  private pendingResolve: ((text: string) => void) | null = null;
  private pendingReject: ((err: Error) => void) | null = null;

  constructor(agyBin: string, model: string) {
    this.model = model;
    const args = [
      '--input-format',
      'stream-json',
      '--output-format',
      'stream-json',
      '--disable-slash-commands',
    ];
    if (model && model !== 'default') {
      args.push('--model', model);
    } else {
      args.push('--effort', 'low');
    }

    this.child = spawn(agyBin, args, {
      cwd: os.tmpdir(),
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, CI: '1', NO_COLOR: '1' },
    });

    this.child.stdout.on('data', (chunk) => {
      this.buffer += String(chunk);
      let nl: number;
      while ((nl = this.buffer.indexOf('\n')) !== -1) {
        const line = this.buffer.slice(0, nl).trim();
        this.buffer = this.buffer.slice(nl + 1);
        if (!line) continue;
        try {
          const evt = JSON.parse(line) as {
            event?: string;
            result?: { status?: string; response?: string; error?: string };
          };
          if (evt.event === 'init') {
            this.initialized = true;
          } else if (evt.event === 'result' && evt.result) {
            this.initialized = true;
            const res = evt.result;
            const resolve = this.pendingResolve;
            const reject = this.pendingReject;
            this.pendingResolve = null;
            this.pendingReject = null;
            if (res.status === 'SUCCESS') {
              resolve?.(res.response ?? '');
            } else {
              reject?.(new Error(res.error || `agy returned status ${res.status}`));
            }
          }
        } catch {
          // ignore non-JSON diagnostic lines
        }
      }
    });

    this.child.stderr.on('data', (chunk) => {
      this.stderrBuf = (this.stderrBuf + String(chunk)).slice(-600);
    });

    const onExit = (code: number | null) => {
      this.dead = true;
      if (this.pendingReject) {
        const reject = this.pendingReject;
        this.pendingResolve = null;
        this.pendingReject = null;
        const detail = this.stderrBuf.trim().replace(/\s+/g, ' ').slice(0, 180);
        reject(new Error(`agy exited (${code})${detail ? `: ${detail}` : ''}`));
      }
    };

    this.child.on('close', onExit);
    this.child.on('error', (err) => {
      this.dead = true;
      if (this.pendingReject) {
        const reject = this.pendingReject;
        this.pendingResolve = null;
        this.pendingReject = null;
        reject(err);
      }
    });
  }

  enqueue(prompt: string): Promise<string> {
    const next = this.queue.catch(() => undefined).then(() => this.askOnce(prompt));
    this.queue = next;
    return next;
  }

  private askOnce(prompt: string): Promise<string> {
    if (this.dead) {
      return Promise.reject(new Error('agy session closed'));
    }
    const timeoutMs = this.initialized ? 45000 : 240000;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.dead = true;
        this.pendingResolve = null;
        this.pendingReject = null;
        this.close();
        reject(new Error(`agy timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      this.pendingResolve = (val) => {
        clearTimeout(timer);
        resolve(val);
      };
      this.pendingReject = (err) => {
        clearTimeout(timer);
        reject(err);
      };

      const payload = JSON.stringify({ event: 'user', message: { content: prompt } }) + '\n';
      this.child.stdin.write(payload);
    });
  }

  close(): void {
    this.dead = true;
    try {
      this.child.stdin.end();
      this.child.kill('SIGTERM');
    } catch {
      // ignore
    }
  }
}

const AGY_WORKERS = new Map<string, AgyStreamWorker>();

async function runAgyPrompt(model: string, prompt: string): Promise<string> {
  const agyBin = resolveBinaryPath('agy');
  if (!agyBin) {
    throw new Error('Antigravity CLI (agy) not found. Install via: curl -fsSL https://antigravity.google/cli/install.sh | bash');
  }

  let worker = AGY_WORKERS.get(model);
  if (!worker || worker.dead) {
    worker = new AgyStreamWorker(agyBin, model);
    AGY_WORKERS.set(model, worker);
  }

  return worker.enqueue(
    `[STATELESS JSON EVALUATION — DO NOT CALL ANY TOOLS, DO NOT READ FILES, REPLY IMMEDIATELY WITH ONE RAW JSON OBJECT ONLY]\n\n${prompt}`,
  );
}

export function closeActiveProviderSessions(): void {
  for (const w of AGY_WORKERS.values()) {
    w.close();
  }
  AGY_WORKERS.clear();
}

function runSubprocess(bin: string, args: string[], stdinInput?: string, timeoutMs = 18000): Promise<string> {
  const resolvedBin = resolveBinaryPath(bin) || bin;
  return new Promise((resolve, reject) => {
    const child = spawn(resolvedBin, args, {
      cwd: os.tmpdir(),
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, CI: '1', NO_COLOR: '1' },
    });
    let stdout = '';
    let stderr = '';
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 400).unref();
      reject(new Error(`${bin} timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    child.stdout.on('data', (d) => (stdout += String(d)));
    child.stderr.on('data', (d) => (stderr += String(d)));

    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });

    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code !== 0 && !stdout.trim()) {
        const msg = (stderr || stdout).trim().replace(/\s+/g, ' ').slice(0, 180);
        reject(new Error(`${bin} exited ${code}${msg ? `: ${msg}` : ''}`));
        return;
      }
      resolve(stdout);
    });

    if (stdinInput !== undefined) {
      child.stdin.write(stdinInput);
    }
    child.stdin.end();
  });
}

function extractJsonObject(raw: string): string {
  const cleaned = raw.replace(/```(?:json)?/gi, '').replace(/```/g, '').trim();
  const lastBrace = cleaned.lastIndexOf('}');
  if (lastBrace === -1) throw new Error(`Non-JSON response: ${cleaned.replace(/\s+/g, ' ').slice(0, 120)}`);
  let depth = 0;
  let inStr = false;
  for (let i = lastBrace; i >= 0; i--) {
    const ch = cleaned[i];
    if (inStr) {
      if (ch === '"' && cleaned[i - 1] !== '\\') inStr = false;
      continue;
    }
    if (ch === '"') {
      inStr = true;
      continue;
    }
    if (ch === '}') depth += 1;
    else if (ch === '{') {
      depth -= 1;
      if (depth === 0) {
        return cleaned.slice(i, lastBrace + 1);
      }
    }
  }
  const firstBrace = cleaned.indexOf('{');
  return cleaned.slice(firstBrace, lastBrace + 1);
}

export async function callLLMJson<T>(
  cfg: LLMProviderConfig,
  systemPrompt: string,
  userPrompt: string,
): Promise<T> {
  let rawText = '';
  const combinedCliPrompt = `${systemPrompt}\n\nIMPORTANT: Reply ONLY with a single raw JSON object. Do not wrap in markdown fences or add commentary.\n\n${userPrompt}`;
  const provider = normalizeProviderAlias(cfg.provider);

  if (provider === 'agy-cli') {
    rawText = await runAgyPrompt(cfg.model, combinedCliPrompt);
  } else if (provider === 'claude-cli') {
    const args = ['-p', '--safe-mode', '--tools', ''];
    if (cfg.model && cfg.model !== 'default') args.push('--model', cfg.model);
    rawText = await runSubprocess('claude', args, combinedCliPrompt);
  } else if (provider === 'codex-cli') {
    const args = ['exec', '-c', 'mcp_servers={}', '--skip-git-repo-check', '--color', 'never'];
    if (cfg.model && cfg.model !== 'default') args.push('-m', cfg.model);
    args.push('-');
    rawText = await runSubprocess('codex', args, combinedCliPrompt);
  } else if (provider === 'gemini-cli') {
    const args = ['-e', 'none', '--allowed-mcp-server-names', '__none__', '-p', combinedCliPrompt];
    if (cfg.model && cfg.model !== 'default') args.push('-m', cfg.model);
    rawText = await runSubprocess('gemini', args);
  } else if (provider === 'anthropic') {
    const base = cfg.baseUrl || 'https://api.anthropic.com';
    const url = base.endsWith('/v1') ? `${base}/messages` : `${base}/v1/messages`;
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': cfg.apiKey!,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: cfg.model,
        max_tokens: 900,
        temperature: 0.1,
        system: systemPrompt + '\nRespond ONLY with a valid JSON object. No markdown fences.',
        messages: [{ role: 'user', content: userPrompt }],
      }),
    });
    if (!res.ok) throw new Error(`Anthropic HTTP ${res.status}`);
    const data = (await res.json()) as { content?: Array<{ text?: string }> };
    rawText = data.content?.[0]?.text ?? '';
  } else if (provider === 'openai' || provider === 'openrouter') {
    const url =
      provider === 'openrouter'
        ? 'https://openrouter.ai/api/v1/chat/completions'
        : `${cfg.baseUrl || 'https://api.openai.com/v1'}/chat/completions`;
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${cfg.apiKey!}`,
      },
      body: JSON.stringify({
        model: cfg.model,
        temperature: 0.1,
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: systemPrompt + '\nRespond ONLY with valid JSON.' },
          { role: 'user', content: userPrompt },
        ],
      }),
    });
    if (!res.ok) throw new Error(`${provider} HTTP ${res.status}`);
    const data = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
    rawText = data.choices?.[0]?.message?.content ?? '';
  } else if (provider === 'gemini') {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(cfg.model)}:generateContent?key=${encodeURIComponent(cfg.apiKey!)}`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: systemPrompt + '\nRespond ONLY with valid JSON.' }] },
        contents: [{ role: 'user', parts: [{ text: userPrompt }] }],
        generationConfig: { temperature: 0.1, responseMimeType: 'application/json' },
      }),
    });
    if (!res.ok) throw new Error(`Gemini HTTP ${res.status}`);
    const data = (await res.json()) as {
      candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
    };
    rawText = data.candidates?.[0]?.content?.parts?.[0]?.text ?? '';
  } else if (provider === 'ollama') {
    const res = await fetch(`${cfg.baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        model: cfg.model,
        stream: false,
        format: 'json',
        messages: [
          { role: 'system', content: systemPrompt + '\nRespond ONLY with valid JSON.' },
          { role: 'user', content: userPrompt },
        ],
      }),
    });
    if (!res.ok) throw new Error(`Ollama HTTP ${res.status}`);
    const data = (await res.json()) as { message?: { content?: string } };
    rawText = data.message?.content ?? '';
  }

  return JSON.parse(extractJsonObject(rawText)) as T;
}
