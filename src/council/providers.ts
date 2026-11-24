import { execFileSync, spawn } from 'node:child_process';
import os from 'node:os';

export type ProviderName =
  | 'anthropic'
  | 'openai'
  | 'gemini'
  | 'openrouter'
  | 'ollama'
  | 'claude-cli'
  | 'codex-cli'
  | 'gemini-cli';

const VALID_PROVIDERS = new Set<ProviderName>([
  'anthropic',
  'openai',
  'gemini',
  'openrouter',
  'ollama',
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
  return { provider: rawProvider, model: rawModel };
}

function hasBinary(bin: string): boolean {
  const lookupCmd = process.platform === 'win32' ? 'where' : 'which';
  try {
    execFileSync(lookupCmd, [bin], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

export function resolveProvider(
  preferredProvider?: ProviderName,
  preferredModel?: string,
): LLMProviderConfig | null {
  if (preferredProvider === 'claude-cli') {
    return { provider: 'claude-cli', model: preferredModel || 'default' };
  }
  if (preferredProvider === 'codex-cli') {
    return { provider: 'codex-cli', model: preferredModel || 'default' };
  }
  if (preferredProvider === 'gemini-cli') {
    return { provider: 'gemini-cli', model: preferredModel || 'default' };
  }
  if (preferredProvider === 'ollama') {
    return {
      provider: 'ollama',
      model: preferredModel || process.env.OLLAMA_MODEL || 'qwen2.5-coder:7b',
      baseUrl: process.env.OLLAMA_HOST || 'http://127.0.0.1:11434',
    };
  }

  if ((!preferredProvider || preferredProvider === 'anthropic') && process.env.ANTHROPIC_API_KEY) {
    return {
      provider: 'anthropic',
      model: preferredModel || process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-5',
      apiKey: process.env.ANTHROPIC_API_KEY,
      baseUrl: (process.env.ANTHROPIC_BASE_URL || 'https://api.anthropic.com').replace(/\/+$/, ''),
    };
  }
  if ((!preferredProvider || preferredProvider === 'openai') && process.env.OPENAI_API_KEY) {
    return {
      provider: 'openai',
      model: preferredModel || process.env.OPENAI_MODEL || 'gpt-4o-mini',
      apiKey: process.env.OPENAI_API_KEY,
      baseUrl: (process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1').replace(/\/+$/, ''),
    };
  }
  if ((!preferredProvider || preferredProvider === 'gemini') && process.env.GEMINI_API_KEY) {
    return {
      provider: 'gemini',
      model: preferredModel || 'gemini-2.5-flash',
      apiKey: process.env.GEMINI_API_KEY,
    };
  }
  if ((!preferredProvider || preferredProvider === 'openrouter') && process.env.OPENROUTER_API_KEY) {
    return {
      provider: 'openrouter',
      model: preferredModel || 'anthropic/claude-3.5-sonnet',
      apiKey: process.env.OPENROUTER_API_KEY,
    };
  }
  if (!preferredProvider && process.env.OLLAMA_MODEL) {
    return {
      provider: 'ollama',
      model: preferredModel || process.env.OLLAMA_MODEL,
      baseUrl: process.env.OLLAMA_HOST || 'http://127.0.0.1:11434',
    };
  }

  // Zero-API-key subscription CLI auto-detection when explicitly running `--council llm`
  if (!preferredProvider) {
    if (hasBinary('claude')) return { provider: 'claude-cli', model: preferredModel || 'default' };
    if (hasBinary('codex')) return { provider: 'codex-cli', model: preferredModel || 'default' };
    if (hasBinary('gemini')) return { provider: 'gemini-cli', model: preferredModel || 'default' };
  }

  return null;
}

function runSubprocess(bin: string, args: string[], stdinInput?: string, timeoutMs = 18000): Promise<string> {
  return new Promise((resolve, reject) => {
    // Run inside os.tmpdir() so local CLI agents never auto-load untrusted .mcp.json / CLAUDE.md from target cwd
    const child = spawn(bin, args, {
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

  if (cfg.provider === 'claude-cli') {
    const args = ['-p', '--safe-mode', '--tools', ''];
    if (cfg.model && cfg.model !== 'default') args.push('--model', cfg.model);
    rawText = await runSubprocess('claude', args, combinedCliPrompt);
  } else if (cfg.provider === 'codex-cli') {
    const args = ['exec', '-c', 'mcp_servers={}', '--skip-git-repo-check', '--color', 'never'];
    if (cfg.model && cfg.model !== 'default') args.push('-m', cfg.model);
    args.push('-');
    rawText = await runSubprocess('codex', args, combinedCliPrompt);
  } else if (cfg.provider === 'gemini-cli') {
    const args = ['-e', 'none', '--allowed-mcp-server-names', '__none__', '-p', combinedCliPrompt];
    if (cfg.model && cfg.model !== 'default') args.push('-m', cfg.model);
    rawText = await runSubprocess('gemini', args);
  } else if (cfg.provider === 'anthropic') {
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
  } else if (cfg.provider === 'openai' || cfg.provider === 'openrouter') {
    const url =
      cfg.provider === 'openrouter'
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
    if (!res.ok) throw new Error(`${cfg.provider} HTTP ${res.status}`);
    const data = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
    rawText = data.choices?.[0]?.message?.content ?? '';
  } else if (cfg.provider === 'gemini') {
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
  } else if (cfg.provider === 'ollama') {
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
