export interface LLMProviderConfig {
  provider: 'anthropic' | 'openai' | 'gemini' | 'openrouter' | 'ollama';
  model: string;
  apiKey?: string;
  baseUrl?: string;
}

export function detectLLMProvider(preferredModel?: string): LLMProviderConfig | null {
  if (process.env.ANTHROPIC_API_KEY) {
    return {
      provider: 'anthropic',
      model: preferredModel || 'claude-sonnet-4-20250514',
      apiKey: process.env.ANTHROPIC_API_KEY,
    };
  }
  if (process.env.OPENAI_API_KEY) {
    return {
      provider: 'openai',
      model: preferredModel || 'gpt-4o-mini',
      apiKey: process.env.OPENAI_API_KEY,
    };
  }
  if (process.env.GEMINI_API_KEY) {
    return {
      provider: 'gemini',
      model: preferredModel || 'gemini-2.5-flash',
      apiKey: process.env.GEMINI_API_KEY,
    };
  }
  if (process.env.OPENROUTER_API_KEY) {
    return {
      provider: 'openrouter',
      model: preferredModel || 'anthropic/claude-3.5-sonnet',
      apiKey: process.env.OPENROUTER_API_KEY,
    };
  }
  if (process.env.OLLAMA_MODEL) {
    return {
      provider: 'ollama',
      model: preferredModel || process.env.OLLAMA_MODEL,
      baseUrl: process.env.OLLAMA_HOST || 'http://127.0.0.1:11434',
    };
  }
  return null;
}

export async function callLLMJson<T>(
  cfg: LLMProviderConfig,
  systemPrompt: string,
  userPrompt: string,
): Promise<T> {
  let rawText = '';

  if (cfg.provider === 'anthropic') {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
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
        : 'https://api.openai.com/v1/chat/completions';
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

  const cleaned = rawText.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();
  return JSON.parse(cleaned) as T;
}
