import http from 'node:http';
import { runAudit } from '../index.js';
import type { ScanReport } from '../types.js';

function buildHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>AgentHack Council — AI Agent & MCP Security Harness</title>
<style>
  :root {
    --bg: #080b10;
    --panel: #0e131b;
    --panel-2: #131a24;
    --border: #1e293b;
    --text: #e2e8f0;
    --muted: #8b9bb4;
    --red: #f43f5e;
    --red-bg: rgba(244, 63, 94, 0.12);
    --amber: #f59e0b;
    --amber-bg: rgba(245, 158, 11, 0.12);
    --green: #10b981;
    --green-bg: rgba(16, 185, 129, 0.12);
    --blue: #38bdf8;
    --blue-bg: rgba(56, 189, 248, 0.1);
    --purple: #a78bfa;
    --purple-bg: rgba(167, 139, 250, 0.12);
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", sans-serif;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.5;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 24px;
    border-bottom: 1px solid var(--border);
    background: rgba(14, 19, 27, 0.9);
    backdrop-filter: blur(8px);
    position: sticky;
    top: 0;
    z-index: 10;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
    font-weight: 700;
    letter-spacing: -0.02em;
    font-size: 16px;
  }
  .brand-badge {
    font-family: var(--mono);
    font-size: 11px;
    padding: 3px 8px;
    border-radius: 999px;
    background: var(--purple-bg);
    color: var(--purple);
    border: 1px solid rgba(167, 139, 250, 0.3);
  }
  .scan-bar {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .scan-bar input {
    background: var(--bg);
    border: 1px solid var(--border);
    color: var(--text);
    font-family: var(--mono);
    font-size: 12px;
    padding: 7px 12px;
    border-radius: 6px;
    width: 300px;
  }
  .scan-bar button {
    background: #e2e8f0;
    color: #080b10;
    border: none;
    font-weight: 600;
    font-size: 12px;
    padding: 7px 14px;
    border-radius: 6px;
    cursor: pointer;
  }
  .scan-bar button:hover { opacity: 0.9; }
  .metrics {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    padding: 18px 24px;
    border-bottom: 1px solid var(--border);
  }
  .metric {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 16px;
  }
  .metric-label {
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .metric-val {
    font-family: var(--mono);
    font-size: 24px;
    font-weight: 700;
    margin-top: 4px;
  }
  .workspace {
    display: grid;
    grid-template-columns: 400px 1fr;
    height: calc(100vh - 155px);
  }
  .finding-list {
    border-right: 1px solid var(--border);
    overflow-y: auto;
    background: var(--panel);
  }
  .finding-item {
    padding: 14px 18px;
    border-bottom: 1px solid var(--border);
    cursor: pointer;
    transition: background 0.12s;
  }
  .finding-item:hover, .finding-item.active {
    background: var(--panel-2);
  }
  .finding-item.active {
    border-left: 3px solid var(--purple);
  }
  .pill {
    display: inline-block;
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 700;
    padding: 2px 7px;
    border-radius: 4px;
    margin-right: 6px;
  }
  .pill-CONFIRMED { background: var(--red-bg); color: var(--red); border: 1px solid rgba(244,63,94,0.35); }
  .pill-UNCERTAIN { background: var(--amber-bg); color: var(--amber); border: 1px solid rgba(245,158,11,0.35); }
  .pill-DISMISSED { background: var(--green-bg); color: var(--green); border: 1px solid rgba(16,185,129,0.35); }
  .detail {
    padding: 24px 32px;
    overflow-y: auto;
  }
  .council-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 14px;
    margin-top: 18px;
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
  }
  .card-advocate { border-top: 2px solid var(--red); }
  .card-skeptic { border-top: 2px solid var(--blue); }
  .card-judge { border-top: 2px solid var(--purple); margin-top: 14px; }
  .card h4 {
    margin: 0 0 8px 0;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    display: flex;
    justify-content: space-between;
  }
  pre {
    background: #05070a;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 14px;
    font-family: var(--mono);
    font-size: 12px;
    overflow-x: auto;
    color: #cbd5e1;
  }
  .canary-banner {
    margin-top: 14px;
    padding: 12px 16px;
    border-radius: 8px;
    background: var(--red-bg);
    border: 1px solid rgba(244,63,94,0.35);
    font-family: var(--mono);
    font-size: 12px;
  }
</style>
</head>
<body>
  <header>
    <div class="brand">
      <span>⚡ AGENTHACK COUNCIL</span>
      <span class="brand-badge">Advocate → Skeptic → Judge</span>
    </div>
    <div class="scan-bar">
      <input id="targetInput" placeholder="Path to scan (e.g. . or ~/.claude)" />
      <button onclick="rescan()">Run Scan</button>
    </div>
  </header>
  <section class="metrics" id="metrics"></section>
  <main class="workspace">
    <aside class="finding-list" id="findingList"></aside>
    <section class="detail" id="detailPane"></section>
  </main>
<script>
  let currentReport = null;
  let selectedIdx = 0;

  function esc(s) {
    return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  async function loadInitial() {
    const res = await fetch('/api/report');
    currentReport = await res.json();
    document.getElementById('targetInput').value = currentReport.targetPath;
    render();
  }

  async function rescan() {
    const target = document.getElementById('targetInput').value.trim();
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target })
    });
    currentReport = await res.json();
    selectedIdx = 0;
    render();
  }

  function render() {
    const r = currentReport;
    const gradeColor = r.score >= 90 ? 'var(--green)' : r.score >= 70 ? 'var(--amber)' : 'var(--red)';
    document.getElementById('metrics').innerHTML = \`
      <div class="metric"><div class="metric-label">Security Posture</div><div class="metric-val" style="color:\${gradeColor}">\${esc(r.grade)} (\${r.score})</div></div>
      <div class="metric"><div class="metric-label">Confirmed Exploitable</div><div class="metric-val" style="color:var(--red)">\${r.summary.confirmed}</div></div>
      <div class="metric"><div class="metric-label">Uncertain (Withheld)</div><div class="metric-val" style="color:var(--amber)">\${r.summary.uncertain}</div></div>
      <div class="metric"><div class="metric-label">Dismissed False Positives</div><div class="metric-val" style="color:var(--green)">\${r.summary.dismissed}</div></div>
      <div class="metric"><div class="metric-label">Council Engine</div><div class="metric-val" style="font-size:14px;color:var(--purple);margin-top:10px">\${esc(r.modelName)}</div></div>
    \`;

    const list = document.getElementById('findingList');
    if (!r.findings.length) {
      list.innerHTML = '<div style="padding:24px;color:var(--green)">✓ Clean scan. Zero suspicious agent findings.</div>';
      document.getElementById('detailPane').innerHTML = '';
      return;
    }

    list.innerHTML = r.findings.map((f, idx) => {
      const v = f.council?.judge?.verdict || 'CONFIRMED';
      const sev = (f.council?.judge?.finalSeverity || f.initialSeverity).toUpperCase();
      return \`
        <div class="finding-item \${idx === selectedIdx ? 'active' : ''}" onclick="selectFinding(\${idx})">
          <div>
            <span class="pill pill-\${v}">\${v}</span>
            <span style="font-family:var(--mono);font-size:11px;color:var(--muted)">\${sev} · \${esc(f.ruleId)}</span>
          </div>
          <div style="font-weight:600;margin-top:6px">\${esc(f.ruleName)}</div>
          <div style="font-family:var(--mono);font-size:11px;color:var(--blue);margin-top:3px">\${esc(f.relativePath)}:\${f.line}</div>
        </div>
      \`;
    }).join('');

    renderDetail();
  }

  function selectFinding(idx) {
    selectedIdx = idx;
    render();
  }

  function renderDetail() {
    const f = currentReport.findings[selectedIdx];
    if (!f) return;
    const v = f.council?.judge?.verdict || 'CONFIRMED';
    const c = f.council;
    document.getElementById('detailPane').innerHTML = \`
      <div>
        <span class="pill pill-\${v}">⚖ \${v}</span>
        <span style="font-family:var(--mono);color:var(--muted)">\${esc(f.ruleId)} · \${esc(f.cwe)} · \${esc(f.category)}</span>
      </div>
      <h2 style="margin:8px 0 4px 0">\${esc(f.ruleName)}</h2>
      <div style="font-family:var(--mono);color:var(--blue);font-size:13px">\${esc(f.relativePath)}:\${f.line}</div>
      <p style="color:var(--muted);margin-top:10px">\${esc(f.evidence)}</p>
      <pre>\${esc(f.contextWindow)}</pre>

      \${f.proof?.executed ? \`
        <div class="canary-banner">
          <strong>\${f.proof.triggeredCanary ? '🧪 CANARY SANDBOX PROOF: EXFILTRATION / CREDENTIAL TARGET CONFIRMED' : '🧪 CANARY SANDBOX: NO ACTIVE RUNTIME TRIGGER'}</strong><br/>
          \${esc(f.proof.details)}
        </div>
      \` : ''}

      \${c ? \`
        <div class="council-grid">
          <div class="card card-advocate">
            <h4 style="color:var(--red)"><span>🔴 Advocate (Offensive Case)</span><span>\${Math.round(c.advocate.confidence * 100)}% conf</span></h4>
            <p>\${esc(c.advocate.exploitScenario)}</p>
            <div style="font-size:12px;color:var(--muted)"><strong>Control:</strong> \${esc(c.advocate.attackerControl)}<br/><strong>Blast Radius:</strong> \${esc(c.advocate.blastRadius)}</div>
          </div>
          <div class="card card-skeptic">
            <h4 style="color:var(--blue)"><span>🔵 Skeptic (False-Positive Check)</span><span>\${Math.round(c.skeptic.falsePositiveLikelihood * 100)}% FP prob</span></h4>
            <p>\${esc(c.skeptic.counterArgument)}</p>
          </div>
        </div>
        <div class="card card-judge">
          <h4 style="color:var(--purple)"><span>⚖ Judge Verdict: \${v}</span><span>Final Severity: \${esc(c.judge.finalSeverity.toUpperCase())}</span></h4>
          <p>\${esc(c.judge.rationale)}</p>
          \${c.judge.minimalPatch ? \`<div style="font-size:12px;color:var(--muted);margin-top:10px">Suggested Minimal Remediation Patch:</div><pre>\${esc(c.judge.minimalPatch)}</pre>\` : ''}
        </div>
      \` : ''}
    \`;
  }

  loadInitial();
</script>
</body>
</html>`;
}

export async function startWebDashboard(
  initialReport: ScanReport,
  port = 4317,
  prove = true,
): Promise<string> {
  let latestReport = initialReport;

  const server = http.createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/api/report') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(latestReport));
      return;
    }

    if (req.method === 'POST' && req.url === '/api/scan') {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', async () => {
        try {
          const parsed = JSON.parse(body || '{}') as { target?: string };
          const targets = parsed.target ? parsed.target.split(',').map((s) => s.trim()).filter(Boolean) : undefined;
          latestReport = await runAudit({ targets, prove });
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify(latestReport));
        } catch (err) {
          res.writeHead(400, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: String(err) }));
        }
      });
      return;
    }

    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(buildHtml());
  });

  await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', () => resolve()));
  return `http://127.0.0.1:${port}`;
}
