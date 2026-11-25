import http from 'node:http';
import { runAudit, type AuditOptions } from '../index.js';
import type { ScanReport } from '../types.js';
import { VERSION } from '../version.js';
import { buildSarifReport } from './sarif.js';

function buildHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>AgentHack Council v${VERSION} — AI Agent & MCP Security Harness</title>
<style>
  :root {
    --bg: #070a0f;
    --panel: #0d121a;
    --panel-2: #121925;
    --border: #1e293b;
    --text: #e2e8f0;
    --muted: #8b9bb4;
    --red: #f43f5e;
    --red-bg: rgba(244, 63, 94, 0.13);
    --amber: #f59e0b;
    --amber-bg: rgba(245, 158, 11, 0.13);
    --green: #10b981;
    --green-bg: rgba(16, 185, 129, 0.13);
    --blue: #38bdf8;
    --blue-bg: rgba(56, 189, 248, 0.12);
    --purple: #a78bfa;
    --purple-bg: rgba(167, 139, 250, 0.14);
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
    padding: 13px 24px;
    border-bottom: 1px solid var(--border);
    background: rgba(13, 18, 26, 0.92);
    backdrop-filter: blur(8px);
    position: sticky;
    top: 0;
    z-index: 10;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 700;
    letter-spacing: -0.02em;
    font-size: 15px;
  }
  .brand-badge {
    font-family: var(--mono);
    font-size: 11px;
    padding: 3px 9px;
    border-radius: 999px;
    background: var(--purple-bg);
    color: var(--purple);
    border: 1px solid rgba(167, 139, 250, 0.32);
  }
  .brand-ver {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    font-weight: 500;
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
    width: 280px;
  }
  .btn {
    background: #e2e8f0;
    color: #080b10;
    border: none;
    font-weight: 600;
    font-size: 12px;
    padding: 7px 13px;
    border-radius: 6px;
    cursor: pointer;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }
  .btn-ghost {
    background: var(--panel-2);
    color: var(--text);
    border: 1px solid var(--border);
    font-family: var(--mono);
    font-size: 11px;
    padding: 6px 11px;
  }
  .btn:hover { opacity: 0.9; }
  .metrics {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    padding: 16px 24px;
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
    grid-template-columns: 410px 1fr;
    height: calc(100vh - 150px);
  }
  .sidebar {
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    background: var(--panel);
    overflow: hidden;
  }
  .filter-bar {
    display: flex;
    gap: 6px;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    background: #0a0f16;
  }
  .filter-tab {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--muted);
    font-family: var(--mono);
    font-size: 11px;
    padding: 4px 9px;
    border-radius: 999px;
    cursor: pointer;
  }
  .filter-tab.active {
    background: var(--purple-bg);
    color: var(--purple);
    border-color: rgba(167, 139, 250, 0.45);
    font-weight: 600;
  }
  .finding-list {
    overflow-y: auto;
    flex: 1;
  }
  .finding-item {
    padding: 13px 16px;
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
  .pill-canary { background: rgba(244,63,94,0.2); color: #fda4af; border: 1px solid rgba(244,63,94,0.4); }
  .detail {
    padding: 22px 30px;
    overflow-y: auto;
  }
  .council-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 14px;
    margin-top: 16px;
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
    align-items: center;
  }
  .model-chip {
    font-family: var(--mono);
    font-size: 10px;
    text-transform: none;
    letter-spacing: 0;
    padding: 2px 6px;
    border-radius: 4px;
    background: #070a0f;
    border: 1px solid var(--border);
    color: var(--muted);
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
    margin: 8px 0 0 0;
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
  .canary-banner.safe {
    background: var(--green-bg);
    border-color: rgba(16,185,129,0.35);
  }
  .patch-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 12px;
  }
</style>
</head>
<body>
  <header>
    <div class="brand">
      <span>⚡ AGENTHACK COUNCIL</span>
      <span class="brand-ver">v${VERSION}</span>
      <span class="brand-badge">Advocate → Skeptic → Judge</span>
    </div>
    <div class="scan-bar">
      <input id="targetInput" placeholder="Path to scan (e.g. . or ~/.claude)" />
      <button class="btn" onclick="rescan()">Run Scan</button>
      <a class="btn btn-ghost" href="/api/sarif" download="agenthack-council.sarif">⬇ SARIF</a>
      <a class="btn btn-ghost" href="/api/report" download="agenthack-council.json">⬇ JSON</a>
    </div>
  </header>
  <div id="scanError" role="status" hidden></div>
  <div id="coverage" role="status"></div>
  <section class="metrics" id="metrics"></section>
  <main class="workspace">
    <aside class="sidebar">
      <div class="filter-bar" id="filterBar"></div>
      <div class="finding-list" id="findingList"></div>
    </aside>
    <section class="detail" id="detailPane"></section>
  </main>
<script>
  let currentReport = null;
  let activeFilter = 'ALL';
  let selectedId = null;

  function esc(s) {
    return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  async function loadInitial() {
    const res = await fetch('/api/report');
    currentReport = await res.json();
    document.getElementById('targetInput').value = currentReport.targetPath;
    if (currentReport.findings?.length) selectedId = currentReport.findings[0].id;
    render();
  }

  async function rescan() {
    const target = document.getElementById('targetInput').value.trim();
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target })
    });
    const result = await res.json();
    const status = document.getElementById('scanError');
    status.hidden = res.ok;
    status.textContent = res.ok ? '' : result.error;
    if (!res.ok) return;
    currentReport = result;
    selectedId = currentReport.findings?.[0]?.id || null;
    render();
  }

  function setFilter(f) {
    activeFilter = f;
    const visible = getFilteredFindings();
    if (visible.length && !visible.some(x => x.id === selectedId)) {
      selectedId = visible[0].id;
    }
    render();
  }

  function getFilteredFindings() {
    if (!currentReport?.findings) return [];
    if (activeFilter === 'ALL') return currentReport.findings;
    return currentReport.findings.filter(f => (f.verdict) === activeFilter);
  }

  async function copyPatch(btn) {
    const f = currentReport.findings.find(x => x.id === selectedId);
    const patch = f?.council?.judge?.minimalPatch;
    if (!patch) return;
    await navigator.clipboard.writeText(patch);
    const orig = btn.textContent;
    btn.textContent = '✓ Copied';
    setTimeout(() => { btn.textContent = orig; }, 1400);
  }

  function render() {
    const r = currentReport;
    const gradeColor = r.score === null ? 'var(--muted)' : r.score >= 90 ? 'var(--green)' : r.score >= 70 ? 'var(--amber)' : 'var(--red)';
    document.getElementById('coverage').textContent = r.coverage === 'complete' ? '' :
      'Coverage: ' + r.coverage + (r.scanIssues.length ? ' · ' + r.scanIssues.map(x => x.path + ' (' + x.reason + ')').join(', ') : '');
    document.getElementById('metrics').innerHTML = \`
      <div class="metric"><div class="metric-label">Security Posture</div><div class="metric-val" style="color:\${gradeColor}">\${r.score === null ? 'Not graded' : esc(r.grade) + ' (' + r.score + ')'}</div></div>
      <div class="metric"><div class="metric-label">Deterministic CI policy</div><div class="metric-val" style="color:var(--red)">\${r.summary.ciBlocking}</div></div>
      <div class="metric"><div class="metric-label">Council-confirmed</div><div class="metric-val" style="color:var(--red)">\${r.summary.confirmed}</div></div>
      <div class="metric"><div class="metric-label">Uncertain (Withheld)</div><div class="metric-val" style="color:var(--amber)">\${r.summary.uncertain}</div></div>
      <div class="metric"><div class="metric-label">Dismissed False Positives</div><div class="metric-val" style="color:var(--green)">\${r.summary.dismissed}</div></div>
      <div class="metric"><div class="metric-label">Council Engine (\${r.filesScanned} files · \${r.durationMs}ms)</div><div class="metric-val" style="font-size:13px;color:var(--purple);margin-top:10px">\${esc(r.modelName)}</div></div>
    \`;

    const tabs = [
      ['ALL', \`All (\${r.summary.totalCandidates})\`],
      ['UNREVIEWED', 'Unreviewed (' + r.summary.unreviewed + ')'],
      ['CONFIRMED', \`Confirmed (\${r.summary.confirmed})\`],
      ['UNCERTAIN', \`Uncertain (\${r.summary.uncertain})\`],
      ['DISMISSED', \`Dismissed (\${r.summary.dismissed})\`],
    ];
    document.getElementById('filterBar').innerHTML = tabs.map(([key, label]) =>
      \`<button class="filter-tab \${activeFilter === key ? 'active' : ''}" onclick="setFilter('\${key}')">\${label}</button>\`
    ).join('');

    const visible = getFilteredFindings();
    const list = document.getElementById('findingList');
    if (!visible.length) {
      list.innerHTML = '<div style="padding:24px">No findings in this filter.</div>';
      document.getElementById('detailPane').innerHTML = '';
      return;
    }

    list.innerHTML = visible.map((f) => {
      const v = f.verdict;
      const sev = (f.council?.judge?.finalSeverity || f.initialSeverity).toUpperCase();
      return \`
        <div class="finding-item \${f.id === selectedId ? 'active' : ''}" onclick="selectFinding('\${esc(f.id)}')">
          <div>
            <span class="pill pill-\${v}">\${v}</span>
            \${f.ciBlocking ? '<span class="pill pill-canary">CI policy</span>' : ''}
            \${f.proof?.signal ? '<span class="pill pill-canary">Static evidence</span>' : ''}
            <span style="font-family:var(--mono);font-size:11px;color:var(--muted)">\${sev} · \${esc(f.ruleId)}</span>
          </div>
          <div style="font-weight:600;margin-top:6px">\${esc(f.ruleName)}</div>
          <div style="font-family:var(--mono);font-size:11px;color:var(--blue);margin-top:3px">\${esc(f.relativePath)}:\${f.line}</div>
        </div>
      \`;
    }).join('');

    renderDetail();
  }

  function selectFinding(id) {
    selectedId = id;
    render();
  }

  function renderDetail() {
    const f = currentReport.findings.find(x => x.id === selectedId);
    if (!f) return;
    const v = f.verdict;
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

      \${f.proof ? \`
        <div class="canary-banner">
          <strong>Static evidence</strong><br/>
          \${esc(f.proof.details)}
        </div>
      \` : ''}

      \${c ? \`
        <div class="council-grid">
          <div class="card card-advocate">
            <h4 style="color:var(--red)"><span>🔴 Advocate (Offensive Case)</span><span class="model-chip">\${esc(c.advocate.modelUsed || c.modelUsed)} · \${Math.round(c.advocate.confidence * 100)}%</span></h4>
            <p>\${esc(c.advocate.exploitScenario)}</p>
            <div style="font-size:12px;color:var(--muted)"><strong>Control:</strong> \${esc(c.advocate.attackerControl)}<br/><strong>Blast Radius:</strong> \${esc(c.advocate.blastRadius)}</div>
          </div>
          <div class="card card-skeptic">
            <h4 style="color:var(--blue)"><span>🔵 Skeptic (False-Positive Check)</span><span class="model-chip">\${esc(c.skeptic.modelUsed || c.modelUsed)} · \${Math.round(c.skeptic.falsePositiveLikelihood * 100)}% FP</span></h4>
            <p>\${esc(c.skeptic.counterArgument)}</p>
          </div>
        </div>
        <div class="card card-judge">
          <h4 style="color:var(--purple)"><span>⚖ Judge Verdict: \${v}</span><span class="model-chip">\${esc(c.judge.modelUsed || c.modelUsed)} · Severity: \${esc(c.judge.finalSeverity.toUpperCase())}</span></h4>
          <p>\${esc(c.judge.rationale)}</p>
          \${c.judge.minimalPatch ? \`
            <div class="patch-header">
              <span style="font-size:12px;color:var(--muted)">Suggested Minimal Remediation Patch (Secrets Pre-Redacted):</span>
              <button class="btn btn-ghost" onclick="copyPatch(this)">Copy Diff</button>
            </div>
            <pre>\${esc(c.judge.minimalPatch)}</pre>
          \` : ''}
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
  auditOptions: AuditOptions = {},
): Promise<{ url: string; close: () => Promise<void> }> {
  let latestReport = initialReport;
  let latestTargets = auditOptions.targets;
  let origin: string;
  let host: string;
  let scanning = false;

  const server = http.createServer(async (req, res) => {
    if (req.headers.host !== host) {
      res.writeHead(403).end();
      return;
    }
    if (req.method === 'GET' && req.url === '/api/report') {
      res.writeHead(200, {
        'content-type': 'application/json',
        'content-disposition': 'inline; filename="agenthack-council.json"',
      });
      res.end(JSON.stringify(latestReport, null, 2));
      return;
    }

    if (req.method === 'GET' && req.url === '/api/sarif') {
      res.writeHead(200, {
        'content-type': 'application/sarif+json',
        'content-disposition': 'attachment; filename="agenthack-council.sarif"',
      });
      res.end(JSON.stringify(buildSarifReport(latestReport), null, 2));
      return;
    }

    if (req.method === 'POST' && req.url === '/api/scan') {
      const contentType = req.headers['content-type']?.split(';', 1)[0]?.trim();
      if (contentType !== 'application/json' || (req.headers.origin && req.headers.origin !== origin)) {
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Rescan requires a same-origin JSON request.' }));
        return;
      }

      try {
        let body = '';
        req.setEncoding('utf8');
        for await (const chunk of req.iterator({ destroyOnReturn: false })) {
          body += chunk;
          if (body.length > 16384) {
            req.resume();
            res.writeHead(413, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: 'Rescan request is too large.' }));
            return;
          }
        }
        const parsed = JSON.parse(body) as { target?: unknown } | null;
        if (typeof parsed?.target !== 'string') throw new Error('Expected a target string.');
        const requested = parsed.target.trim();
        const targets = !requested || requested === latestReport.targetPath
          ? latestTargets
          : requested.split(',').map((item) => item.trim()).filter(Boolean);
        if (targets?.length === 0 && requested && requested !== latestReport.targetPath) {
          throw new Error('Expected at least one target path.');
        }
        if (scanning) {
          res.writeHead(409, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'A scan is already running.' }));
          return;
        }
        scanning = true;
        try {
          latestReport = await runAudit({ ...auditOptions, targets });
          latestTargets = targets;
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify(latestReport));
        } finally {
          scanning = false;
        }
      } catch (err) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
      }
      return;
    }

    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(buildHtml());
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  const addr = server.address();
  const actualPort = typeof addr === 'object' && addr ? addr.port : port;
  host = '127.0.0.1:' + actualPort;
  origin = 'http://' + host;
  return {
    url: origin,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
