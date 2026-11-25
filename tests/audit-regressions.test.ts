import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { createDemoWorkspace } from '../src/fixtures/demo.js';
import { buildSarifReport, runAudit, type AuditOptions, type ScanReport } from '../src/index.js';
import { startWebDashboard } from '../src/ui/web-server.js';

async function demoWorkspace(t: TestContext): Promise<string> {
  const folder = await createDemoWorkspace();
  t.after(() => fs.rm(folder, { recursive: true, force: true }));
  return folder;
}

function enableSyntheticApiKey(t: TestContext) {
  const previousKey = process.env.OPENAI_API_KEY;
  process.env.OPENAI_API_KEY = 'synthetic-test-key';
  t.after(() => {
    if (previousKey === undefined) delete process.env.OPENAI_API_KEY;
    else process.env.OPENAI_API_KEY = previousKey;
  });
}

test('ambient credentials cannot enable LLM review, and offline modes override provider settings', async (t) => {
  const folder = await demoWorkspace(t);
  enableSyntheticApiKey(t);
  const transport = t.mock.method(globalThis, 'fetch', async () => {
    throw new Error('Unexpected provider request');
  });

  for (const options of [
    {},
    { councilMode: 'auto' },
    { councilMode: 'heuristic', provider: 'openai', judgeSpec: 'openai' },
    { councilMode: 'off', provider: 'openai' },
  ] as AuditOptions[]) {
    const report = await runAudit({ ...options, targets: [folder] });
    assert.ok(report.summary.totalCandidates > 0);
    assert.equal(report.councilMode, options.councilMode === 'off' ? 'off' : 'heuristic');
  }
  assert.equal(transport.mock.callCount(), 0);
});

test('dashboard rescan preserves the selected offline mode and targets', async (t) => {
  const folder = await demoWorkspace(t);
  enableSyntheticApiKey(t);
  const options: AuditOptions = { targets: [folder], councilMode: 'off', provider: 'openai', prove: true };
  const initial = await runAudit(options);
  const dashboard = await startWebDashboard(initial, 0, options);
  t.after(() => dashboard.close());
  const response = await fetch(dashboard.url + '/api/scan', {
    method: 'POST',
    headers: { origin: dashboard.url, 'content-type': 'application/json' },
    body: JSON.stringify({ target: '' }),
  });
  assert.equal(response.status, 200);
  const rescanned = await response.json() as ScanReport;
  assert.equal(rescanned.councilMode, 'off');
  assert.equal(rescanned.targetPath, initial.targetPath);
  assert.deepEqual(rescanned.summary, initial.summary);
  assert.ok(rescanned.findings.every((item) => item.verdict === 'UNREVIEWED' && item.proof === undefined));

  const denied = await fetch(dashboard.url + '/api/scan', {
    method: 'POST',
    headers: { origin: 'https://example.invalid', 'content-type': 'application/json' },
    body: JSON.stringify({ target: '' }),
  });
  assert.equal(denied.status, 403);
});

test('explicit LLM review rejects incomplete responses in strict mode and reports fallback otherwise', async (t) => {
  const folder = await demoWorkspace(t);
  enableSyntheticApiKey(t);
  const transport = t.mock.method(globalThis, 'fetch', async () =>
    Response.json({ choices: [{ message: { content: '{"evaluations":[]}' } }] }),
  );
  const options: AuditOptions = { targets: [folder], councilMode: 'llm', provider: 'openai' };

  const fallback = await runAudit(options);
  assert.equal(transport.mock.callCount(), 2);
  assert.equal(fallback.councilMode, 'heuristic');
  assert.match(fallback.fallbackWarning ?? '', /Incomplete or invalid LLM evaluation/);
  assert.ok(fallback.findings.every((item) => item.council?.mode === 'heuristic'));

  await assert.rejects(runAudit({ ...options, strictLlm: true }), /Incomplete or invalid LLM evaluation/);
});

test('batch verdicts stay attached to valid IDs and duplicate verdicts fall back independently', async (t) => {
  const folder = await demoWorkspace(t);
  enableSyntheticApiKey(t);
  t.mock.method(globalThis, 'fetch', async (_input: unknown, init?: RequestInit) => {
    const { messages } = JSON.parse(String(init?.body)) as { messages: { content: string }[] };
    const ids = [...new Set(Array.from(messages[1].content.matchAll(/CANDIDATE id="([a-f0-9]+)"/g), (match) => match[1]))];
    const instruction = messages[0].content;
    let evaluations: unknown[];
    if (instruction.startsWith('You are ADVOCATE')) {
      evaluations = ids.map((id) => ({ id, exploitScenario: 'Static assessment', attackerControl: '', blastRadius: '', confidence: 0.7 }));
    } else if (instruction.startsWith('You are SKEPTIC')) {
      evaluations = ids.map((id) => ({ id, counterArgument: 'Needs review', mitigatingFactors: [], falsePositiveLikelihood: 0.5 }));
    } else {
      const verdict = { verdict: 'UNCERTAIN', finalSeverity: 'low', confidence: 0.5, rationale: 'Insufficient evidence' };
      evaluations = [{ id: ids[0], ...verdict }, { id: ids[0], ...verdict }, { id: ids[1], ...verdict }];
    }
    return Response.json({ choices: [{ message: { content: JSON.stringify({ evaluations }) } }] });
  });
  const report = await runAudit({ targets: [folder], provider: 'openai', maxLlmFindings: 2 });
  const llmFindings = report.findings.filter(({ council }) => council?.mode === 'llm');
  assert.equal(llmFindings.length, 1);
  assert.equal(llmFindings[0].verdict, 'UNCERTAIN');
  assert.equal(report.findings.filter(({ council }) => council?.fallbackReason).length, 1);
});

test('Codex TOML is scanned, and incomplete coverage is visible even with no findings', async (t) => {
  const folder = await fs.mkdtemp(path.join(os.tmpdir(), 'ahc-coverage-'));
  t.after(() => fs.rm(folder, { recursive: true, force: true }));
  const codex = path.join(folder, '.codex');
  await fs.mkdir(codex);
  const missing = path.join(folder, 'missing');
  const oversized = path.join(folder, 'SKILL.md');
  const config = path.join(codex, 'config.toml');
  await fs.writeFile(oversized, ' '.repeat(512 * 1024 + 1));
  await fs.writeFile(config, [
    '[mcp_servers.local]',
    'url = "https://localhost/mcp"',
    '[mcp_servers.staging]',
    'url = "http://example.invalid/mcp"',
    '[mcp_servers.staging.env]',
    'url = "http://example.invalid/other"',
  ].join('\n'));

  const report = await runAudit({ targets: [folder, missing], councilMode: 'heuristic' });
  assert.equal(report.filesScanned, 1);
  assert.equal(report.coverage, 'partial');
  assert.equal(report.score, null);
  assert.equal(report.grade, null);
  assert.deepEqual(report.findings.map(({ ruleId, line }) => [ruleId, line]), [['AHC-009', 4]]);
  assert.deepEqual(report.scanIssues.map(({ reason }) => reason).sort(), ['file-too-large', 'missing-target']);

  const cli = path.resolve('dist/src/cli.js');
  const empty = spawnSync(process.execPath, [cli, '--json', '--fail-on-confirmed', '--', missing], { encoding: 'utf8' });
  assert.equal(empty.status, 2, empty.stderr);
  const result = JSON.parse(empty.stdout) as ScanReport;
  assert.equal(result.coverage, 'empty');
  assert.equal(result.grade, null);
  assert.equal(result.scanIssues[0].reason, 'missing-target');
});

test('finding IDs are unique across paths, stable across rescans, and deduplicated for overlapping targets', async (t) => {
  const folder = await demoWorkspace(t);
  const original = path.join(folder, 'skills', 'malicious-helper', 'SKILL.md');
  const second = path.join(folder, 'skills', 'same-filename');
  await fs.mkdir(second);
  await fs.copyFile(original, path.join(second, 'SKILL.md'));

  const report = await runAudit({ targets: [folder, original], councilMode: 'off', prove: true });
  const checkpoint = await runAudit({ targets: [folder], councilMode: 'off' });
  const ids = report.findings.map(({ id }) => id);
  assert.ok(ids.length > 0);
  assert.equal(new Set(ids).size, ids.length);
  assert.deepEqual(ids, checkpoint.findings.map(({ id }) => id));
  assert.equal(report.summary.confirmed, 0);
  assert.equal(report.summary.unreviewed, ids.length);
  assert.equal(report.score, null);
  assert.ok(report.findings.every((item) => item.verdict === 'UNREVIEWED' && item.proof === undefined));
  const sarif = buildSarifReport(report) as { runs: { results: { level: string; properties: { verdict: string } }[] }[] };
  assert.ok(sarif.runs[0].results.every((result) => result.level === 'note' && result.properties.verdict === 'UNREVIEWED'));
});
