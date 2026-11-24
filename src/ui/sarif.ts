import crypto from 'node:crypto';
import path from 'node:path';
import { RULES_CATALOG } from '../scanner/rules.js';
import type { EvaluatedFinding, ScanReport, Severity } from '../types.js';
import { VERSION } from '../version.js';

function toSarifLevel(verdict: string, sev: Severity): 'error' | 'warning' | 'note' {
  if (verdict === 'UNCERTAIN') return 'note';
  if (sev === 'critical' || sev === 'high') return 'error';
  if (sev === 'medium') return 'warning';
  return 'note';
}

function normalizeSarifUri(relPath: string, fullPath: string): string {
  const unix = relPath.replace(/\\/g, '/').replace(/^\.\//, '');
  if (!unix || unix.startsWith('/') || unix.startsWith('..')) {
    return path.basename(fullPath);
  }
  return unix;
}

function formatMessage(f: EvaluatedFinding): string {
  const parts = [`[${f.ruleName}] ${f.evidence}`];
  if (f.council) {
    parts.push(`Council Verdict: ${f.council.judge.verdict} (${f.council.modelUsed}) — ${f.council.judge.rationale}`);
  }
  if (f.proof?.executed && f.proof.triggeredCanary) {
    parts.push(`Canary Sandbox Proof: ${f.proof.details}`);
  }
  return parts.join(' | ');
}

export function buildSarifReport(report: ScanReport): Record<string, unknown> {
  const rules = RULES_CATALOG.map((r) => ({
    id: r.id,
    name: r.name.replace(/[^A-Za-z0-9]+/g, ''),
    shortDescription: { text: r.shortDescription },
    fullDescription: { text: r.fullDescription },
    helpUri: `https://github.com/RiccardoBifulco/agenthack-council#${r.id.toLowerCase()}`,
    help: {
      text: `${r.fullDescription} (${r.cwe})`,
      markdown: `### ${r.id}: ${r.name} (\`${r.cwe}\`)\n\n${r.fullDescription}`,
    },
    defaultConfiguration: {
      level: r.defaultSeverity === 'critical' || r.defaultSeverity === 'high' ? 'error' : 'warning',
    },
    properties: {
      tags: ['security', 'ai-security', 'mcp', `external/cwe/${r.cwe.toLowerCase()}`],
      'security-severity': r.securitySeverityScore,
      precision: 'high',
    },
  }));

  const ruleIndexMap = new Map<string, number>(RULES_CATALOG.map((r, idx) => [r.id, idx]));

  const activeFindings = report.findings.filter(
    (f) => (f.council?.judge.verdict ?? 'CONFIRMED') !== 'DISMISSED',
  );

  const results = activeFindings.map((f) => {
    const verdict = f.council?.judge.verdict ?? 'CONFIRMED';
    const sev = f.council?.judge.finalSeverity ?? f.initialSeverity;
    const uri = normalizeSarifUri(f.relativePath, f.filePath);
    const fingerprint = crypto
      .createHash('sha256')
      .update(`${f.ruleId}:${uri}:${f.line}:${f.snippet}`)
      .digest('hex')
      .slice(0, 32);

    return {
      ruleId: f.ruleId,
      ruleIndex: ruleIndexMap.get(f.ruleId) ?? 0,
      level: toSarifLevel(verdict, sev),
      message: {
        text: formatMessage(f),
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri,
              uriBaseId: '%SRCROOT%',
            },
            region: {
              startLine: Math.max(1, f.line),
              snippet: { text: f.snippet },
            },
          },
        },
      ],
      partialFingerprints: {
        primaryLocationLineHash: fingerprint,
      },
      properties: {
        category: f.category,
        cwe: f.cwe,
        verdict,
        confidence: f.council?.judge.confidence ?? 1,
        councilModel: f.council?.modelUsed ?? 'none',
        canaryTriggered: Boolean(f.proof?.triggeredCanary),
        minimalPatch: f.council?.judge.minimalPatch,
      },
    };
  });

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'AgentHack Council',
            version: VERSION,
            informationUri: 'https://github.com/RiccardoBifulco/agenthack-council',
            rules,
          },
        },
        properties: {
          grade: report.grade,
          score: report.score,
          councilMode: report.councilMode,
          modelName: report.modelName,
          summary: report.summary,
        },
        results,
      },
    ],
  };
}
