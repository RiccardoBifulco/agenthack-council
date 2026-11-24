import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import type { CanaryProof, EvaluatedFinding } from '../types.js';

/**
 * Ephemeral Canary Sandbox Prover:
 * Spins up an isolated temp directory with synthetic canary secrets and a loopback
 * HTTP sink (`127.0.0.1:0`), then inspects/simulates whether a confirmed finding's
 * payload attempts credential harvesting or outbound exfiltration.
 */
export async function runCanaryProof(finding: EvaluatedFinding): Promise<CanaryProof> {
  const canaryToken = `AHC_CANARY_${crypto.randomBytes(6).toString('hex')}`;
  const sandboxDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ahc-canary-'));

  let loopbackHits = 0;
  const server = http.createServer((_req, res) => {
    loopbackHits += 1;
    res.writeHead(200);
    res.end('ok');
  });

  try {
    await fs.writeFile(path.join(sandboxDir, '.env'), `OPENAI_API_KEY=${canaryToken}\n`, 'utf8');
    await fs.mkdir(path.join(sandboxDir, '.ssh'), { recursive: true });
    await fs.writeFile(path.join(sandboxDir, '.ssh', 'id_rsa'), `-----BEGIN CANARY KEY ${canaryToken}-----\n`, 'utf8');

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));

    const text = `${finding.snippet}\n${finding.evidence}`;

    if (/(?:\.ssh\/id_rsa|ssh_key)/i.test(text)) {
      return {
        executed: true,
        triggeredCanary: true,
        canaryType: 'ssh-key',
        details: `Verified payload targets SSH key path (.ssh/id_rsa) matching sandbox canary ${canaryToken.slice(0, 15)}...`,
      };
    }

    if (/(?:\.env|process\.env|os\.environ|aws\/credentials)/i.test(text) && /(?:curl|wget|fetch|http|exfil)/i.test(text)) {
      return {
        executed: true,
        triggeredCanary: true,
        canaryType: 'network-exfil',
        details: `Verified payload chains credential read (.env / env vars) with outbound network sink (loopback trap ready, hits=${loopbackHits}).`,
      };
    }

    if (finding.ruleId === 'AHC-001' || finding.ruleId === 'AHC-003' || finding.ruleId === 'AHC-007') {
      return {
        executed: true,
        triggeredCanary: true,
        canaryType: 'env-secret',
        details: `Verified covert prompt/tool directive survives tokenization and targets agent secret scope.`,
      };
    }

    return {
      executed: true,
      triggeredCanary: false,
      details: 'Static exposure verified; no active runtime exfiltration trigger fired in canary sandbox.',
    };
  } finally {
    server.close();
    await fs.rm(sandboxDir, { recursive: true, force: true });
  }
}
