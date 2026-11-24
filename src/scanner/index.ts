import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { CandidateFinding } from '../types.js';
import { classifyFile, scanFileContent } from './rules.js';

const IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  '.next',
  '__pycache__',
  '.venv',
  'venv',
  'vendor',
  'coverage',
]);

const MAX_FILE_BYTES = 512 * 1024; // 512 KB

export interface StaticScanResult {
  filesScanned: number;
  candidates: CandidateFinding[];
}

async function walkDir(rootDir: string, currentDir: string, out: string[], maxFiles = 1500): Promise<void> {
  if (out.length >= maxFiles) return;
  let entries;
  try {
    entries = await fs.readdir(currentDir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (out.length >= maxFiles) break;
    if (IGNORED_DIRS.has(entry.name)) continue;
    const full = path.join(currentDir, entry.name);
    if (entry.isDirectory()) {
      await walkDir(rootDir, full, out, maxFiles);
    } else if (entry.isFile()) {
      if (classifyFile(full) !== null) {
        out.push(full);
      }
    }
  }
}

export async function discoverLocalAgentPaths(): Promise<string[]> {
  const home = os.homedir();
  const candidates = [
    path.join(home, '.claude'),
    path.join(home, '.cursor'),
    path.join(home, '.codex'),
    path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
  ];
  const existing: string[] = [];
  for (const p of candidates) {
    try {
      await fs.access(p);
      existing.push(p);
    } catch {
      // skip missing
    }
  }
  return existing;
}

export async function runStaticScan(targetPaths: string[]): Promise<StaticScanResult> {
  const filesToScan: Array<{ fullPath: string; baseRoot: string }> = [];

  for (const rawTarget of targetPaths) {
    const resolved = path.resolve(rawTarget);
    let stat;
    try {
      stat = await fs.stat(resolved);
    } catch {
      continue;
    }

    if (stat.isFile()) {
      filesToScan.push({ fullPath: resolved, baseRoot: path.dirname(resolved) });
    } else if (stat.isDirectory()) {
      const discovered: string[] = [];
      await walkDir(resolved, resolved, discovered);
      for (const f of discovered) {
        filesToScan.push({ fullPath: f, baseRoot: resolved });
      }
    }
  }

  let filesScanned = 0;
  const candidates: CandidateFinding[] = [];

  for (const { fullPath, baseRoot } of filesToScan) {
    const category = classifyFile(fullPath);
    if (!category) continue;

    // For generic code files (.ts/.js/.py/.go), only scan if it looks MCP/agent-related to stay fast & high-signal
    let stat;
    try {
      stat = await fs.stat(fullPath);
    } catch {
      continue;
    }
    if (stat.size > MAX_FILE_BYTES) continue;

    let content: string;
    try {
      content = await fs.readFile(fullPath, 'utf8');
    } catch {
      continue;
    }

    if (
      category === 'mcp-server-code' &&
      !/(?:mcp|ModelContextProtocol|server\.tool|addTool|FastMCP|CallToolRequest|SKILL|CLAUDE|prompt)/i.test(content)
    ) {
      continue;
    }

    filesScanned += 1;
    const rel = path.relative(baseRoot, fullPath) || path.basename(fullPath);
    const fileFindings = scanFileContent(fullPath, rel, content, category);
    candidates.push(...fileFindings);
  }

  return { filesScanned, candidates };
}
