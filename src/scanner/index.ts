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
  '.tmp',
  '.staging',
  'marketplaces',
  'backups',
  'archivio',
  '.cache',
  '.npm',
  '.pnpm-store',
  '.yarn',
  '.cargo',
  '.rustup',
  '.Trash',
  // Agent runtime session/transcript/telemetry directories (not skills or configs)
  'projects',
  'session-env',
  'sessions',
  'file-history',
  'paste-cache',
  'shell-snapshots',
  'telemetry',
  'debug',
  'todos',
  'uploads',
  // OS home media/system folders when invoked from ~
  'Library',
  'Applications',
  'Pictures',
  'Music',
  'Movies',
  'Downloads',
]);

const HIGH_PRIORITY_DIRS = new Set([
  '.claude',
  '.cursor',
  '.codex',
  '.gemini',
  'skills',
  'skills-cursor',
  'rules',
  'hooks',
  'mcp-servers',
  'agents',
  'commands',
]);

const LOW_PRIORITY_DIRS = new Set(['plugins', 'vendor_imports', 'marketplaces', 'cache']);

const MAX_FILE_BYTES = 512 * 1024; // 512 KB

const MCP_SERVER_CODE_MARKERS =
  /(?:@modelcontextprotocol|ModelContextProtocol|FastMCP|McpServer|server\.tool\s*\(|addTool\s*\(|CallToolRequest|ListToolsRequest|@mcp\.tool)/i;

export interface StaticScanResult {
  filesScanned: number;
  candidates: CandidateFinding[];
}

function dirPriority(name: string): number {
  if (HIGH_PRIORITY_DIRS.has(name)) return 0;
  if (LOW_PRIORITY_DIRS.has(name)) return 2;
  return 1;
}

async function walkDir(rootDir: string, currentDir: string, out: string[], maxFiles = 6000): Promise<void> {
  if (out.length >= maxFiles) return;
  let entries;
  try {
    entries = await fs.readdir(currentDir, { withFileTypes: true });
  } catch {
    return;
  }

  const subdirs: string[] = [];

  // 1. Collect direct files in this directory first (ensures root .mcp.json, settings.json, CLAUDE.md, SKILL.md are never starved)
  for (const entry of entries) {
    if (out.length >= maxFiles) break;
    if (entry.isSymbolicLink()) continue;
    if (IGNORED_DIRS.has(entry.name)) continue;
    const full = path.join(currentDir, entry.name);
    if (entry.isFile()) {
      if (classifyFile(full) !== null) {
        out.push(full);
      }
    } else if (entry.isDirectory()) {
      subdirs.push(entry.name);
    }
  }

  // 2. Recurse into high-priority directories (`skills`, `rules`, `hooks`, `mcp-servers`) before bulky plugin caches
  subdirs.sort((a, b) => dirPriority(a) - dirPriority(b) || a.localeCompare(b));
  for (const dirName of subdirs) {
    if (out.length >= maxFiles) break;
    await walkDir(rootDir, path.join(currentDir, dirName), out, maxFiles);
  }
}

export async function discoverLocalAgentPaths(): Promise<string[]> {
  const home = os.homedir();
  const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
  const candidates = [
    path.join(home, '.claude'),
    path.join(home, '.cursor'),
    path.join(home, '.codex'),
    path.join(home, '.gemini', 'config'),
    path.join(home, '.codeium', 'windsurf'),
    path.join(home, '.continue'),
    path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
    path.join(home, '.config', 'Claude', 'claude_desktop_config.json'),
    path.join(appData, 'Claude', 'claude_desktop_config.json'),
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

    if (category === 'mcp-server-code' && !MCP_SERVER_CODE_MARKERS.test(content)) {
      continue;
    }

    filesScanned += 1;
    const rel = path.relative(baseRoot, fullPath) || path.basename(fullPath);
    const fileFindings = scanFileContent(fullPath, rel, content, category);
    candidates.push(...fileFindings);
  }

  return { filesScanned, candidates };
}
