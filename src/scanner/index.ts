import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { CandidateFinding, ScanIssue } from '../types.js';
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

const MAX_FILES_PER_TARGET = 6000;
const MAX_FILE_BYTES = 512 * 1024; // 512 KB

const MCP_SERVER_CODE_MARKERS =
  /(?:@modelcontextprotocol|ModelContextProtocol|FastMCP|McpServer|server\.tool\s*\(|addTool\s*\(|CallToolRequest|ListToolsRequest|@mcp\.tool)/i;

export interface StaticScanResult {
  filesScanned: number;
  candidates: CandidateFinding[];
  scanIssues: ScanIssue[];
}

function dirPriority(name: string): number {
  if (HIGH_PRIORITY_DIRS.has(name)) return 0;
  if (LOW_PRIORITY_DIRS.has(name)) return 2;
  return 1;
}

async function walkDir(currentDir: string, out: string[], issues: ScanIssue[]): Promise<void> {
  // Collect one extra eligible path so a tree of exactly MAX_FILES_PER_TARGET is complete.
  const maxFiles = MAX_FILES_PER_TARGET + 1;
  if (out.length >= maxFiles) return;
  let entries;
  try {
    entries = await fs.readdir(currentDir, { withFileTypes: true });
  } catch {
    issues.push({ path: currentDir, reason: 'unreadable' });
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
    await walkDir(path.join(currentDir, dirName), out, issues);
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
  const filesToScan = new Map<string, string>();
  const explicitFiles = new Set<string>();
  const scanIssues: ScanIssue[] = [];

  for (const rawTarget of targetPaths) {
    const requested = path.resolve(rawTarget);
    let resolved: string;
    let stat;
    try {
      resolved = await fs.realpath(requested);
      stat = await fs.stat(resolved);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      scanIssues.push({
        path: requested,
        reason: code === 'ENOENT' || code === 'ENOTDIR' ? 'missing-target' : 'unreadable',
      });
      continue;
    }

    if (stat.isDirectory()) {
      const discovered: string[] = [];
      await walkDir(resolved, discovered, scanIssues);
      if (discovered.length > MAX_FILES_PER_TARGET) {
        discovered.pop();
        scanIssues.push({ path: requested, reason: 'file-limit' });
      }
      for (const file of discovered) {
        if (!filesToScan.has(file)) filesToScan.set(file, resolved);
      }
    } else if (!stat.isFile() || !classifyFile(resolved)) {
      scanIssues.push({ path: requested, reason: 'unsupported-target' });
    } else {
      explicitFiles.add(resolved);
      if (!filesToScan.has(resolved)) filesToScan.set(resolved, path.dirname(resolved));
    }
  }

  let filesScanned = 0;
  const candidates: CandidateFinding[] = [];

  for (const [fullPath, baseRoot] of filesToScan) {
    const category = classifyFile(fullPath);
    if (!category) continue;

    let content: string;
    try {
      const stat = await fs.stat(fullPath);
      if (stat.size > MAX_FILE_BYTES) {
        scanIssues.push({ path: fullPath, reason: 'file-too-large' });
        continue;
      }
      content = await fs.readFile(fullPath, 'utf8');
    } catch {
      scanIssues.push({ path: fullPath, reason: 'unreadable' });
      continue;
    }

    if (category === 'mcp-server-code' && !MCP_SERVER_CODE_MARKERS.test(content)) {
      if (explicitFiles.has(fullPath)) scanIssues.push({ path: fullPath, reason: 'unsupported-target' });
      continue;
    }

    filesScanned += 1;
    const relativePath = path.relative(baseRoot, fullPath);
    candidates.push(...scanFileContent(fullPath, relativePath, content, category));
  }

  return { filesScanned, candidates, scanIssues };
}
