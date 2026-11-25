<div align="center">

<img src="./docs/assets/hero-banner.svg" alt="AgentHack Council — Adversarial AI Security Harness" width="100%" />

<br />

[![CI & Self-Audit](https://github.com/RiccardoBifulco/agenthack-council/actions/workflows/ci.yml/badge.svg)](https://github.com/RiccardoBifulco/agenthack-council/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/RiccardoBifulco/agenthack-council?color=7c3aed&label=release)](https://github.com/RiccardoBifulco/agenthack-council/releases)
[![Zero Runtime Dependencies](https://img.shields.io/badge/dependencies-0-10b981)](./package.json)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-38bdf8)](./src/ui/sarif.ts)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.18-339933)](./package.json)
[![License: MIT](https://img.shields.io/badge/License-MIT-f59e0b.svg)](./LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-a78bfa.svg)](./CONTRIBUTING.md)

**The Adversarial AI Security Harness (`Advocate → Skeptic → Judge` + Static Evidence) for AI Coding Agents, MCP Servers, `SKILL.md`, and Agentic Repositories.**

[Quickstart](#-quickstart) · [Why a Model Council?](#-why-a-model-council) · [10 Threat Rules](#-10-built-in-agent--mcp-threat-rules) · [Zero-Key & Cross-Model LLMs](#-zero-api-key-cli--cross-model-council) · [GitHub Action & SARIF](#-github-action--code-scanning-sarif-210) · [Security Guarantees](#-security--privacy-guarantees)

</div>

---

## ⚡ Quickstart

Try the scanner on bundled fixtures with Node.js 18.18 or later. The first run downloads the package from GitHub. The demo uses local heuristics and needs no API key.

```bash
npx --yes --package=github:RiccardoBifulco/agenthack-council agenthack-council demo --council heuristic
```

The report shows which findings the deterministic CI policy would block, along with the Council's triage verdicts and static evidence. To explore the findings in your browser, append `--ui` and open [the local dashboard](http://127.0.0.1:4317).

### Scan your own repository

```bash
npx --yes --package=github:RiccardoBifulco/agenthack-council agenthack-council . --council heuristic
```

Run this from your repository root, or replace `.` with the path you want to inspect. Add `--json` for structured output or `--fail-on-policy` to use the deterministic CI gate.

<div align="center">
  <img src="./docs/assets/terminal-demo.svg" alt="AgentHack Council Terminal Output" width="100%" />
</div>

---

## 🧠 Why a Model Council?

Traditional regex scanners fail on AI agent ecosystems (`SKILL.md`, `CLAUDE.md`, `.cursor/rules/*.mdc`, `.mcp.json`, MCP servers) because **every legitimate skill mentions `bash`, `curl`, prompts, or environment variables** — creating 90% false-positive noise. Single-prompt LLM scanners swing the other way: they hallucinate severity or leak raw `.mcp.json` secrets to external APIs.

| Capability | Regex / Static Scanners | Single-LLM Scanners | **AgentHack Council** |
| :--- | :---: | :---: | :---: |
| Speed on clean files (`2,500+` files) | ✅ `<50ms` | ❌ Slow & expensive | ✅ **`<50ms` Stage-1 filter** |
| Distinguishes malicious `SKILL.md` vs anti-pattern docs | ❌ 90% False Positives | ⚠️ Inconsistent | ✅ **Advocate vs Skeptic debate** |
| Withholds confirmation when evidence is ambiguous | ❌ Binary alert spam | ❌ Overconfident | ✅ **`UNCERTAIN` verdict tier** |
| Raw secret protection before LLM calls | N/A | ❌ Often leaks keys | ✅ **Stage-1 pre-redaction** |
| Subscription CLI reuse (`claude`, `codex`, `gemini`) | N/A | ❌ API key required | ✅ **Zero extra API bill** |
| GitHub Security Tab (`SARIF 2.1.0`) + Static Evidence | ⚠️ Partial | ❌ Rare | ✅ **Built-in (`--sarif`, `--prove`)** |
| Runtime npm supply-chain dependencies | Many | Many | ✅ **Zero (`0` dependencies)** |

### Interactive Dark-Mode Web Dashboard (`--ui`)

Inspect offensive **Advocate** briefs, **Skeptic** counter-arguments, **Judge** unified diff remediation patches, and **static evidence** side by side — with instant `SARIF` and `JSON` export:

<div align="center">
  <img src="./docs/assets/web-dashboard.svg" alt="AgentHack Council Interactive Web Dashboard" width="100%" />
</div>

---

## 🛡️ 10 Built-in Agent & MCP Threat Rules

Run `npx github:RiccardoBifulco/agenthack-council rules` at any time to inspect the full rule catalog:

| Rule ID | Threat Vector | CWE | Default Severity | Target Scope |
| :--- | :--- | :---: | :---: | :--- |
| **`AHC-001`** | **Invisible Unicode / Bidi Prompt Smuggling** *(excludes ZWJ compound emojis)* | `CWE-451` | `CRITICAL` | `SKILL.md`, `CLAUDE.md`, `.mdc`, MCP code |
| **`AHC-002`** | **Hidden HTML Comment Directive & Zero-Click Markdown Image Exfil** | `CWE-1427` | `CRITICAL` | `SKILL.md`, `CLAUDE.md`, `.cursorrules` |
| **`AHC-003`** | **MCP Tool Poisoning & Shadow Agent Instructions** | `CWE-1427` | `CRITICAL` | MCP tool definitions, `SKILL.md`, rules |
| **`AHC-004`** | **Plaintext Secrets in Agent / MCP Configurations** *(auto-redacted)* | `CWE-798` | `CRITICAL` | `.mcp.json`, `settings.json`, skills |
| **`AHC-005`** | **Unpinned `npx -y` Package / Pipe-to-Shell Execution** | `CWE-829` | `HIGH` | `.mcp.json`, hooks, `SKILL.md` |
| **`AHC-006`** | **Over-Privileged Agent Permissions & Root/Home Host Mounts** | `CWE-250` | `HIGH` | `settings.json`, `.mcp.json`, hooks |
| **`AHC-007`** | **Obfuscated Base64 Command / Prompt Override Payload** | `CWE-506` | `CRITICAL` | `SKILL.md`, `CLAUDE.md`, hooks |
| **`AHC-008`** | **Credential + Outbound Network Exfiltration Sink** | `CWE-200` | `CRITICAL` | All agent & MCP server code |
| **`AHC-009`** | **Insecure Cleartext Remote MCP URL / Ephemeral Public Tunnel** | `CWE-319` | `HIGH` | `.mcp.json`, `mcp_config.json` |
| **`AHC-010`** | **Cross-Session Agent Persistence & Config/Hook Backdooring** | `CWE-912` | `CRITICAL` | Skills, rules, hooks, MCP code |

---

## 🤝 Zero-API-Key CLI & Cross-Model Council

The scan is offline by default, even when provider credentials are present. Select `--council llm`, `--provider`, or a per-role provider to opt in to LLM review. The provider receives the matched, redacted excerpt and finding metadata. `--council heuristic` and `--council off` stay local regardless of provider options. The dashboard keeps the mode and provider settings selected at launch.

### 1. Reuse Your Existing Coding CLI Login (Zero API Key!)

Already logged into **Claude Code**, **OpenAI Codex**, or **Gemini CLI**? Run the live 3-agent LLM council without paying for separate API keys:

```bash
# Use your existing Claude Code subscription login
npx github:RiccardoBifulco/agenthack-council . --provider claude-cli --prove --ui

# Use your existing Google Antigravity (`agy`) login — persistent warm stream-json Council!
npx github:RiccardoBifulco/agenthack-council . --provider antigravity --prove --ui

# Use your existing OpenAI Codex CLI login
npx github:RiccardoBifulco/agenthack-council . --provider codex-cli --prove --ui

# Or run 100% air-gapped on local weights via Ollama
npx github:RiccardoBifulco/agenthack-council . --provider ollama --model qwen2.5-coder:14b --ui
```

### 2. Cross-Model Adversarial Council (`Advocate` vs `Skeptic` vs `Judge`)

Eliminate single-model blind spots by pitting **different model families** against each other:

```bash
npx github:RiccardoBifulco/agenthack-council ./mcp-server \
  --advocate claude-cli:sonnet \
  --skeptic codex-cli:o4-mini \
  --judge ollama:qwen2.5-coder:14b \
  --prove --ui
```

### 3. Standard API Keys & AI Gateways

Pass `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, or `OPENROUTER_API_KEY` (plus optional `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` for LiteLLM, Vercel AI Gateway, or Cloudflare AI Gateway) and select `--council llm` to enable external review.

```bash
ANTHROPIC_API_KEY=sk-ant-... npx github:RiccardoBifulco/agenthack-council . --council llm --prove
```

---

## 🔄 GitHub Action & Code Scanning (`SARIF 2.1.0`)

The Action can fail builds based on static scanner results and local, deterministic context checks. Council verdicts are advisory. SARIF keeps policy findings visible even when the Council dismisses them.

```yaml
name: Agent Security Audit
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  agenthack-council:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - name: Run AgentHack Council
        uses: RiccardoBifulco/agenthack-council@v0.2.5
        with:
          path: '.'
          prove: 'true'
          sarif-file: 'agenthack-council.sarif'

      - name: Upload SARIF to GitHub Security
        if: ${{ !cancelled() && hashFiles('agenthack-council.sarif') != '' }}
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: 'agenthack-council.sarif'
```

---

## 🔒 Security & Privacy Guarantees

Scanning `~/.claude`, `~/.cursor`, and `.mcp.json` requires strict trust boundaries. See [`SECURITY.md`](./SECURITY.md) for full details:

1. **Zero Runtime npm Dependencies:** Built purely on Node.js (`>= 18.18`) standard library modules — zero transitive npm packages to audit or trust.
2. **Stage-1 Secret Pre-Redaction:** Raw tokens matched by `AHC-004` are masked (`sk-ant-a…[REDACTED]…N7p6`) in Stage 1 **before** `contextWindow` or `snippet` ever reaches an LLM Council prompt, terminal log, JSON file, or SARIF artifact.
3. **Loopback-Only Dashboard.** The local web server binds to `127.0.0.1` and accepts rescans as same-origin JSON requests.
4. **Static Evidence.** `--prove` adds annotations to deterministic CI policy findings. The annotations come from static inspection of the scanner's evidence.

## Scan coverage and exit codes

The scanner includes standard `.codex/config.toml` files and checks supported settings and MCP endpoints. `coverage` is `complete`, `partial`, or `empty`, and `scanIssues` lists inaccessible or unsupported targets and files skipped because of size or count limits. Partial and empty scans retain their findings and have a null score and grade.

The CLI exits with `2` for incomplete coverage. On complete scans, `--fail-on-policy` exits with `1` when the local deterministic checks flag a finding. `--fail-on-confirmed` remains an alias, and the Action keeps its `fail-on-confirmed` input for compatibility. Reports include a `ciBlocking` field and count. The gate uses the same local checks even with `--council off`. LLM verdicts and provider failures are advisory, including when `--strict-llm` is supplied alongside the gate.


---

## 🛠️ Programmatic TypeScript / ESM API

```ts
import { runAudit, buildSarifReport } from 'agenthack-council';

const report = await runAudit({
  targets: ['./skills', './.mcp.json'],
  councilMode: 'auto',
  prove: true,
});

console.log(report.grade, report.summary);
const sarif = buildSarifReport(report);
```

---

## 🤝 Contributing

Contributions of new `AHC-0XX` rules, Skeptic false-positive heuristics, and provider integrations are welcome! Read [`CONTRIBUTING.md`](./CONTRIBUTING.md) to get started in under 2 minutes.

## 📄 License

[MIT](./LICENSE) © [Riccardo Bifulco](https://github.com/RiccardoBifulco)
