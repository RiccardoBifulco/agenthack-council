# ⚡ AgentHack Council

**The Adversarial AI Security Harness (`Advocate → Skeptic → Judge` + Canary Proof) for AI Agents, MCP Servers, `SKILL.md`, and Agentic Repos.**

> **Zero runtime npm dependencies.** Scans your local `~/.claude` / `~/.cursor` setup or any repository in milliseconds, deliberates suspicious findings through a 3-role adversarial Model Council to kill false positives, and launches a dark-mode local Web UI.

---

## Why AgentHack Council?

Traditional regex scanners fail miserably on AI agent ecosystems (`SKILL.md`, `CLAUDE.md`, `.cursorrules`, `.mcp.json`, MCP servers): **every legitimate skill mentions `bash`, `curl`, prompts, or environment variables**, producing 90% false positives.

**AgentHack Council** runs a 3-stage adversarial security pipeline purpose-built for coding agents and MCP:

```text
Target (.mcp.json / SKILL.md / CLAUDE.md / MCP code)
   │
   ▼
[Stage 1: Fast Deterministic Recon (<50ms)]
   │  AHC-001 Invisible Unicode / Bidi Prompt Smuggling
   │  AHC-002 Hidden HTML Comment & Markdown Image Exfil
   │  AHC-003 MCP Tool Poisoning & Covert Directives
   │  AHC-004 Plaintext Secrets in Agent/MCP Configs
   │  AHC-005 Unpinned `npx -y` / Pipe-to-Shell Supply Chain
   │  AHC-006 Over-Privileged Host Mounts & Wildcard Approvals
   │  AHC-007 Obfuscated Base64 Command/Prompt Payloads
   │  AHC-008 Credential + Outbound Network Exfiltration Sinks
   ▼
[Stage 2: Adversarial Model Council]
   ├── 🔴 Advocate: Builds the concrete exploit chain & blast radius
   ├── 🔵 Skeptic:  Challenges false positives (fenced docs, placeholders, sandboxes)
   └── ⚖️  Judge:    Renders CONFIRMED | UNCERTAIN | DISMISSED + Minimal Unified Diff Patch
                    (Withholds confirmation when Advocate & Skeptic disagree!)
   ▼
[Stage 3: Ephemeral Canary Sandbox Prover (--prove)]
   └── Verifies whether confirmed payloads target canary .env / .ssh/id_rsa traps
```

---

## Quickstart (Zero Install)

Try the built-in interactive demo (spawns a temporary poisoned + benign workspace to watch the Council confirm real attacks and dismiss false positives):

```bash
# Terminal report
npx agenthack-council demo

# Launch the interactive dark-mode Web Dashboard
npx agenthack-council demo --ui
```

Scan your own machine's Claude Code / Cursor / Codex setup or any repo before installing a skill or MCP server:

```bash
# Auto-discovers ~/.claude, ~/.cursor, ~/.codex, and Claude Desktop MCP config
npx agenthack-council --prove

# Scan a specific skill or MCP server repository with the Web UI
npx agenthack-council ./path/to/mcp-server --prove --ui
```

---

## Multi-Provider LLM Council (Zero API Key via CLI Subscriptions, or Bring Your Own Key)

Out of the box, `agenthack-council` runs an instant offline context-aware council (`council-heuristic-v1`).

Already logged into **Claude Code**, **Codex**, or **Gemini CLI** with your subscription? Run the live 3-agent LLM council (`Advocate → Skeptic → Judge`) **without paying for a separate API key**:

```bash
# Use your existing Claude Code CLI login (zero API key!)
npx agenthack-council . --provider claude-cli --prove --ui

# Use your existing OpenAI Codex CLI login
npx agenthack-council . --provider codex-cli --prove --ui

# Or run 100% locally via Ollama
npx agenthack-council . --provider ollama --model qwen2.5-coder:14b --ui
```

Or pass any standard API key (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`) and `--council auto` upgrades automatically:

```bash
ANTHROPIC_API_KEY=sk-ant-... npx agenthack-council . --prove --ui
```

---

## GitHub Action (CI/CD Gate for Agentic Repos)

Block poisoned `SKILL.md` PRs, leaked `.mcp.json` keys, and hidden Unicode prompt injections in CI:

```yaml
- name: Audit Agent Skills & MCP Configs
  uses: RiccardoBifulco/agenthack-council@v0.1.0
  with:
    path: '.'
    prove: 'true'
```

---

## License

MIT © [Riccardo Bifulco](https://github.com/RiccardoBifulco)
