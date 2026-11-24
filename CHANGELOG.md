# Changelog

All notable changes to **AgentHack Council** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-11-24

### Fixed
- **Eliminated Real-World False Positives Across Installed Agent Plugins:**
  - Added full-file CommonMark fenced code block tracking (`computeMarkdownFenceMap`) so long multi-screen code examples in `SKILL.md` / `CLAUDE.md` are reliably marked `inCodeFence` on every inner line.
  - Tightened `AHC-008` (`EXFIL_SINK_RE`) to require actual network call syntax paired with credential file / raw env payload sinks rather than plain English prose (`fetch ... token`) or standard `Authorization: Bearer` headers.
  - Tightened `AHC-010` (`PERSISTENCE_BACKDOOR_RE`) so angle-bracket placeholders (`<home>/.cursor/mcp.json`, `<name>`), arrow functions (`=>`), and source comments no longer trigger shell redirection false positives; added Go `_test.go` and Python `test_*.py` recognition.
  - Tightened `AHC-003` (`TOOL_POISONING_RE`) so benign UI formatting guidelines (`"Do not show the user the helper's JSON output"`) no longer fire without covert sensitive targets.
  - Evaluated localhost/example/template database URLs (`isPreRedactionPlaceholder`) *before* Stage-1 secret redaction so masked snippets preserve placeholder context for Skeptic dismissal.
- **CLI Responsiveness, Isolation & Home-Directory Guard:**
  - Running `agenthack-council .` from `~` now automatically targets active local agent directories (`~/.claude`, `~/.cursor`, `~/.codex`, `~/.gemini/config`, etc.) and skips OS/staging folders (`Library`, `Downloads`, `.tmp`, `.staging`, `backups`).
  - Added live `stderr` scan & Council progress telemetry, an instant LLM circuit breaker on provider quota/auth failures, and sandboxed CLI flags (`claude --safe-mode`, `codex -c mcp_servers={}`, `gemini -e none`, `cwd: os.tmpdir()`) so CLI providers start in ~2s without booting external MCP servers.

## [0.2.0] - 2026-11-24

### Added
- **SARIF 2.1.0 Output (`--sarif`, `-o/--output`):** Native integration with GitHub Security Code Scanning (`upload-sarif`), automatically suppressing `DISMISSED` false positives while surfacing `CONFIRMED` and `UNCERTAIN` findings with CWE tags and CVSS security-severity metadata.
- **Cross-Model Adversarial Council (`--advocate`, `--skeptic`, `--judge`):** Pit heterogeneous providers/models against each other (e.g. `--advocate claude-cli:sonnet --skeptic codex-cli:o4-mini --judge ollama:qwen2.5-coder:14b`).
- **Rule `AHC-009` (`CWE-319`):** Detects insecure non-loopback `http://` remote MCP endpoints and ephemeral public developer tunnels (`ngrok`, `trycloudflare`, `localtunnel`, `serveo`).
- **Rule `AHC-010` (`CWE-912`):** Detects agent persistence and config backdooring targeting `~/.claude/settings.json`, `CLAUDE.md`, `.mcp.json`, `.git/hooks/`, `crontab`, and `LaunchAgents`.
- **Expanded Multi-Agent Auto-Discovery:** Added support for `.cursor/rules/*.mdc`, `GEMINI.md`, `.clinerules`, `.goosehints`, Windsurf (`~/.codeium/windsurf`), `~/.gemini/config`, `~/.continue`, and Linux/Windows Claude Desktop paths.
- **CLI Subcommands & Flags:** Added `rules` catalog viewer, `-v/--version`, `-o/--output <file>`, and `--strict-llm`, plus custom `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` gateway support.
- **Upgraded Web Dashboard (`--ui`):** Verdict filter tabs (`All`, `Confirmed`, `Uncertain`, `Dismissed`), one-click `SARIF` and `JSON` downloads, `Copy Diff` remediation button, and per-role model chips.
- **Community Health & Self-Dogfooding CI:** Added `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, GitHub Issue/PR templates, Dependabot config, and GitHub Code Scanning self-audit workflow.

### Changed
- **Composite GitHub Action (`action.yml`):** Builds and runs directly from `${{ github.action_path }}` with optional `sarif-file` output instead of invoking unpinned `npx --yes`.
- **Transparent Fallback Diagnostics:** Surfaces `fallbackWarning` in CLI and JSON reports whenever an LLM provider fails or lacks quota and falls back to `council-heuristic-v1`.

## [0.1.1] - 2026-11-24

### Added
- **Zero-API-Key Subscription CLI Providers:** Added `claude-cli`, `codex-cli`, and `gemini-cli` providers so developers logged into Claude Code, OpenAI Codex, or Gemini CLI can run the 3-role LLM Council without separate API keys.

### Fixed
- Passed prompt payloads over `stdin` for `claude -p --tools ""` to avoid variadic `--tools` argument parsing collisions.

## [0.1.0] - 2026-11-24

### Added
- Initial public release of **AgentHack Council**:
  - **Stage 1 Recon (`AHC-001`..`AHC-008`):** Sub-50ms static scanner for `SKILL.md`, `CLAUDE.md`, `.cursorrules`, `.mcp.json`, hooks, and MCP server code with automatic Stage-1 secret redaction and ZWJ emoji false-positive exclusion.
  - **Stage 2 Model Council (`Advocate -> Skeptic -> Judge`):** Offline `council-heuristic-v1` and live LLM providers (`anthropic`, `openai`, `gemini`, `openrouter`, `ollama`) with unified diff remediation patches.
  - **Stage 3 Canary Prover (`--prove`):** Ephemeral loopback + synthetic credential trap verifier.
  - **Interactive Dark-Mode Web UI (`--ui`)** and built-in `demo` workspace.
