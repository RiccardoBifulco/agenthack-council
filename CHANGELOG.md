# Changelog

All notable changes to **AgentHack Council** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
