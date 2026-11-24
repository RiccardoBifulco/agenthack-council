# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2.0 | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability, scanner bypass, remote code execution vector, or secret-redaction leak in **AgentHack Council**, please **do not open a public GitHub issue**.

Instead, report it privately via **GitHub Private Vulnerability Reporting**:

1. Navigate to the [**Security Advisories**](https://github.com/RiccardoBifulco/agenthack-council/security/advisories/new) page of this repository.
2. Submit a private advisory including reproduction steps, affected file category (`SKILL.md`, `.mcp.json`, MCP server code, etc.), and impact.
3. You will receive an initial acknowledgment within **48 hours** and a remediation timeline once triaged.

## Built-in Security & Privacy Guarantees

Because `agenthack-council` inspects developer machines (`~/.claude`, `~/.cursor`, `~/.codex`) and sensitive repositories, it enforces four strict architectural invariants:

1. **Zero Runtime npm Dependencies:** Only Node.js built-in modules (`node:fs`, `node:http`, `node:crypto`, `node:child_process`) ship at runtime, eliminating transitive npm supply-chain risk.
2. **Stage-1 Secret Pre-Redaction:** Plaintext API keys and credentials matched in Stage 1 (`AHC-004`) are masked (`sk-ant-a…[REDACTED]…N7p6`) in `snippet`, `contextWindow`, and `evidence` **before** Stage 2 ever constructs an LLM Council prompt or writes a JSON/SARIF report.
3. **Loopback-Only Web Dashboard (`127.0.0.1`):** Both the `--ui` dashboard server and the ephemeral Canary Sandbox HTTP listener bind exclusively to `127.0.0.1`, never `0.0.0.0`.
4. **Non-Executing Canary Prover:** `--prove` validates exfiltration and credential-targeting chains against synthetic canary tokens in an isolated temporary directory without executing untrusted repository scripts or shell hooks.
