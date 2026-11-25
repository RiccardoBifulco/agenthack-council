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

Because `agenthack-council` inspects developer machines (`~/.claude`, `~/.cursor`, `~/.codex`) and sensitive repositories, it uses the following controls.

1. **Zero Runtime npm Dependencies:** Only Node.js built-in modules (`node:fs`, `node:http`, `node:crypto`, `node:child_process`) ship at runtime, eliminating transitive npm supply-chain risk.
2. **Stage-1 Secret Pre-Redaction:** Plaintext API keys and credentials matched in Stage 1 (`AHC-004`) are masked (`sk-ant-a…[REDACTED]…N7p6`) in `snippet`, `contextWindow`, and `evidence` **before** Stage 2 ever constructs an LLM Council prompt or writes a JSON/SARIF report.
3. **Offline by Default.** A configured API key alone never enables LLM review. An explicit LLM or provider selection allows the selected provider to receive matched excerpts and metadata. Secret masking applies to recognized credential patterns.
4. **Loopback-Only Dashboard.** The dashboard binds to `127.0.0.1` and checks the host and origin for rescans.
5. **Static Evidence.** `--prove` inspects source evidence without executing target code or contacting a canary sink.
