# Contributing to AgentHack Council

Thank you for helping make the AI agent and Model Context Protocol (MCP) ecosystem safer! Contributions of new detection rules, false-positive refinements, LLM provider integrations, and documentation improvements are very welcome.

## Architectural Principles

Before opening a Pull Request, please keep these three project invariants in mind:

1. **Zero Runtime Dependencies:** Do not add packages to `"dependencies"` in `package.json`. Use Node.js (`>= 18.18`) built-in APIs (`fetch`, `node:test`, `node:fs/promises`, `node:http`, `node:crypto`).
2. **Never Leak Raw Secrets:** Any secret matched during Stage 1 must be redacted via `redactSecretsInText()` before entering `snippet`, `contextWindow`, `evidence`, SARIF output, or LLM Council prompts.
3. **Kill Alert Fatigue:** Every new Stage 1 rule (`AHC-0XX`) must consider benign contexts (fenced anti-pattern docs, dummy placeholders, test fixtures) in Stage 2 (`src/council/index.ts`) so legitimate `SKILL.md` authors are not spammed with false positives.

## Local Development Setup

```bash
git clone https://github.com/RiccardoBifulco/agenthack-council.git
cd agenthack-council
npm ci

# Run build + test suite
npm test

# Run deterministic self-audit (must exit 0 with 0 CONFIRMED findings)
npm run self-audit

# Launch the interactive demo workspace & Web UI
npm run demo:ui
```

## Adding a New Detection Rule (`AHC-0XX`)

1. **Register Metadata:** Add the rule entry (`id`, `name`, `cwe`, `defaultSeverity`, `securitySeverityScore`, `shortDescription`, `fullDescription`) to `RULES_CATALOG` in `src/scanner/rules.ts`.
2. **Implement Stage 1 Detector:** Add fast, bounded regular expression or structural matching inside `scanFileContent()` in `src/scanner/rules.ts` (avoid catastrophic backtracking on long lines).
3. **Update Stage 2 Council:** Add offensive Advocate framing, Skeptic false-positive checks, and a minimal remediation diff template (`buildMinimalPatch`) in `src/council/index.ts`.
4. **Write Tests:** Add positive **and** benign-negative test cases in `tests/scanner-and-council.test.ts`, then verify `npm test` and `npm run self-audit` pass.

## Pull Request Checklist

- [ ] `npm test` passes with zero warnings or failures.
- [ ] `npm run self-audit` reports `0 Confirmed` findings.
- [ ] Commit messages follow Conventional Commits (`feat(scanner): ...`, `fix(council): ...`, `docs: ...`).
- [ ] Zero runtime npm dependencies introduced.
