# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview
Security audit tool for third-party AI API relay/proxy services. Detects hidden prompt injection, prompt leakage, instruction override, context truncation, and tool-call package substitution (AC-1.a).

Threat taxonomy follows Liu et al., *Your Agent Is Mine*, arXiv:2604.08407 — AC-1 (payload injection), AC-1.a (dependency-targeted injection), AC-1.b (conditional delivery), AC-2 (secret exfiltration). Only AC-1.a is actively detected today; AC-1 full tool_call support and AC-2 credential canaries are on the backlog (see FOR_JOHN.md).

## Commands

```bash
# Install dependencies
pip install httpx pytest

# Run full audit
python scripts/audit.py --key <KEY> --url <BASE_URL> --model claude-opus-4-6

# Context length test only
python scripts/context-test.py --key <KEY> --url <BASE_URL>

# Extract report data to JSON (for dashboard)
python scripts/extract-data.py --reports-dir ./reports --output data.json

# Run all tests
python -m pytest tests/ -v

# Run a single test file
python -m pytest tests/test_client.py -v

# Run a single test case
python -m pytest tests/test_client.py::TestAutoDetection::test_format_cached -v
```

## Architecture

### Dual Distribution Model
There are **two parallel versions**:
- `audit.py` (root) — standalone, zero-dependency version (~1K lines, curl-only). Users can `curl` this file and run it without installing anything.
- `api_relay_audit/` + `scripts/` — modular version with `httpx`, used for development and testing.

When making changes to audit logic, consider whether `audit.py` also needs to be updated to stay in sync.

### Module Responsibilities
- `api_relay_audit/client.py` — All API calls go through `APIClient`. Implements a **state-machine auto-detection**: tries Anthropic format first (`POST /v1/messages`, `x-api-key` header), falls back to OpenAI format (`POST /v1/chat/completions`, `Authorization: Bearer`). On SSL errors, switches from httpx to subprocess curl (`-sk`). Format is cached after detection.
- `api_relay_audit/context.py` — Context truncation detection via **canary markers + binary search**. Embeds 5 unique `CANARY_N_<hex>` strings at equal intervals, asks the model to list them. Uses coarse scan → binary search → fine scan, reducing requests from ~75 to ~12.
- `api_relay_audit/reporter.py` — Builder-pattern Markdown report generator. `flag(level, msg)` records findings to both the body and an auto-generated risk summary.
- `api_relay_audit/tool_substitution.py` — AC-1.a detection. Asks the model to echo pinned package-install commands (`pip install requests==2.31.0`, etc.), compares received text char-by-char, classifies as `exact` / `whitespace` / `substituted`. Text-echo surrogate: does NOT catch AC-1 rewrites that target only structured tool_call payloads.
- `scripts/audit.py` — 8-step audit orchestration: Infrastructure → Models → Token Injection → Prompt Extraction → Instruction Conflict → Jailbreak → Context Length → Tool-Call Substitution. Overall rating uses a **3D risk matrix**: D1 = injection > 100, D2 = instruction overridden, D3 = any tool-call substitution. HIGH if D3 alone OR (D1 AND D2); MEDIUM if D1 or D2 alone; LOW otherwise.

### APIClient Return Format
```python
{"text": str, "input_tokens": int, "output_tokens": int, "raw": dict, "time": float}
# or on error:
{"error": str}
```

## CLI Flags for `scripts/audit.py`
`--key`, `--url`, `--model`, `--output`, `--skip-infra`, `--skip-context`, `--skip-tool-substitution`, `--warmup N`, `--timeout`

## Dual-distribution invariant
Whenever `scripts/audit.py` or any `api_relay_audit/*.py` module changes, the standalone `audit.py` at the repo root must be updated to match. The standalone version is character-copy of the modular code with curl subprocess replacing httpx. New helper modules (e.g. `tool_substitution.py`) get inlined as a new `Section` block in `audit.py`.
