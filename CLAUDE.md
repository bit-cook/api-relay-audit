# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview
Security audit tool for third-party AI API relay/proxy services. Detects hidden prompt injection, prompt leakage, instruction override, and context truncation.

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
- `scripts/audit.py` — 7-step audit orchestration: Infrastructure → Models → Token Injection → Prompt Extraction → Instruction Conflict → Jailbreak → Context Length. Overall rating uses a **2D risk matrix**: injection delta > 100 tokens AND instruction overridden → HIGH; either alone → MEDIUM; neither → LOW.

### APIClient Return Format
```python
{"text": str, "input_tokens": int, "output_tokens": int, "raw": dict, "time": float}
# or on error:
{"error": str}
```

## CLI Flags for `scripts/audit.py`
`--key`, `--url`, `--model`, `--output`, `--skip-infra`, `--skip-context`, `--timeout`
