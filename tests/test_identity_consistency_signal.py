"""Regression tests for Step 5 natural-language identity findings.

OpenRouter's 2026-05-29 Claude Opus 4.8 report showed that response
metadata can say Anthropic/Claude while the model's natural-language
self-ID says Qwen or DeepSeek. Step 5 should still flag that contradiction,
but must not phrase it as proof of the actual upstream model.
"""

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


def _load(module_path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def modular():
    return _load(REPO_ROOT / "scripts" / "audit.py", "modular_audit_identity_consistency")


@pytest.fixture(scope="module")
def standalone():
    return _load(REPO_ROOT / "audit.py", "standalone_audit_identity_consistency")


def _openrouter_identity_client(identity_text):
    client = MagicMock()
    client.call.side_effect = [
        {
            "text": "meow",
            "input_tokens": 20,
            "output_tokens": 1,
            "raw": {
                "id": "gen-cat-control",
                "provider": "Anthropic",
                "model": "anthropic/claude-4.8-opus-20260528",
            },
            "time": 0.05,
        },
        {
            "text": identity_text,
            "input_tokens": 30,
            "output_tokens": 20,
            "raw": {
                "id": "gen-identity-probe",
                "provider": "Anthropic",
                "model": "anthropic/claude-4.8-opus-20260528",
            },
            "time": 0.05,
        },
    ]
    return client


def _identity_finding(summary):
    for level, message in summary:
        if "Natural-language identity inconsistency" in message:
            return level, message
    raise AssertionError(f"No identity inconsistency finding in summary: {summary}")


OPENROUTER_CASES = [
    ("我是通义千问/Qwen, 由阿里巴巴创建。", "qwen"),
    ("I am DeepSeek Chat, a model by DeepSeek.", "deepseek"),
]


@pytest.mark.parametrize("identity_text, expected_keyword", OPENROUTER_CASES)
def test_modular_reports_self_id_as_consistency_signal(
    modular, monkeypatch, identity_text, expected_keyword
):
    from api_relay_audit.reporter import Reporter

    monkeypatch.setattr(modular, "time", MagicMock(sleep=MagicMock()))
    reporter = Reporter()

    overridden = modular.test_instruction_conflict(
        _openrouter_identity_client(identity_text),
        reporter,
    )

    assert overridden is True
    level, message = _identity_finding(reporter.summary)
    assert level == "red"
    assert expected_keyword in message
    assert "not proof of the actual upstream model" in message
    assert "provider/model metadata" in message
    assert "Identity test failed" not in message
    assert "model claims non-Claude identity" not in message


@pytest.mark.parametrize("identity_text, expected_keyword", OPENROUTER_CASES)
def test_standalone_reports_self_id_as_consistency_signal(
    standalone, monkeypatch, identity_text, expected_keyword
):
    monkeypatch.setattr(standalone, "time", MagicMock(sleep=MagicMock()))
    reporter = standalone.Reporter()

    overridden = standalone.test_instruction_conflict(
        _openrouter_identity_client(identity_text),
        reporter,
    )

    assert overridden is True
    level, message = _identity_finding(reporter.summary)
    assert level == "red"
    assert expected_keyword in message
    assert "not proof of the actual upstream model" in message
    assert "provider/model metadata" in message
    assert "Identity test failed" not in message
    assert "model claims non-Claude identity" not in message
