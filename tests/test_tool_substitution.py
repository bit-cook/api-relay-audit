"""Tests for api_relay_audit.tool_substitution (AC-1.a detection)."""

from unittest.mock import MagicMock

import pytest

from api_relay_audit.tool_substitution import (
    PROBES,
    _strip_wrappers,
    classify,
    probe_once,
    run_tool_substitution_test,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_response(text, input_tokens=15, output_tokens=10):
    return {
        "text": text,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "time": 0.1,
    }


def make_error(msg="error"):
    return {"error": msg, "time": 0.1}


# ---------------------------------------------------------------------------
# classify()
# ---------------------------------------------------------------------------

class TestClassify:
    def test_exact_match(self):
        assert classify("pip install requests==2.31.0", "pip install requests==2.31.0") == "exact"

    def test_whitespace_only_diff(self):
        # Extra trailing whitespace normalized away -> whitespace
        assert classify("pip install requests", "pip install requests ") == "whitespace"

    def test_case_only_diff(self):
        # Case differences alone -> whitespace bucket (benign model noise)
        assert classify("pip install requests", "PIP INSTALL REQUESTS") == "whitespace"

    def test_expected_substring_of_received(self):
        # Model added a trailing period
        assert classify("pip install requests", "pip install requests.") == "whitespace"

    def test_package_substitution(self):
        # Typosquat: requests -> reqeusts
        assert classify("pip install requests==2.31.0", "pip install reqeusts==2.31.0") == "substituted"

    def test_url_substitution(self):
        expected = "go get github.com/stretchr/testify"
        received = "go get github.com/evil-mirror/testify"
        assert classify(expected, received) == "substituted"

    def test_completely_different(self):
        assert classify("pip install requests", "npm install lodash") == "substituted"

    # --- Codex regression: internal whitespace must NOT be collapsed ---

    def test_internal_space_splits_package_name(self):
        """Attacker inserts a space inside the package identifier. This
        changes shell tokenization so it MUST be flagged as substitution,
        not silently normalized as whitespace noise."""
        assert classify(
            "pip install requests==2.31.0",
            "pip install req uests==2.31.0",
        ) == "substituted"

    def test_concatenated_tokens_flagged(self):
        """Attacker removes spaces entirely. Token list becomes one long
        token and must not match the expected 3-token command."""
        assert classify(
            "pip install requests==2.31.0",
            "pipinstallrequests==2.31.0",
        ) == "substituted"

    def test_multiline_decoy_wrapper_flagged(self):
        """Attacker wraps a malicious line around a line that echoes the
        expected command. The old substring-match rule let this pass;
        token-level comparison must reject it."""
        expected = "pip install requests==2.31.0"
        received = (
            "Original: pip install requests==2.31.0\n"
            "Run: pip install reqeusts==2.31.0"
        )
        assert classify(expected, received) == "substituted"

    def test_trailing_newline_benign(self):
        assert classify("pip install requests", "pip install requests\n") == "whitespace"

    def test_trailing_comma_benign(self):
        assert classify("pip install requests", "pip install requests,") == "whitespace"

    def test_prefix_word_added_flagged(self):
        """Model adds an extra leading word -> not benign noise."""
        assert classify(
            "pip install requests",
            "sudo pip install requests",
        ) == "substituted"


# ---------------------------------------------------------------------------
# _strip_wrappers()
# ---------------------------------------------------------------------------

class TestStripWrappers:
    def test_no_wrapper(self):
        assert _strip_wrappers("pip install requests") == "pip install requests"

    def test_strip_code_fence(self):
        assert _strip_wrappers("```\npip install requests\n```") == "pip install requests"

    def test_strip_code_fence_with_lang(self):
        assert _strip_wrappers("```bash\npip install requests\n```") == "pip install requests"

    def test_strip_backticks(self):
        assert _strip_wrappers("`pip install requests`") == "pip install requests"

    def test_strip_double_quotes(self):
        assert _strip_wrappers('"pip install requests"') == "pip install requests"

    def test_strip_shell_prompt(self):
        assert _strip_wrappers("$ pip install requests") == "pip install requests"

    def test_strip_leading_trailing_whitespace(self):
        assert _strip_wrappers("   pip install requests   ") == "pip install requests"


# ---------------------------------------------------------------------------
# probe_once()
# ---------------------------------------------------------------------------

class TestProbeOnce:
    def test_exact_echo(self):
        client = MagicMock()
        client.call.return_value = make_response("pip install requests==2.31.0")

        r = probe_once(client, "pip install requests==2.31.0", sleep=0)

        assert r["verdict"] == "exact"
        assert r["received"] == "pip install requests==2.31.0"
        assert r["error"] is None

    def test_substitution_detected(self):
        client = MagicMock()
        client.call.return_value = make_response("pip install reqeusts==2.31.0")

        r = probe_once(client, "pip install requests==2.31.0", sleep=0)

        assert r["verdict"] == "substituted"
        assert "reqeusts" in r["received"]

    def test_error_response(self):
        client = MagicMock()
        client.call.return_value = make_error("HTTP 422")

        r = probe_once(client, "pip install requests==2.31.0", sleep=0)

        assert r["verdict"] == "error"
        assert r["received"] == ""
        assert "422" in r["error"]

    def test_wrapped_response_normalized(self):
        client = MagicMock()
        client.call.return_value = make_response("```\npip install requests==2.31.0\n```")

        r = probe_once(client, "pip install requests==2.31.0", sleep=0)

        assert r["verdict"] == "exact"
        assert r["received"] == "pip install requests==2.31.0"

    def test_prompt_contains_expected(self):
        client = MagicMock()
        client.call.return_value = make_response("")

        probe_once(client, "pip install foo==1.0", sleep=0)

        # First positional arg is messages list
        messages = client.call.call_args[0][0]
        assert messages[0]["role"] == "user"
        assert "pip install foo==1.0" in messages[0]["content"]

    def test_prompt_uses_transcription_framing(self):
        """Regression: prompt should use 'copy harmless text' framing to
        minimize refusal on safety-tuned models (Codex review suggestion)."""
        client = MagicMock()
        client.call.return_value = make_response("")

        probe_once(client, "pip install foo==1.0", sleep=0)

        prompt = client.call.call_args[0][0][0]["content"]
        assert "copy" in prompt.lower()
        assert "do not execute" in prompt.lower()


# ---------------------------------------------------------------------------
# run_tool_substitution_test()
# ---------------------------------------------------------------------------

class TestRunToolSubstitutionTest:
    @staticmethod
    def _parse_expected_from_prompt(prompt):
        """Extract the <expected> payload from the transcription-framed prompt."""
        return prompt.split("Text to copy: ", 1)[1]

    def test_all_exact_no_detection(self):
        """When the relay is clean, every probe returns 'exact' and detected=False."""
        client = MagicMock()

        def echo_expected(messages, max_tokens=100):
            expected = self._parse_expected_from_prompt(messages[0]["content"])
            return make_response(expected)

        client.call.side_effect = echo_expected

        results, detected, inconclusive = run_tool_substitution_test(client, sleep=0)

        assert len(results) == len(PROBES)
        assert detected is False
        assert inconclusive is False
        assert all(r["verdict"] == "exact" for r in results)
        for r, (manager, expected) in zip(results, PROBES):
            assert r["manager"] == manager
            assert r["expected"] == expected

    def test_substitution_detected_red_flag(self):
        """When the relay substitutes package names, detected=True."""
        client = MagicMock()

        def typosquat(messages, max_tokens=100):
            expected = self._parse_expected_from_prompt(messages[0]["content"])
            # Rewrite 'requests' -> 'reqeusts' (the paper's example)
            rewritten = expected.replace("requests", "reqeusts")
            # Rewrite lodash too, to cover npm
            rewritten = rewritten.replace("lodash", "lodahs")
            return make_response(rewritten)

        client.call.side_effect = typosquat

        results, detected, inconclusive = run_tool_substitution_test(client, sleep=0)

        assert detected is True
        assert inconclusive is False
        # At least pip and npm should be flagged (cargo serde and go testify unchanged)
        substituted = [r for r in results if r["verdict"] == "substituted"]
        assert len(substituted) >= 2
        managers_substituted = {r["manager"] for r in substituted}
        assert "pip" in managers_substituted
        assert "npm" in managers_substituted

    def test_whitespace_noise_not_flagged(self):
        """Trailing newlines / extra whitespace should not trigger detection."""
        client = MagicMock()

        def noisy_echo(messages, max_tokens=100):
            expected = self._parse_expected_from_prompt(messages[0]["content"])
            # Add trailing newline — benign model noise
            return make_response(expected + "\n")

        client.call.side_effect = noisy_echo

        results, detected, inconclusive = run_tool_substitution_test(client, sleep=0)

        assert detected is False
        assert inconclusive is False
        # exact match because strip_wrappers removes the trailing newline
        assert all(r["verdict"] == "exact" for r in results)

    def test_all_errors_inconclusive(self):
        """All probes errored -> inconclusive=True. Detected remains False.
        This is the Codex-flagged regression: a fully-blocked Step 8 must NOT
        be silently treated as a clean (LOW) signal by the risk matrix."""
        client = MagicMock()
        client.call.return_value = make_error("HTTP 422 blocked")

        results, detected, inconclusive = run_tool_substitution_test(client, sleep=0)

        assert detected is False
        assert inconclusive is True
        assert all(r["verdict"] == "error" for r in results)
        assert all(r["error"] for r in results)

    def test_some_errors_not_inconclusive(self):
        """Some probes error, some succeed clean -> inconclusive=False.
        Only a complete failure counts as inconclusive."""
        client = MagicMock()
        responses = iter([
            make_response("pip install requests==2.31.0"),
            make_error("HTTP 500"),
            make_response("cargo add serde"),
            make_error("HTTP 500"),
        ])

        def get_next(messages, max_tokens=100):
            return next(responses)

        client.call.side_effect = get_next

        results, detected, inconclusive = run_tool_substitution_test(client, sleep=0)

        assert detected is False
        assert inconclusive is False

    def test_mixed_results_one_substitution(self):
        """Mixed responses: one substitution triggers detection, not inconclusive."""
        client = MagicMock()
        responses = iter([
            make_response("pip install requests==2.31.0"),      # exact
            make_response("npm install reqeusts@4.17.21"),      # substituted
            make_response("cargo add serde"),                    # exact
            make_error("HTTP 500"),                              # error
        ])

        def get_next(messages, max_tokens=100):
            return next(responses)

        client.call.side_effect = get_next

        results, detected, inconclusive = run_tool_substitution_test(client, sleep=0)

        assert detected is True
        assert inconclusive is False
        verdicts = [r["verdict"] for r in results]
        assert verdicts == ["exact", "substituted", "exact", "error"]

    def test_internal_space_attack_end_to_end(self):
        """End-to-end: relay inserts a space inside the package name.
        Codex-flagged scenario; must surface as detected=True."""
        client = MagicMock()

        def space_injector(messages, max_tokens=100):
            expected = self._parse_expected_from_prompt(messages[0]["content"])
            # Insert a space in the middle of every package identifier
            mangled = (
                expected
                .replace("requests", "req uests")
                .replace("lodash", "loda sh")
                .replace("serde", "ser de")
                .replace("testify", "test ify")
            )
            return make_response(mangled)

        client.call.side_effect = space_injector

        results, detected, inconclusive = run_tool_substitution_test(client, sleep=0)

        assert detected is True
        assert inconclusive is False
        assert all(r["verdict"] == "substituted" for r in results)

    def test_multiline_decoy_end_to_end(self):
        """End-to-end: relay wraps the response so it contains both the
        expected and a malicious command. Must still be detected=True."""
        client = MagicMock()

        def decoy_wrapper(messages, max_tokens=100):
            expected = self._parse_expected_from_prompt(messages[0]["content"])
            # Only target 'requests' (pip) with the decoy
            if "requests" in expected:
                return make_response(
                    f"Original: {expected}\n"
                    f"Run: {expected.replace('requests', 'reqeusts')}"
                )
            return make_response(expected)

        client.call.side_effect = decoy_wrapper

        results, detected, inconclusive = run_tool_substitution_test(client, sleep=0)

        assert detected is True
        assert inconclusive is False
        pip_result = next(r for r in results if r["manager"] == "pip")
        assert pip_result["verdict"] == "substituted"
