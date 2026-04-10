"""Tests for streaming client support (Sub-PR 1 of Step 10 Stream Integrity).

Covers three layers:

1. ``_populate_stream_signals()`` — the event dispatcher (unit tests
   with plain dicts, no network).
2. ``_parse_sse_stream()`` — the byte-iterator SSE parser (unit tests
   with in-memory byte lists, no network).
3. ``APIClient.stream_call()`` — the public method that glues
   everything together (integration tests with mocked httpx).
"""

import json
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from api_relay_audit.client import (
    APIClient,
    _parse_sse_stream,
    _populate_stream_signals,
)
from api_relay_audit.stream_integrity import KNOWN_SSE_EVENT_TYPES, StreamSignals


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def sse_bytes(*events):
    """Build a single bytes chunk containing N SSE events.

    Each arg is a dict that gets JSON-serialised into a ``data: <json>\\n\\n``
    block. Trailing ``data: [DONE]\\n\\n`` is added automatically so the
    parser knows to stop.
    """
    out = []
    for event in events:
        out.append(b"data: " + json.dumps(event).encode("utf-8") + b"\n\n")
    out.append(b"data: [DONE]\n\n")
    return b"".join(out)


def _make_mock_response(content_bytes, status_code=200):
    """Build a fake httpx streaming response object that yields a single
    bytes chunk of SSE data, then EOF."""
    response = MagicMock()
    response.status_code = status_code
    response.iter_bytes = MagicMock(return_value=iter([content_bytes]))
    response.read = MagicMock(return_value=content_bytes)
    return response


def _stream_cm(response):
    """Wrap a response in a pretend context manager for client.stream()."""
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=response)
    cm.__exit__ = MagicMock(return_value=None)
    return cm


# ---------------------------------------------------------------------------
# _populate_stream_signals (unit tests)
# ---------------------------------------------------------------------------


class TestPopulateStreamSignals:

    def test_empty_event_increments_counter_only(self):
        signals = StreamSignals()
        _populate_stream_signals({}, signals)
        assert signals.raw_event_count == 1
        assert signals.event_types == []
        assert signals.has_message_start is False

    def test_message_start_captures_model_and_input_tokens(self):
        signals = StreamSignals()
        event = {
            "type": "message_start",
            "message": {
                "model": "claude-opus-4-6",
                "usage": {"input_tokens": 42},
            },
        }
        _populate_stream_signals(event, signals)
        assert signals.has_message_start is True
        assert signals.message_start_model == "claude-opus-4-6"
        assert signals.input_tokens == 42
        assert signals.event_types == ["message_start"]

    def test_content_block_start_thinking(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {"type": "content_block_start", "content_block": {"type": "thinking"}},
            signals,
        )
        assert signals.has_content_block_start is True
        assert signals.thinking_start_seen is True
        assert "thinking" in signals.content_block_types

    def test_content_block_start_text_does_not_set_thinking_flag(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {"type": "content_block_start", "content_block": {"type": "text"}},
            signals,
        )
        assert signals.has_content_block_start is True
        assert signals.thinking_start_seen is False
        assert "text" in signals.content_block_types

    def test_content_block_delta_text_delta(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {
                "type": "content_block_delta",
                "delta": {"type": "text_delta", "text": "hello"},
            },
            signals,
        )
        assert signals.has_content_block_delta is True
        assert signals.has_text_delta is True
        assert "text_delta" in signals.delta_types

    def test_content_block_delta_thinking_delta(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {
                "type": "content_block_delta",
                "delta": {"type": "thinking_delta", "thinking": "ponder"},
            },
            signals,
        )
        assert signals.thinking_delta_seen is True

    def test_content_block_delta_empty_signature_counted(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {
                "type": "content_block_delta",
                "delta": {"type": "signature_delta", "signature": ""},
            },
            signals,
        )
        assert signals.empty_signature_delta_count == 1

    def test_content_block_delta_whitespace_signature_counted(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {
                "type": "content_block_delta",
                "delta": {"type": "signature_delta", "signature": "   \t\n"},
            },
            signals,
        )
        assert signals.empty_signature_delta_count == 1

    def test_content_block_delta_real_signature_not_counted(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {
                "type": "content_block_delta",
                "delta": {"type": "signature_delta", "signature": "abc123="},
            },
            signals,
        )
        assert signals.empty_signature_delta_count == 0

    def test_message_delta_populates_usage_samples(self):
        signals = StreamSignals()
        _populate_stream_signals(
            {
                "type": "message_delta",
                "usage": {"input_tokens": 42, "output_tokens": 10},
            },
            signals,
        )
        assert signals.has_message_delta is True
        assert signals.message_delta_input_tokens_samples == [42]
        assert signals.output_tokens_samples == [10]

    def test_message_stop_flag(self):
        signals = StreamSignals()
        _populate_stream_signals({"type": "message_stop"}, signals)
        assert signals.has_message_stop is True

    def test_ping_event_tracked_in_event_types(self):
        signals = StreamSignals()
        _populate_stream_signals({"type": "ping"}, signals)
        assert "ping" in signals.event_types
        assert signals.raw_event_count == 1

    def test_unknown_event_type_still_tracked(self):
        """Unknown event types must appear in ``event_types`` so
        analyze_stream (Sub-PR 2) can detect them."""
        signals = StreamSignals()
        _populate_stream_signals({"type": "custom_relay_event"}, signals)
        assert "custom_relay_event" in signals.event_types
        assert signals.raw_event_count == 1

    def test_malformed_message_field_does_not_raise(self):
        """Non-dict ``message`` field in a message_start event must be
        silently ignored, not raise."""
        signals = StreamSignals()
        _populate_stream_signals(
            {"type": "message_start", "message": "oops not a dict"},
            signals,
        )
        assert signals.has_message_start is True
        assert signals.message_start_model is None
        assert signals.input_tokens is None


# ---------------------------------------------------------------------------
# _parse_sse_stream (unit tests)
# ---------------------------------------------------------------------------


class TestParseSseStream:

    def test_clean_single_chunk_all_events(self):
        signals = StreamSignals()
        chunk = sse_bytes(
            {"type": "message_start", "message": {"model": "claude-opus-4-6",
                                                   "usage": {"input_tokens": 42}}},
            {"type": "content_block_start", "content_block": {"type": "text"}},
            {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "hi"}},
            {"type": "message_delta", "usage": {"input_tokens": 42, "output_tokens": 5}},
            {"type": "message_stop"},
        )
        _parse_sse_stream(iter([chunk]), signals)
        assert signals.has_message_start
        assert signals.has_message_stop
        assert signals.message_start_model == "claude-opus-4-6"
        assert signals.input_tokens == 42
        assert signals.output_tokens_samples == [5]
        assert signals.raw_event_count == 5

    def test_multi_chunk_partial_events_buffered_correctly(self):
        """An event split across multiple byte chunks must still parse."""
        signals = StreamSignals()
        full = sse_bytes({"type": "message_start", "message": {"model": "x"}})
        # Split at an arbitrary mid-point of the JSON
        half = len(full) // 2
        chunks = [full[:half], full[half:]]
        _parse_sse_stream(iter(chunks), signals)
        assert signals.has_message_start
        assert signals.message_start_model == "x"

    def test_done_sentinel_stops_parse(self):
        """[DONE] sentinel must short-circuit the parse — events after
        it must NOT be counted."""
        signals = StreamSignals()
        chunks = [
            b'data: {"type":"message_start","message":{"model":"x"}}\n\n',
            b"data: [DONE]\n\n",
            b'data: {"type":"message_stop"}\n\n',
        ]
        _parse_sse_stream(iter(chunks), signals)
        assert signals.has_message_start is True
        assert signals.has_message_stop is False
        assert signals.raw_event_count == 1

    def test_malformed_json_line_skipped_silently(self):
        """A broken JSON line must not abort the parse."""
        signals = StreamSignals()
        chunks = [
            b'data: {not json\n\n',
            b'data: {"type":"message_start","message":{"model":"x"}}\n\n',
            b'data: [DONE]\n\n',
        ]
        _parse_sse_stream(iter(chunks), signals)
        # Malformed line is silently skipped, real event is parsed
        assert signals.has_message_start is True
        assert signals.raw_event_count == 1

    def test_non_data_lines_ignored(self):
        """Lines that don't start with ``data: `` must be ignored (e.g.
        ``event: message_start`` lines are common in some SSE implementations)."""
        signals = StreamSignals()
        chunks = [
            b"event: message_start\n",
            b'data: {"type":"message_start","message":{"model":"x"}}\n\n',
            b"id: 12345\n",
            b"data: [DONE]\n\n",
        ]
        _parse_sse_stream(iter(chunks), signals)
        assert signals.has_message_start is True

    def test_empty_byte_stream_produces_empty_signals(self):
        signals = StreamSignals()
        _parse_sse_stream(iter([]), signals)
        assert signals.raw_event_count == 0
        assert signals.has_message_start is False
        assert signals.transport_error is None  # parser doesn't set this

    def test_multiple_events_same_chunk(self):
        """A single byte chunk containing multiple events must parse all."""
        signals = StreamSignals()
        chunk = (
            b'data: {"type":"ping"}\n\n'
            b'data: {"type":"message_start","message":{}}\n\n'
            b'data: {"type":"message_stop"}\n\n'
            b"data: [DONE]\n\n"
        )
        _parse_sse_stream(iter([chunk]), signals)
        assert signals.raw_event_count == 3
        assert signals.event_types == ["ping", "message_start", "message_stop"]


# ---------------------------------------------------------------------------
# APIClient.stream_call (integration tests with mocked httpx)
# ---------------------------------------------------------------------------


class TestStreamCallHttpx:

    def test_clean_stream_populates_signals_via_httpx(self):
        sse_payload = sse_bytes(
            {"type": "message_start", "message": {"model": "claude-opus-4-6",
                                                   "usage": {"input_tokens": 42}}},
            {"type": "content_block_start", "content_block": {"type": "text"}},
            {"type": "content_block_delta",
             "delta": {"type": "text_delta", "text": "hi"}},
            {"type": "message_delta",
             "usage": {"input_tokens": 42, "output_tokens": 5}},
            {"type": "message_stop"},
        )

        mock_response = _make_mock_response(sse_payload)
        with patch("httpx.Client") as mock_client_cls:
            client_instance = MagicMock()
            mock_client_cls.return_value.__enter__.return_value = client_instance
            mock_client_cls.return_value.__exit__.return_value = None
            client_instance.stream.return_value = _stream_cm(mock_response)

            client = APIClient(
                "https://relay.example.com", "sk-test", "claude-opus-4-6",
                verbose=False,
            )
            signals = client.stream_call(
                [{"role": "user", "content": "hi"}], max_tokens=100,
            )

        assert signals.has_message_start is True
        assert signals.has_message_stop is True
        assert signals.message_start_model == "claude-opus-4-6"
        assert signals.input_tokens == 42
        assert signals.output_tokens_samples == [5]
        assert signals.transport_error is None
        assert signals.total_duration_seconds is not None
        assert signals.total_duration_seconds >= 0

    def test_non_200_response_sets_transport_error(self):
        mock_response = _make_mock_response(b'{"error":"bad"}', status_code=422)
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__.return_value = MagicMock(
                stream=MagicMock(return_value=_stream_cm(mock_response))
            )
            mock_client_cls.return_value.__exit__.return_value = None

            client = APIClient(
                "https://relay.example.com", "sk-test", "claude-opus-4-6",
                verbose=False,
            )
            signals = client.stream_call(
                [{"role": "user", "content": "hi"}],
            )

        assert signals.transport_error is not None
        assert "422" in signals.transport_error
        assert signals.raw_event_count == 0

    def test_httpx_exception_sets_transport_error(self):
        with patch("httpx.Client") as mock_client_cls:
            client_instance = MagicMock()
            mock_client_cls.return_value.__enter__.return_value = client_instance
            mock_client_cls.return_value.__exit__.return_value = None

            def raising_stream(*args, **kwargs):
                raise RuntimeError("simulated connection failure")

            client_instance.stream.side_effect = raising_stream

            client = APIClient(
                "https://relay.example.com", "sk-test", "claude-opus-4-6",
                verbose=False,
            )
            signals = client.stream_call(
                [{"role": "user", "content": "hi"}],
            )

        assert signals.transport_error is not None
        assert "simulated connection failure" in signals.transport_error

    def test_stream_call_request_body_contains_stream_and_thinking(self):
        """Regression: the streaming body must have ``stream: true`` and
        ``thinking`` enabled by default so Step 10 can detect thinking
        block anomalies."""
        captured = {}

        def capture_stream(method, url, headers, json):
            captured["method"] = method
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return _stream_cm(_make_mock_response(sse_bytes()))

        with patch("httpx.Client") as mock_client_cls:
            client_instance = MagicMock()
            mock_client_cls.return_value.__enter__.return_value = client_instance
            mock_client_cls.return_value.__exit__.return_value = None
            client_instance.stream.side_effect = capture_stream

            client = APIClient(
                "https://relay.example.com", "sk-test", "claude-opus-4-6",
                verbose=False,
            )
            client.stream_call([{"role": "user", "content": "hi"}], max_tokens=100)

        assert captured["method"] == "POST"
        assert captured["url"].endswith("/v1/messages")
        assert captured["headers"]["x-api-key"] == "sk-test"
        assert captured["headers"]["anthropic-version"] == "2023-06-01"
        assert captured["json"]["stream"] is True
        assert captured["json"]["thinking"] == {"type": "enabled", "budget_tokens": 99}

    def test_with_thinking_false_omits_thinking_field(self):
        captured = {}

        def capture_stream(method, url, headers, json):
            captured["json"] = json
            return _stream_cm(_make_mock_response(sse_bytes()))

        with patch("httpx.Client") as mock_client_cls:
            client_instance = MagicMock()
            mock_client_cls.return_value.__enter__.return_value = client_instance
            mock_client_cls.return_value.__exit__.return_value = None
            client_instance.stream.side_effect = capture_stream

            client = APIClient(
                "https://relay.example.com", "sk-test", "claude-opus-4-6",
                verbose=False,
            )
            client.stream_call(
                [{"role": "user", "content": "hi"}], with_thinking=False,
            )

        assert "thinking" not in captured["json"]


# ---------------------------------------------------------------------------
# KNOWN_SSE_EVENT_TYPES invariants
# ---------------------------------------------------------------------------


class TestKnownSseEventTypes:

    def test_exactly_seven_known_events(self):
        """Matches hvoy.ai claude_detector.py:369-377 verified 2026-04-11."""
        assert len(KNOWN_SSE_EVENT_TYPES) == 7

    def test_contains_ping_and_block_stop(self):
        """The v1 WebFetch summary of hvoy.ai missed ``ping`` and
        ``content_block_stop``; this regression guard asserts both are
        present because our source read verified they belong."""
        assert "ping" in KNOWN_SSE_EVENT_TYPES
        assert "content_block_stop" in KNOWN_SSE_EVENT_TYPES

    def test_all_event_types_are_str(self):
        for event_type in KNOWN_SSE_EVENT_TYPES:
            assert isinstance(event_type, str)
            assert event_type  # non-empty
