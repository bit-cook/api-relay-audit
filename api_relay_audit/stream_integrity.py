"""Stream integrity signals for Step 10 SSE-level relay tampering detection.

This module provides the data structures that capture what an
Anthropic-format streaming response looked like at the SSE event
layer. The actual verdict logic (:func:`analyze_stream`) is added in
a follow-up commit (Sub-PR 2); this commit ships the dataclass plus
constants so :meth:`api_relay_audit.client.APIClient.stream_call`
has something to populate.

## Detection approach

A malicious relay that rewrites or proxies Claude's streaming
responses can be caught at three distinct layers, even if the final
text the user sees looks correct:

1. **SSE event whitelist.** Anthropic's stream schema uses exactly
   7 event types (see :data:`KNOWN_SSE_EVENT_TYPES`). An unknown
   event type in the stream is a strong fingerprint of a relay that
   is injecting or rewriting events. Sub-PR 2's ``analyze_stream``
   penalises any unknown event.
2. **Usage-field monotonicity.** The ``message_start`` event carries
   an ``input_tokens`` count; subsequent ``message_delta`` events
   carry incremental ``output_tokens`` and a reiteration of
   ``input_tokens``. A relay that rewrites usage (to under-bill the
   caller or hide a model downgrade) often fails these invariants:
   ``output_tokens`` may go non-monotonic, or ``input_tokens`` may
   mysteriously shift between events.
3. **Thinking block signature consistency.** Claude Opus/Sonnet 4.6
   extended-thinking responses emit ``signature_delta`` events whose
   ``signature`` field must be non-empty. A relay that degrades to
   a non-thinking model and fakes the surrounding stream events may
   leave the signatures empty. :attr:`StreamSignals.empty_signature_delta_count`
   counts these.

## Attribution

The threat model and the specific list of observable signals is
inspired by hvoy.ai's ``zzsting88/relayAPI`` ``claude_detector.py``
``StreamSignals`` dataclass (verified against the source on
2026-04-11). The upstream repository has no ``LICENSE`` file, so
this module is an independent clean-room reimplementation:

- The field NAMES (``event_types``, ``message_start_model``,
  ``empty_signature_delta_count`` etc.) overlap with hvoy.ai's
  because they describe the same Anthropic SSE schema — schema
  field names and protocol event types are not copyrightable.
- The field TYPES and default factories are our own choices.
- The scoring / verdict logic in Sub-PR 2 will be tri-state
  (``clean`` / ``anomaly`` / ``inconclusive``), NOT hvoy.ai's
  weighted 0-100 score model.

See the ``reference_hvoy_relayapi`` memory file for the full
verification and the list of things we chose NOT to port
(knowledge cutoff probe, Claude Code CLI header impersonation,
``"null"`` text-block request body fingerprint).

Reference: Liu, Shou, Wen, Chen, Fang, Feng, *"Your Agent Is Mine:
Measuring Malicious Intermediary Attacks on the LLM Supply Chain"*,
arXiv:2604.08407, section 4.2. SSE whitelist / usage monotonicity
/ signature consistency are AC-1-class detections at the transport
layer.
"""

from dataclasses import dataclass, field
from typing import List, Optional


# The 7 known Anthropic SSE event types. Anything else in an
# ``event_types`` list is an "unknown event" — a potential signal
# that a relay is injecting or rewriting SSE events. Sourced from
# reading ``claude_detector.py`` lines 369-377 of
# ``zzsting88/relayAPI`` on 2026-04-11.
KNOWN_SSE_EVENT_TYPES = frozenset({
    "ping",
    "message_start",
    "content_block_start",
    "content_block_delta",
    "content_block_stop",
    "message_delta",
    "message_stop",
})


@dataclass
class StreamSignals:
    """Captures what a streaming Anthropic response looked like at
    the SSE event layer.

    Populated by :meth:`api_relay_audit.client.APIClient.stream_call`
    during the request; consumed by
    :func:`analyze_stream` (added in Sub-PR 2) afterwards.

    All fields default to the "nothing observed" value so that a
    stream that errored out still produces a valid, serialisable
    signals object. Downstream consumers must check
    :attr:`transport_error` before drawing conclusions about
    "clean vs anomalous" — an empty signals object with an error
    should be reported as *inconclusive*, not *clean*.

    Attributes:
        event_types: Ordered list of every SSE event type observed
            in the stream, including unknown types. Used for the
            whitelist check.
        content_block_types: Types observed in
            ``content_block_start`` events (e.g. ``"text"`` or
            ``"thinking"``), in arrival order.
        delta_types: Types observed in ``content_block_delta``
            events (e.g. ``"text_delta"``, ``"thinking_delta"``,
            ``"signature_delta"``), in arrival order.
        has_message_start: True iff at least one ``message_start``
            event was observed.
        has_content_block_start: True iff at least one
            ``content_block_start`` event was observed.
        has_content_block_delta: True iff at least one
            ``content_block_delta`` event was observed.
        has_message_delta: True iff at least one ``message_delta``
            event was observed.
        has_message_stop: True iff at least one ``message_stop``
            event was observed.
        has_text_delta: True iff at least one ``text_delta`` inside
            a ``content_block_delta`` was observed.
        thinking_start_seen: True iff a ``content_block_start`` with
            ``content_block.type == "thinking"`` was observed.
        thinking_delta_seen: True iff at least one ``thinking_delta``
            was observed inside a ``content_block_delta``.
        message_start_model: The ``message.model`` field from the
            first ``message_start`` event, or ``None`` if missing.
            A relay that routes ``claude-*`` to a non-Claude model
            often leaks the truth here.
        input_tokens: The ``input_tokens`` value from the first
            ``message_start`` event's ``usage`` block, or ``None``.
        message_delta_input_tokens_samples: Every ``input_tokens``
            value observed in ``message_delta`` events. Used to
            detect rewriting — these should all equal
            :attr:`input_tokens`.
        output_tokens_samples: Every ``output_tokens`` value
            observed in ``message_delta`` events, in arrival order.
            Used to check monotonicity (each sample should be
            greater than or equal to the previous one).
        empty_signature_delta_count: Number of ``signature_delta``
            events with an empty or whitespace-only signature field.
            > 0 is a thinking-block downgrade signal.
        transport_error: Non-``None`` iff the stream could not be
            opened or parsed cleanly (connection error, non-200
            response status, timeout). Downstream consumers should
            treat this as *inconclusive*, never *clean*.
        total_duration_seconds: Wall clock time from request start
            to stream close. Useful for detecting buffered-rewriter
            relays that delay the entire response.
        raw_event_count: Total number of events parsed from the
            stream, including unknown types. Zero means no data was
            received at all — another inconclusive signal.
    """

    # Ordered event type sequence (for whitelist check)
    event_types: List[str] = field(default_factory=list)
    # Content block types observed in content_block_start events
    content_block_types: List[str] = field(default_factory=list)
    # Delta types observed in content_block_delta events
    delta_types: List[str] = field(default_factory=list)

    # Boolean presence flags for convenient queries
    has_message_start: bool = False
    has_content_block_start: bool = False
    has_content_block_delta: bool = False
    has_message_delta: bool = False
    has_message_stop: bool = False
    has_text_delta: bool = False
    thinking_start_seen: bool = False
    thinking_delta_seen: bool = False

    # Identity and usage signals
    message_start_model: Optional[str] = None
    input_tokens: Optional[int] = None
    message_delta_input_tokens_samples: List[int] = field(default_factory=list)
    output_tokens_samples: List[int] = field(default_factory=list)

    # Thinking block anomaly counters
    empty_signature_delta_count: int = 0

    # Transport and timing
    transport_error: Optional[str] = None
    total_duration_seconds: Optional[float] = None
    raw_event_count: int = 0
