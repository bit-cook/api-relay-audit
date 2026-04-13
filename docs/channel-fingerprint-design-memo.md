# ROADMAP Item 5 — Channel Fingerprint via Protobuf Signature

**Status**: design memo only, not implemented. Must complete §2 verification before any code.
**Source**: cctest.ai FAQ (2026-04-13); independent brainstorm 2026-04-13.

## 1. Where is the signature?

Most likely location, ranked:

1. **`signature` field on thinking content blocks** — both SSE `signature_delta`
   events and non-stream `content[].signature`. Public Anthropic docs confirm
   this is a base64-encoded opaque blob (values like `EuYBCkQYAiJAy6...`) used
   for thinking-block continuity across turns. Leading bytes decode cleanly as
   protobuf wire format (tag 1, wire-type 2, length-delimited). **Almost
   certainly what cctest means.** Already captured by
   `StreamSignals.empty_signature_delta_count` — we see the value, we just
   don't parse it.
2. Response headers: `request-id` and `anthropic-organization-id` are
   confirmed present on direct Anthropic. Bedrock/Vertex strip or rewrite
   them — absence is a channel signal but a separate detector.
3. Top-level JSON (`id`, `model`, `stop_reason`): corroboration, not protobuf.
4. TLS JA3/JA4: out of scope — transport layer, not response payload; we talk
   to the relay not upstream.

**Unknown**: whether decoded protobuf contains a channel discriminator (model
serial / region / tenant) or just an opaque HMAC. Verify by §2.

## 2. Pre-implementation verification (30–60 min, 1 Anthropic key)

1. Send an Anthropic-direct thinking-enabled request; dump full headers + raw
   stream; save the first 3 `signature` strings.
2. Base64-decode each; hexdump the first ~64 bytes. Confirm varint tag/wire-
   type structure.
3. Walk fields: record `(field_number, wire_type, value_or_length)` tuples.
   Are there stable string fields (channel name) or just opaque bytes?
4. Cross-run stability: 3 identical requests, diff decoded field maps. Fields
   constant across calls but differing across models/channels = fingerprint.
5. If a user can obtain a Bedrock or Vertex Claude trace (even one pasted
   blob), compare decoded structure. Schema divergence = channel signal.
6. **Disproof criteria**: if signatures are fully opaque ciphertext (high
   entropy, no parseable tags) the hypothesis fails — abandon item 5, fall
   back to header-presence fingerprinting.

## 3. Zero-dep protobuf parser sketch

Minimum viable: varint reader, tag splitter
`(field_num, wire_type) = (tag >> 3, tag & 7)`, dispatch on wire-type 0
(varint), 1 (fixed64, skip 8), 2 (length-delimited, read length varint then
bytes), 5 (fixed32, skip 4). ~40–60 LOC pure stdlib.

Edge cases: group wire-types 3/4 (deprecated — raise), signed zigzag (defer —
only needed if we interpret a specific field), nested messages (recurse on
wire-type 2 payloads that themselves parse cleanly), unknown fields (preserve
as raw tuples, never raise). Python 3.7 `int.from_bytes` + slicing sufficient.

## 4. Architecture integration

- New module **`channel_fingerprint.py`**, not an extension of
  `stream_integrity.py` — different concern (identity vs integrity), and the
  non-stream path also needs it.
- Hook points: (a) `_populate_stream_signals` passes `signature` to a new
  `StreamSignals.first_signature_bytes: Optional[bytes]`; (b) `_call_anthropic`
  extracts `response["content"][i]["signature"]` similarly. One shared
  `fingerprint_signature(blob) -> ChannelVerdict` function consumes either.
- **D7 verdict**: tri-state mirroring D5 — `clean` (parsed, channel=direct-
  anthropic), `anomaly` (parsed, channel in {bedrock, vertex, warp, kiro,
  windsurf, antigravity, unknown-non-direct}), `inconclusive` (field absent,
  unparseable, or schema drift). Default inconclusive, matching Step 10.
- Risk matrix: HIGH escalator only if D7=anomaly AND corroborated by D5 or
  Step 5 identity leak; D7 alone = MEDIUM. Protects against a brittle signal
  flipping the overall rating.

## 5. Known failure modes (accepted)

- **Claim wrong / opaque ciphertext**: §2 step 6 kills the feature before
  code lands.
- **Anthropic schema drift**: parse defensively (unknown fields = inconclusive,
  never anomaly). Pin a `SIGNATURE_SCHEMA_VERIFIED_AT = "2026-04-13"` constant,
  re-verify quarterly.
- **Relay strips signature**: falls to inconclusive, already a Step 10
  `empty_signature_delta` anomaly — no new hole.
- **Relay forges signature as direct-anthropic**: accepted residual risk,
  documented explicitly. Without an official-key replay (out of scope per
  invariants), a resourced attacker who knows the schema can always forge.
  Mitigation: D7 is corroborative, never sole evidence.
- **Bedrock/Vertex that legitimately proxy a user's own upstream**: D7=anomaly
  is a false positive for that user. Report copy must say "upstream channel ≠
  direct-anthropic" not "relay is malicious".

## 6. Public-doc findings

No public Anthropic doc describes the signature's internal protobuf schema or
a channel-discriminator field. `request-id` and `anthropic-organization-id`
response headers are documented; Bedrock/Vertex are documented as having
different request/response envelopes (Vertex puts `anthropic_version` in body,
not header). **Conclusion**: cctest's claim is plausible (signature is real,
is protobuf, base64-encoded) but the channel-discrimination step is
undocumented and must be empirically verified before we build.
