"""Non-Claude identity keywords for relay substitution detection.

Used by Step 5 (Instruction Override tests) to flag responses that
self-identify as a non-Claude model despite a ``"You are Claude by
Anthropic"`` system prompt. When a relay routes your request to a
cheaper domestic substitute (GLM, DeepSeek, Qwen, etc.) instead of
the advertised Claude model, the substitute model's own identity
bleeds through in the response — and we can detect it cheaply by
checking for a known list of non-Claude model / brand names.

## Matching strategy (v1.6.1)

ASCII keywords use a **leading word-boundary regex** (``\\b<kw>``,
case-insensitive) to avoid substring collisions with common English
words. For example, under the v1.6 substring approach, ``"aws"``
would spuriously match ``"laws"`` / ``"paws"`` / ``"draws"``; the
v1.6.1 word-boundary approach only matches ``aws`` as a standalone
token. Codex review finding, 2026-04-11.

v1.6.2 note: the trailing ``\\b`` was loosened to a negative-letter
lookahead (``(?![a-zA-Z])``) so version-suffixed model names like
``Qwen2.5``, ``GPT4``, or ``GLM4.6`` still match while alphabetic
continuations (``grokking``, ``glmrules``) remain blocked. Codex
review round 3, 2026-04-11.

CJK keywords (Chinese brand names) use plain substring matching
because CJK scripts have no word-boundary concept in Python's ``re``
engine. CJK tokens are distinctive enough that false positives on
random prose are extremely rare.

## Residual false positives (documented)

Word-boundary matching still trips on standalone-word false positives
such as ``"I grok your question"`` (where ``grok`` is a legitimate
English verb), ``"Kimi is my friend"`` (as a person's name), or
``"I am Claude, not GPT"`` (documented in the regression test).
These are rare in a 200-token answer to "Who are you? Who made you?"
and we accept the residual noise in exchange for implementation
simplicity. Future work (v1.7+) could require identity-phrase anchors
(``"I am X"`` / ``"made by X"``) to eliminate these.

## Attribution

The identity-substitution detection *concept* is inspired by hvoy.ai
(`https://hvoy.ai/`) and its backing repo
`github.com/zzsting88/relayAPI` `claude_detector.py`
``IDENTITY_NEGATIVE_PATTERNS``. The repo has no explicit LICENSE file,
so this module is an **independent reimplementation** of the concept
(not a code copy):

- We use a plain tuple of keyword literals + a compiled regex cache,
  not hvoy.ai's per-pattern regex list.
- The keyword set extends theirs (glm / z.ai / deepseek / minimax /
  grok / qwen / gpt) with additional Chinese-market substitutes
  (Zhipu / Tongyi / ERNIE / Doubao / Moonshot / Kimi) and Chinese
  brand names (通义 / 千问 / 智谱 / 豆包 / 文心 / 月之暗面) for
  catching responses in Chinese.
- The matching function is our own.

Verified against hvoy.ai's source on 2026-04-11. See the
``reference_hvoy_relayapi`` memory file for the full review of what
their tool does and does not detect.
"""

import re


# Keyword literals that, if present in a response to "Who are you?
# Who made you?", indicate that the relay is routing to a non-Claude
# substitute model. See module docstring for matching strategy.
#
# Groups (not enforced by code, just for readability):
#   1. Legacy (v2.1)        — Amazon / AWS brand leakage from earlier audits
#   2. hvoy.ai verified     — ASCII model names from hvoy.ai's exact
#                              IDENTITY_NEGATIVE_PATTERNS regex list
#   3. Extended ASCII       — our additions (Zhipu / Tongyi brand aliases
#                              for hvoy.ai's glm / qwen + Chinese-market
#                              substitutes hvoy.ai did not cover)
#   4. Chinese brand names  — CJK literals for catching Chinese-language
#                              responses that use the Chinese brand instead
#                              of the ASCII model name
NON_CLAUDE_IDENTITY_KEYWORDS = (
    # 1. Legacy (v2.1)
    "amazon",
    "kiro",
    "aws",
    # 2. hvoy.ai verified ASCII substitutes (exact regex list from
    #    claude_detector.py IDENTITY_NEGATIVE_PATTERNS, verified 2026-04-11)
    "glm",
    "z.ai",
    "deepseek",
    "qwen",
    "minimax",
    "grok",
    "gpt",
    # 3. sub2api / Antigravity relay identity (v1.7.5, source-verified
    #    from Wei-Shaw/sub2api request_transformer.go:179-186)
    "antigravity",  # sub2api injected identity: "You are Antigravity"
    "deepmind",     # sub2api injected identity: "designed by the Google Deepmind team"
    # 4. Reverse-proxy dev-tool platforms (v1.7.6, sourced from cctest.ai
    #    FAQ 2026-04-13). Unlike sub2api's Antigravity injection, these
    #    platforms do NOT inject a literal identity phrase; the channel
    #    label only occasionally bleeds through — classified as strict
    #    (anchor-required) because both are common English words.
    "warp",       # "warp speed", "time warp" in prose
    "windsurf",   # the watersport
    # 5. Extended ASCII (our additions — aliases and Chinese-market
    #    substitutes not in hvoy.ai's set)
    "zhipu",     # Zhipu AI, parent of GLM
    "tongyi",    # Alibaba Tongyi, parent of Qwen
    "ernie",     # Baidu ERNIE
    "doubao",    # ByteDance Doubao
    "moonshot",  # Moonshot AI
    "kimi",      # Moonshot's Kimi product
    # 6. Chinese brand names (catch Chinese-language responses)
    "通义",
    "千问",
    "智谱",
    "豆包",
    "文心",
    "月之暗面",
)


# v1.7.2 two-tier matching: short / common English-word keywords need
# an identity-phrase anchor to avoid false positives like "I am Claude,
# not GPT" or "I grok your question". Distinctive keywords like
# "deepseek" / "qwen" / "minimax" don't need anchors because they can't
# appear in ordinary English prose.
_STRICT_ASCII_KEYWORDS = frozenset({
    # Legacy short v2.1 keywords
    "amazon",
    "kiro",
    "aws",
    # Short/common ASCII words from hvoy.ai and our extensions
    "grok",   # English slang verb "to grok"
    "gpt",    # "unlike GPT" / "not GPT" prose
    "ernie",  # common given name (Sesame Street)
    "kimi",   # common given name
    # v1.7.6 reverse-proxy dev-tool channels (common English words)
    "warp",       # "warp speed" / "time warp"
    "windsurf",   # the watersport
})

# Identity anchor phrases that must immediately precede (up to ~4 filler
# words of distance) a strict keyword for it to count as a model
# self-identification claim. Covers English and Chinese forms.
_IDENTITY_ANCHOR_ALTERNATION = (
    r"i am|i'm|i am a|i'm a|i am an|i'm an|i am the|i'm the|"
    r"i was made|i was created|i was developed|i was built|i was trained|"
    r"i was released|i was fine[- ]?tuned|"
    r"made by|created by|developed by|built by|trained by|powered by|"
    r"released by|fine[- ]?tuned by|"
    r"my name is|my name's|call me|you can call me|"
    r"we are|we're|"
    # Chinese anchors
    r"我是|我叫|本人是|我的名字|我是一个|我是个|本 ?ai"
)


def _build_strict_pattern(keyword):
    """Build an anchored regex for a strict keyword.

    Matches only when the keyword appears after an identity anchor
    phrase, optionally separated by 0-4 filler words (articles,
    adjectives, ``called``, ``named``, etc.).

    **v1.7.3 Codex fix**: the filler pattern now uses
    ``(?!not\\s|isn't\\s|aren't\\s)`` to exclude negation words.
    This prevents false positives like ``"I am Claude not GPT"``
    (without a comma) which v1.7.2 still matched because "Claude not"
    counted as two filler words bridging the anchor to the keyword.

    The trailing ``(?![a-zA-Z])`` preserves the v1.6.2 version-suffix
    fix so ``GPT4`` still matches.
    """
    return re.compile(
        r"(?:" + _IDENTITY_ANCHOR_ALTERNATION + r")"
        r"\s+(?:(?!not\s|isn'?t\s|aren'?t\s|wasn'?t\s|weren'?t\s|unlike\s)\w+\s+){0,4}?"
        r"\b" + re.escape(keyword) + r"(?![a-zA-Z])",
        re.IGNORECASE,
    )


# Precompile patterns. Strict keywords use anchor-gated regex; lax
# (distinctive) keywords use the v1.6.2 word-boundary + non-letter
# lookahead. CJK keywords stay on substring matching.
_STRICT_ASCII_PATTERNS = tuple(
    (kw, _build_strict_pattern(kw))
    for kw in NON_CLAUDE_IDENTITY_KEYWORDS
    if kw in _STRICT_ASCII_KEYWORDS
)
_LAX_ASCII_PATTERNS = tuple(
    (kw, re.compile(r"\b" + re.escape(kw) + r"(?![a-zA-Z])", re.IGNORECASE))
    for kw in NON_CLAUDE_IDENTITY_KEYWORDS
    if kw.isascii() and kw not in _STRICT_ASCII_KEYWORDS
)
_CJK_KEYWORDS = tuple(
    kw for kw in NON_CLAUDE_IDENTITY_KEYWORDS if not kw.isascii()
)


def find_non_claude_identities(text: str) -> list:
    """Return a sorted list of non-Claude identity keywords found in text.

    v1.7.2 two-tier matching:

    - **Strict** keywords (``amazon``, ``kiro``, ``aws``, ``grok``,
      ``gpt``, ``ernie``, ``kimi``) must appear after an identity
      anchor phrase (``"I am"`` / ``"made by"`` / ``"我是"`` / ...).
      Eliminates false positives like ``"I am Claude, not GPT"``
      and ``"I grok your question"``.
    - **Lax** keywords (``deepseek``, ``glm``, ``qwen``, ``minimax``,
      etc.) use word-boundary + non-letter lookahead because these
      distinctive tokens don't appear in ordinary prose.
    - **CJK** keywords (``通义``, ``千问``, ...) use substring match
      because Python's ``re`` engine has no useful word-boundary
      semantics for CJK scripts.

    Args:
        text: The model response text to scan. Empty / None returns [].

    Returns:
        Sorted list of matched keywords (in their canonical form
        from ``NON_CLAUDE_IDENTITY_KEYWORDS``). Empty if no match.

    Examples:
        >>> find_non_claude_identities("I am Claude, made by Anthropic.")
        []
        >>> find_non_claude_identities("I am Claude, not GPT, made by Anthropic.")
        []
        >>> find_non_claude_identities("I am GPT-5 by OpenAI.")
        ['gpt']
        >>> find_non_claude_identities("I'm DeepSeek-V3, an assistant.")
        ['deepseek']
        >>> find_non_claude_identities("我是通义千问,由阿里巴巴创建。")
        ['千问', '通义']
        >>> find_non_claude_identities("I comply with local laws.")
        []
    """
    if not text:
        return []
    matched = []
    for keyword, pattern in _STRICT_ASCII_PATTERNS:
        if pattern.search(text):
            matched.append(keyword)
    for keyword, pattern in _LAX_ASCII_PATTERNS:
        if pattern.search(text):
            matched.append(keyword)
    for keyword in _CJK_KEYWORDS:
        if keyword in text:
            matched.append(keyword)
    return sorted(matched)
