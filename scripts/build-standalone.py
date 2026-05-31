#!/usr/bin/env python3
"""Build/check the committed standalone audit.py artifact.

Phase 1 intentionally keeps the standalone file committed for `curl -sO`
users while introducing a generated-artifact contract. The current builder
updates a source digest header derived from the modular source files that
must stay mirrored into standalone. CI combines this with the existing
behavior/parity tests so modular changes cannot silently skip the
standalone artifact.
"""

import argparse
import difflib
import hashlib
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
STANDALONE = REPO_ROOT / "audit.py"

HEADER_START = "# GENERATED STANDALONE ARTIFACT - DO NOT EDIT BY HAND."
HEADER_END = "# END GENERATED STANDALONE HEADER"

SOURCE_PATHS = (
    "scripts/audit.py",
    "api_relay_audit/channel_classifier.py",
    "api_relay_audit/_transport.py",
    "api_relay_audit/client.py",
    "api_relay_audit/context.py",
    "api_relay_audit/error_leakage.py",
    "api_relay_audit/identity_patterns.py",
    "api_relay_audit/infra_fingerprint.py",
    "api_relay_audit/latency_variance.py",
    "api_relay_audit/refusal.py",
    "api_relay_audit/reporter.py",
    "api_relay_audit/stream_integrity.py",
    "api_relay_audit/tool_substitution.py",
    "api_relay_audit/transparent_log.py",
    "api_relay_audit/web3/injection_probes.py",
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def source_digest() -> str:
    hasher = hashlib.sha256()
    for rel in SOURCE_PATHS:
        path = REPO_ROOT / rel
        hasher.update(rel.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(read(path).replace("\r\n", "\n").encode("utf-8"))
        hasher.update(b"\0")
    return hasher.hexdigest()


def text_digest(text: str) -> str:
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def generated_header(source_sha: str, body_sha: str) -> str:
    return (
        f"{HEADER_START}\n"
        "# Source of truth: modular files listed in scripts/build-standalone.py.\n"
        "# Regenerate after modular audit changes with:\n"
        "#   python3 scripts/build-standalone.py\n"
        "# CI verifies this header plus dual-distribution parity tests.\n"
        f"# source_sha256: {source_sha}\n"
        f"# standalone_body_sha256: {body_sha}\n"
        f"{HEADER_END}\n"
        "\n"
    )


def strip_generated_header(text: str) -> str:
    start = text.find(HEADER_START)
    if start == -1:
        return text
    end = text.find(HEADER_END, start)
    if end == -1:
        raise SystemExit("audit.py has generated header start but no end marker")
    end = text.find("\n", end)
    if end == -1:
        return text[:start]
    # Drop one extra blank line if the header is followed by one.
    next_pos = end + 1
    if text.startswith("\n", next_pos):
        next_pos += 1
    return text[:start] + text[next_pos:]


def build_text(current_text: str) -> str:
    body = strip_generated_header(current_text)
    header = generated_header(source_digest(), text_digest(body))

    if body.startswith("#!"):
        first_newline = body.find("\n")
        if first_newline == -1:
            return body + "\n" + header
        return body[:first_newline + 1] + header + body[first_newline + 1:]
    return header + body


def check() -> int:
    current = read(STANDALONE)
    expected = build_text(current)
    if current == expected:
        print("Standalone artifact check passed.")
        return 0

    diff = "\n".join(
        difflib.unified_diff(
            current.splitlines(),
            expected.splitlines(),
            fromfile="audit.py (current)",
            tofile="audit.py (expected)",
            lineterm="",
            n=3,
        )
    )
    print("Standalone artifact drift detected.", file=sys.stderr)
    print(diff, file=sys.stderr)
    print("\nRegenerate with: python3 scripts/build-standalone.py", file=sys.stderr)
    return 1


def write() -> None:
    STANDALONE.write_text(build_text(read(STANDALONE)), encoding="utf-8")
    print(f"Wrote {STANDALONE.relative_to(REPO_ROOT)}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Regenerate or check the standalone audit.py artifact."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if audit.py generated header is stale.",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.check:
        return check()
    write()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
