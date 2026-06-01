#!/usr/bin/env python3
"""
Process a community audit-evidence GitHub Issue.

Called by the process-submission.yml GitHub Action. Reads issue metadata from
environment variables, validates the submitted shape, and writes a candidate
evidence record to web/data/evidence.json. The workflow must put that JSON diff
behind a maintainer-reviewed PR; community issues never publish directly to
master.

Usage (by GitHub Action):
  python3 scripts/process_submission.py

Environment variables (set by the Action):
  ISSUE_BODY        -- full issue body text
  ISSUE_AUTHOR      -- GitHub username of the submitter
  ISSUE_NUMBER      -- issue number
  AUTHOR_CREATED_AT -- ISO timestamp of the author's GitHub account creation
  PENDING_EVIDENCE_PRS_FILE -- optional gh-pr-list JSON for open evidence PRs
  GITHUB_OUTPUT     -- path to output file (set by GitHub Actions runtime)
"""

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

EVIDENCE_JSON = Path(__file__).resolve().parent.parent / "web" / "data" / "evidence.json"
ACCOUNT_AGE_WARN_DAYS = 30
MAX_SUBMISSIONS_PER_RELAY_24H = 10
MAX_RED_FLAGS = 10
MAX_FLAG_LENGTH = 500
MAX_IMAGES = 4
MAX_VERSION_LENGTH = 20
STALE_AFTER_DAYS = 90

HOSTNAME_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
TOOL_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
REPORT_HASH_RE = re.compile(r"^(?:sha256:)?[0-9a-fA-F]{64}$")
MARKDOWN_IMAGE_RE = re.compile(r"!\[[^\]\r\n]*\]\((https://[^\s)]+)\)")
HTTPS_URL_RE = re.compile(r"https://[^\s<>)]+")
PENDING_EVIDENCE_BRANCH_RE = re.compile(r"^community/evidence-(?P<domain>[^/]+)-issue-\d+$")


def _set_output(key, value):
    """Write a key=value pair to $GITHUB_OUTPUT (no-op outside Actions)."""
    path = os.environ.get("GITHUB_OUTPUT", "")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{key}={value}\n")


def parse_issue_body(body):
    """Extract structured fields from the GitHub Issue form body."""
    fields = {}

    patterns = {
        "relay_domain": r"### Relay Domain.*?\n\n(.+?)(?:\n\n|\n###|\Z)",
        "profile": r"### Audit Profile.*?\n\n(.+?)(?:\n\n|\n###|\Z)",
        "tool_version": r"### Tool Version.*?\n\n(.+?)(?:\n\n|\n###|\Z)",
        "tool_commit": r"### Tool Commit.*?\n\n(.+?)(?:\n\n|\n###|\Z)",
        "tested_at": r"### Tested At.*?\n\n(.+?)(?:\n\n|\n###|\Z)",
        "overall_rating": r"### Overall Rating.*?\n\n(.+?)(?:\n\n|\n###|\Z)",
        "report_hash": r"### Report Hash.*?\n\n(.+?)(?:\n\n|\n###|\Z)",
        "red_flags": r"### Key Findings.*?\n\n(.+?)(?:\n###|\Z)",
        "report_image": r"### Report Screenshot.*?\n\n(.+?)(?:\n###|\Z)",
        "report_artifact": r"### Report Artifact.*?\n\n(.+?)(?:\n###|\Z)",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, body, re.DOTALL | re.IGNORECASE)
        if match:
            fields[key] = match.group(1).strip()

    return fields


def normalize_domain(domain):
    """Lowercase, strip whitespace and trailing dots."""
    return domain.lower().strip().rstrip(".")


def normalize_report_hash(report_hash):
    """Normalize a SHA-256 report hash to sha256:<lowercase-hex>."""
    value = (report_hash or "").strip().lower()
    if value.startswith("sha256:"):
        return value
    return f"sha256:{value}"


def parse_tested_at(value):
    """Parse an ISO date/datetime, returning an aware UTC datetime."""
    if not value:
        raise ValueError("empty tested_at")
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        parsed = datetime.fromisoformat(f"{normalized}T00:00:00+00:00")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def is_valid_hostname(hostname):
    """Return True for canonical ASCII hostnames without ports or URL syntax."""
    if not hostname:
        return False
    if len(hostname) > 253:
        return False
    if not hostname.isascii():
        return False
    if any(ch in hostname for ch in "/\\:@?#[]"):
        return False

    labels = hostname.split(".")
    return all(HOSTNAME_LABEL_RE.fullmatch(label) for label in labels)


def validate_fields(fields):
    """Return list of error messages. Empty list = valid shape."""
    errors = []

    required = [
        "relay_domain",
        "profile",
        "tool_version",
        "tool_commit",
        "tested_at",
        "overall_rating",
        "report_hash",
        "report_image",
        "report_artifact",
    ]
    for f in required:
        if not fields.get(f):
            errors.append(f"Missing required field: {f}")

    if fields.get("overall_rating", "").upper() not in ("LOW", "MEDIUM", "HIGH"):
        errors.append(f"Invalid overall_rating: {fields.get('overall_rating')}")

    if fields.get("profile", "").lower() not in ("general", "web3", "full"):
        errors.append(f"Invalid profile: {fields.get('profile')}")

    version = fields.get("tool_version", "")
    if version:
        if len(version) > MAX_VERSION_LENGTH:
            errors.append(f"tool_version too long (max {MAX_VERSION_LENGTH}): {version}")
        elif not re.fullmatch(r"v?\d+\.\d+(?:\.\d+)?", version):
            errors.append(f"Invalid tool_version format: {version}")

    tool_commit = fields.get("tool_commit", "")
    if tool_commit and not TOOL_COMMIT_RE.fullmatch(tool_commit.strip()):
        errors.append(f"Invalid tool_commit format: {tool_commit}")

    tested_at = fields.get("tested_at", "")
    if tested_at:
        try:
            parse_tested_at(tested_at)
        except ValueError:
            errors.append(f"Invalid tested_at ISO date/datetime: {tested_at}")

    report_hash = fields.get("report_hash", "")
    if report_hash and not REPORT_HASH_RE.fullmatch(report_hash.strip()):
        errors.append("report_hash must be a SHA-256 hex digest, optionally prefixed with sha256:")

    domain = fields.get("relay_domain", "")
    if domain:
        canonical_domain = normalize_domain(domain)
        if not is_valid_hostname(canonical_domain):
            errors.append(f"Invalid relay_domain (hostname only, no port/path): {domain}")

    report_image = fields.get("report_image", "")
    if report_image and not extract_image_urls(report_image):
        errors.append("report_image must contain at least one image URL (![alt](https://...))")

    report_artifact = fields.get("report_artifact", "")
    if report_artifact and not extract_artifact_url(report_artifact):
        errors.append("report_artifact must contain an HTTPS report artifact URL")

    return errors


def check_account_age(author_created_at):
    """Return True if account is younger than ACCOUNT_AGE_WARN_DAYS."""
    if not author_created_at:
        return True
    try:
        created = datetime.fromisoformat(author_created_at.replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - created).days
        return age < ACCOUNT_AGE_WARN_DAYS
    except (ValueError, TypeError):
        print(f"WARNING: could not parse author_created_at: {author_created_at!r}")
        return True


def _entry_domain(entry):
    return entry.get("relayDomain") or entry.get("domain", "")


def check_rate_limit(domain, evidence_data):
    """Return True if domain has >= MAX_SUBMISSIONS_PER_RELAY_24H in last 24h."""
    now = datetime.now(timezone.utc)
    count = 0
    canonical_domain = normalize_domain(domain)
    for entry in evidence_data:
        if normalize_domain(_entry_domain(entry)) != canonical_domain:
            continue
        try:
            submitted = datetime.fromisoformat(
                entry.get("submittedAt", "2000-01-01").replace("Z", "+00:00")
            )
            if submitted.tzinfo is None:
                submitted = submitted.replace(tzinfo=timezone.utc)
            if (now - submitted.astimezone(timezone.utc)).total_seconds() < 86400:
                count += 1
        except (ValueError, TypeError):
            pass
    return count >= MAX_SUBMISSIONS_PER_RELAY_24H


def load_pending_evidence_pr_entries(path):
    """Load open evidence PR branch metadata as rate-limit entries."""
    if not path:
        return []
    try:
        items = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        print(f"WARNING: could not load pending evidence PRs: {exc}")
        return []

    entries = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("isCrossRepository"):
            continue
        match = PENDING_EVIDENCE_BRANCH_RE.fullmatch(item.get("headRefName", ""))
        if not match:
            continue
        domain = normalize_domain(match.group("domain"))
        created_at = item.get("createdAt", "")
        if not created_at or not is_valid_hostname(domain):
            continue
        entries.append({"relayDomain": domain, "submittedAt": created_at})
    return entries


def extract_image_urls(text):
    """Extract strict HTTPS image URLs from markdown image syntax."""
    urls = []
    for match in MARKDOWN_IMAGE_RE.finditer(text):
        url = match.group(1)
        parsed = urlparse(url)
        if parsed.scheme == "https" and parsed.netloc:
            urls.append(url)
    return urls


def extract_artifact_url(text):
    """Extract the first HTTPS URL from an uploaded or linked report artifact."""
    for match in HTTPS_URL_RE.finditer(text or ""):
        url = match.group(0).rstrip(".,;")
        parsed = urlparse(url)
        if parsed.scheme == "https" and parsed.netloc:
            return url
    return ""


def build_evidence_record(fields, issue_author, issue_number, now=None):
    """Build a community-submitted audit evidence record from validated fields."""
    if now is None:
        now = datetime.now(timezone.utc)

    tested_at = parse_tested_at(fields["tested_at"])
    stale_after = tested_at + timedelta(days=STALE_AFTER_DAYS)

    red_flags = []
    if fields.get("red_flags"):
        for line in fields["red_flags"].split("\n"):
            line = line.strip().lstrip("- ")[:MAX_FLAG_LENGTH]
            if line:
                red_flags.append(line)
            if len(red_flags) >= MAX_RED_FLAGS:
                break

    return {
        "schemaVersion": 1,
        "recordType": "community-submitted-audit-evidence",
        "relayDomain": normalize_domain(fields["relay_domain"]),
        "toolVersion": fields.get("tool_version", ""),
        "toolCommit": fields["tool_commit"].strip().lower(),
        "auditProfile": fields.get("profile", "general").lower(),
        "toolReportedOverallRating": fields["overall_rating"].upper(),
        "submittedAt": now.isoformat(),
        "testedAt": tested_at.isoformat(),
        "submitter": issue_author,
        "issueNumber": int(issue_number) if issue_number else None,
        "reportHash": normalize_report_hash(fields["report_hash"]),
        "reportArtifactUrl": extract_artifact_url(fields["report_artifact"]),
        "evidenceStatus": "accepted_unverified",
        "reviewStatus": "unverified",
        "disputeStatus": "none",
        "staleAfter": stale_after.date().isoformat(),
        "redFlags": red_flags,
        "reportImages": extract_image_urls(fields.get("report_image", ""))[:MAX_IMAGES],
        "source": "github-issue",
    }


def main():
    body = os.environ.get("ISSUE_BODY", "")
    author = os.environ.get("ISSUE_AUTHOR", "")
    issue_number = os.environ.get("ISSUE_NUMBER", "")
    author_created_at = os.environ.get("AUTHOR_CREATED_AT", "")

    if not body:
        print("ERROR: ISSUE_BODY is empty")
        _set_output("status", "ERROR")
        sys.exit(1)

    fields = parse_issue_body(body)
    errors = validate_fields(fields)
    if errors:
        print("VALIDATION_ERRORS:")
        for e in errors:
            print(f"  - {e}")
        _set_output("status", "VALIDATION_ERRORS")
        sys.exit(2)

    if check_account_age(author_created_at):
        print("NEEDS_REVIEW: account younger than 30 days")
        _set_output("status", "NEEDS_REVIEW")
        sys.exit(3)

    if EVIDENCE_JSON.exists():
        evidence_data = json.loads(EVIDENCE_JSON.read_text(encoding="utf-8"))
    else:
        evidence_data = []
    pending_evidence_data = load_pending_evidence_pr_entries(
        os.environ.get("PENDING_EVIDENCE_PRS_FILE", "")
    )

    domain = normalize_domain(fields["relay_domain"])
    if check_rate_limit(domain, evidence_data + pending_evidence_data):
        print(f"RATE_LIMITED: {domain} has >= {MAX_SUBMISSIONS_PER_RELAY_24H} submissions in 24h")
        _set_output("status", "RATE_LIMITED")
        sys.exit(4)

    entry = build_evidence_record(fields, author, issue_number)
    evidence_data.append(entry)

    EVIDENCE_JSON.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE_JSON.write_text(
        json.dumps(evidence_data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    _set_output("status", "SHAPE_VALID")
    _set_output("relay_domain", entry["relayDomain"])
    _set_output("report_hash", entry["reportHash"])
    _set_output("report_artifact_url", entry["reportArtifactUrl"])
    _set_output("tool_commit", entry["toolCommit"])
    print(f"SHAPE_VALID: staged evidence for {domain} (#{issue_number}) by @{author}")
    print("Publication requires maintainer review via PR; no direct master push.")


if __name__ == "__main__":
    main()
