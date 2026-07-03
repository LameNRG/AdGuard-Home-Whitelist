"""
merge_whitelists.py

Fetches external AdGuard whitelist sources, deduplicates entries,
removes anything already covered by LameNRG managed lists,
and outputs a clean merged list for publishing to GitHub.

Usage:
    python3 merge_whitelists.py

Output:
    Modules/Merged/external_whitelist.txt
"""

import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ── Sources ────────────────────────────────────────────────────────────────────

# External lists to merge (not under your control)
EXTERNAL_SOURCES = [
    "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/refs/heads/master/Whitelists/Whitelist",
    "https://raw.githubusercontent.com/GoodnessJSON/PiHole-Whitelist/master/lists/whitelist.txt",
    "https://raw.githubusercontent.com/GoodnessJSON/PiHole-Whitelist/master/lists/optional-list.txt",
]

# Your managed LameNRG lists — used to detect overlap (not merged, just compared)
LAMENRG_SOURCES = [
    "https://raw.githubusercontent.com/LameNRG/AdGuard-Home-Whitelist/refs/heads/main/Modules/Organizations/apple_whitelist.txt",
    "https://raw.githubusercontent.com/LameNRG/AdGuard-Home-Whitelist/refs/heads/main/Modules/Organizations/google_whitelist.txt",
    "https://raw.githubusercontent.com/LameNRG/AdGuard-Home-Whitelist/refs/heads/main/Modules/Organizations/microsoft_whitelist.txt",
    "https://raw.githubusercontent.com/LameNRG/AdGuard-Home-Whitelist/refs/heads/main/Modules/Media/video_whitelist.txt",
]

# Output path (relative to repo root)
OUTPUT_FILE = Path("Modules/Merged/external_whitelist.txt")

# ── Helpers ────────────────────────────────────────────────────────────────────

def fetch(url: str) -> list[str]:
    """Fetch a URL and return lines."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "merge_whitelists/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8").splitlines()
    except Exception as e:
        print(f"  WARNING: Could not fetch {url}: {e}", file=sys.stderr)
        return []


def extract_domain(line: str) -> str | None:
    """
    Extract the bare domain from an AdGuard/Pi-hole rule line.
    Handles formats:
      @@||example.com^$important
      @@||example.com^
      ||example.com^
      example.com
      0.0.0.0 example.com   (hosts format)
      # comments / ! comments → None
    """
    line = line.strip()

    # Skip blanks and comments
    if not line or line.startswith("!") or line.startswith("#"):
        return None

    # Strip inline comments: "example.com # reason" or "example.com ! reason"
    line = re.split(r"\s+[#!]", line)[0].strip()

    if not line:
        return None

    # Hosts format: "0.0.0.0 example.com" or "127.0.0.1 example.com"
    if re.match(r"^(0\.0\.0\.0|127\.0\.0\.1)\s+", line):
        parts = line.split()
        return parts[1].lower() if len(parts) >= 2 else None

    # Strip AdGuard rule wrappers: @@||, ||, leading @
    line = re.sub(r"^@@\|\|", "", line)
    line = re.sub(r"^\|\|", "", line)
    line = re.sub(r"^@+", "", line)

    # Strip trailing modifiers: ^$important, ^, $important, etc.
    line = re.sub(r"[\^$].*$", "", line)

    # Must look like a domain
    if not line or "." not in line:
        return None

    # Skip wildcards — we can't meaningfully deduplicate them
    if line.startswith("*"):
        return None

    return line.lower().strip(".")


def load_domains(urls: list[str]) -> set[str]:
    """Fetch all URLs and return a set of bare domains."""
    domains: set[str] = set()
    for url in urls:
        print(f"  Fetching: {url}")
        for line in fetch(url):
            domain = extract_domain(line)
            if domain:
                domains.add(domain)
    return domains


def format_rule(domain: str) -> str:
    # return f"@@||{domain}^$important"
    return f"@@||{domain}^"

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print("\n── Fetching external lists ──────────────────────────────")
    external_domains = load_domains(EXTERNAL_SOURCES)
    print(f"  Total entries fetched: {len(external_domains)}")

    print("\n── Fetching LameNRG managed lists (for overlap check) ───")
    managed_domains = load_domains(LAMENRG_SOURCES)
    print(f"  Total managed entries: {len(managed_domains)}")

    print("\n── Deduplicating ────────────────────────────────────────")
    overlap = external_domains & managed_domains
    unique = external_domains - managed_domains
    print(f"  Overlap with managed lists (removed): {len(overlap)}")
    print(f"  Unique entries to publish:            {len(unique)}")

    # Sort for clean diffs in git
    sorted_domains = sorted(unique)

    # Build output
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"! Title: External Whitelist (auto-merged)",
        f"! Description: Merged and deduplicated from external sources.",
        f"!              Overlap with LameNRG managed lists removed.",
        f"! Last updated: {now}",
        f"! Entries: {len(sorted_domains)}",
        f"!",
        f"! Sources:",
    ]
    for url in EXTERNAL_SOURCES:
        lines.append(f"!   {url}")
    lines.append("!")
    lines.append("")

    for domain in sorted_domains:
        lines.append(format_rule(domain))

    # Write output
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"\n── Output written to: {OUTPUT_FILE}")
    print(f"   {len(sorted_domains)} rules ready to publish.\n")


if __name__ == "__main__":
    main()