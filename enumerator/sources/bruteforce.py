"""
bruteforce.py — active subdomain discovery via DNS wordlist brute-forcing.

Unlike crtsh.py, this module actively interacts with DNS infrastructure:
for every word in a wordlist (e.g. "www", "mail", "dev", "staging"), we
build a candidate like "dev.example.com" and ask a DNS resolver "does
this exist?" If it resolves, we've found a real subdomain — even one
that was never issued a certificate and would never show up in crt.sh.

This is called "active" recon because we're generating real DNS traffic
that (in theory) the target's DNS infrastructure could log or notice.
It's slower than the passive method and depends entirely on wordlist
quality — if "admin-panel" isn't in the wordlist, we'll never find
admin-panel.example.com this way.

We use concurrent.futures.ThreadPoolExecutor to run many DNS lookups
in parallel, since each lookup is I/O-bound (mostly waiting on the
network) rather than CPU-bound.
"""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from enumerator.resolver import is_alive

# Compute the wordlist's location relative to THIS FILE's position on
# disk, not the process's current working directory. A relative path
# like "wordlists/common_subdomains.txt" only resolves correctly if
# the script happens to be launched from the project root — it breaks
# the moment you run `cd web && python app.py` (cwd becomes web/) or
# deploy to a server where the working directory isn't guaranteed.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DEFAULT_WORDLIST = os.path.join(_PROJECT_ROOT, "wordlists", "common_subdomains.txt")


def _load_wordlist(wordlist_path: str) -> list[str]:
    """Read the wordlist file and return a clean list of words."""
    try:
        with open(wordlist_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[bruteforce] wordlist not found: {wordlist_path}")
        return []


def find(
    domain: str,
    wordlist_path: str = None,
    max_workers: int = 20,
) -> list[str]:
    """
    Attempt to resolve {word}.{domain} for every word in the wordlist,
    in parallel, and return the ones that successfully resolve.

    Args:
        domain: the target domain, e.g. "example.com"
        wordlist_path: path to a newline-separated wordlist file. If
            None (default), uses the bundled wordlist regardless of
            the current working directory.
        max_workers: how many DNS lookups to run concurrently

    Returns:
        A list of subdomain strings that resolved successfully.
    """
    path = wordlist_path or _DEFAULT_WORDLIST
    words = _load_wordlist(path)
    if not words:
        return []

    candidates = [f"{word}.{domain}" for word in words]
    found = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_candidate = {
            executor.submit(is_alive, c): c for c in candidates
        }
        for future in as_completed(future_to_candidate):
            candidate = future_to_candidate[future]
            try:
                if future.result():
                    found.append(candidate)
            except Exception as e:
                print(f"[bruteforce] error checking {candidate}: {e}")

    return sorted(found)