"""
resolver.py — confirms whether a candidate subdomain is actually "alive".

crt.sh can return subdomains that no longer exist (a cert was issued
years ago for a subdomain that was later decommissioned). This module
does a real DNS lookup to check: does this subdomain currently resolve
to an IP address?

is_alive() checks a single subdomain. resolve_all() checks a whole
list of them in parallel using ThreadPoolExecutor — used by core.py
to confirm passive (crt.sh) candidates quickly, the same way
bruteforce.py already resolves its own candidates in parallel.
"""

import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed


def is_alive(subdomain: str) -> bool:
    """
    Check whether a subdomain currently resolves via DNS.

    Args:
        subdomain: full subdomain to check, e.g. "mail.example.com"

    Returns:
        True if the subdomain resolves to at least one A record,
        False otherwise (NXDOMAIN, SERVFAIL, timeout, etc.)
    """
    try:
        dns.resolver.resolve(subdomain, "A", lifetime=5)
        return True
    except dns.resolver.NXDOMAIN:
        # the subdomain simply doesn't exist — the expected, common case
        return False
    except dns.resolver.NoAnswer:
        # domain exists but has no A record (e.g. only has an MX record)
        return False
    except dns.resolver.NoNameservers:
        # SERVFAIL or similar — the nameserver refused/failed to answer.
        # Common for large infrastructure with strict DNS policies
        # (e.g. big CDNs). Not a bug, just "not usable" for our purposes.
        return False
    except dns.exception.Timeout:
        # DNS server took too long to respond
        return False
    except Exception as e:
        # catch-all: only genuinely unexpected errors get printed
        print(f"[resolver] unexpected error resolving {subdomain}: {e}")
        return False


def resolve_all(candidates: list[str], max_workers: int = 20) -> list[str]:
    """
    Check a list of candidate subdomains in parallel and return only
    the ones that are alive.

    Args:
        candidates: list of full subdomain strings to check
        max_workers: how many DNS lookups to run concurrently

    Returns:
        A sorted list of subdomains that resolved successfully.
    """
    alive = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_candidate = {
            executor.submit(is_alive, c): c for c in candidates
        }
        for future in as_completed(future_to_candidate):
            candidate = future_to_candidate[future]
            try:
                if future.result():
                    alive.append(candidate)
            except Exception as e:
                print(f"[resolver] error checking {candidate}: {e}")
    return sorted(alive)