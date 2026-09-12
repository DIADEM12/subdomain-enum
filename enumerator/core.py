"""
core.py — orchestrates the full enumeration pipeline.

This is the single entry point both the CLI and the web UI call.
It ties together:
    1. sources.crtsh.find()       -> passive candidates
    2. sources.bruteforce.find()  -> active candidates (already
       resolved as part of finding them)
    3. dedup + merge
    4. resolver.resolve_all()     -> confirm liveness on anything
       not already confirmed by brute-force, IN PARALLEL
"""

from enumerator.sources import crtsh, bruteforce
from enumerator.resolver import resolve_all


def run_enumeration(
    domain: str,
    use_bruteforce: bool = True,
    include_apex: bool = False,
    wordlist_path: str = None,
    max_workers: int = 20,
) -> list[str]:
    """
    Run the full subdomain enumeration pipeline against a domain.

    Args:
        domain: the target domain, e.g. "example.com"
        use_bruteforce: whether to also run active DNS brute-forcing
        include_apex: whether to include the bare domain itself in results
        wordlist_path: path to the brute-force wordlist file
        max_workers: how many DNS lookups to run concurrently when
            confirming passive (crt.sh) candidates

    Returns:
        A sorted list of confirmed-live subdomains.
    """
    passive_results = crtsh.find(domain, include_apex=include_apex)

    active_results = []
    if use_bruteforce:
        active_results = bruteforce.find(domain, wordlist_path=wordlist_path)

    passive_candidates = set(passive_results)
    already_confirmed = set(active_results)
    to_check = list(passive_candidates - already_confirmed)

    # Resolve the NEW candidates from crt.sh IN PARALLEL. This used to
    # be a plain one-at-a-time loop — fine for a small domain, but for
    # something like netflix.com with hundreds of crt.sh results,
    # resolving serially could take minutes. resolve_all() keeps both
    # halves of the pipeline consistently fast.
    confirmed_from_passive = set(resolve_all(to_check, max_workers=max_workers))

    all_confirmed = already_confirmed | confirmed_from_passive

    return sorted(all_confirmed)