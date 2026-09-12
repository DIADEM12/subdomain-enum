"""
crtsh.py — passive subdomain discovery via certificate transparency logs.

crt.sh is a public search engine over Certificate Transparency (CT) logs.
Every time a Certificate Authority issues an HTTPS certificate for a domain
(e.g. mail.example.com), that issuance is publicly logged — this is a
security requirement for CAs, not optional. crt.sh lets us search those
logs by domain, which means we can find subdomains that were *ever*
issued a certificate, without sending a single packet to the target.

This is called "passive" recon: we're not interacting with the target's
infrastructure at all, only querying a public third-party dataset. That
makes it stealthy (the target sees no traffic from us) and fast, but it
only reveals subdomains that have certificates — internal-only or
never-certified subdomains won't show up here.
"""

import requests


def find(domain: str, include_apex: bool = False) -> list[str]:
    """
    Query crt.sh for certificates issued for *.{domain} and return
    the list of subdomains found in those certificates.

    Args:
        domain: the target domain, e.g. "example.com"
        include_apex: if True, include the bare domain itself
            (e.g. "example.com") in results if found in a certificate.
            If False (default), only true subdomains are returned —
            "example.com" is filtered out even though it commonly
            appears alongside "*.example.com" in real certificates.

    Returns:
        A list of subdomain strings (deduplicated), e.g.
        ["mail.example.com", "api.example.com"]
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        # crt.sh can be slow/flaky — fail gracefully rather than
        # crashing the whole enumeration if this one source is down
        print(f"[crtsh] request failed: {e}")
        return []

    try:
        certs = response.json()
    except ValueError:
        # crt.sh sometimes returns an empty body instead of valid JSON
        # when it finds nothing or is under load
        return []

    subdomains = set()
    domain_lower = domain.lower()

    for cert in certs:
        name_value = cert.get("name_value", "")
        # one certificate can cover multiple names, newline-separated —
        # e.g. "*.example.com\nexample.com" is a single, real entry
        for name in name_value.split("\n"):
            name = name.strip().lower()

            if not name:
                continue

            # skip wildcard entries like "*.example.com" — not a real host
            if name.startswith("*."):
                continue

            # skip the bare apex domain unless explicitly requested
            if name == domain_lower and not include_apex:
                continue

            subdomains.add(name)

    return sorted(subdomains)