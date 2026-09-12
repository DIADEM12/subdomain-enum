"""
cli.py — command-line interface for the subdomain enumerator.

This file is intentionally "thin": it only handles parsing command-line
arguments and printing/saving results. All real enumeration logic lives
in enumerator/core.py.

Usage:
    python cli.py example.com
    python cli.py example.com --passive-only
    python cli.py example.com --include-apex
    python cli.py example.com --output results.txt
"""

import argparse

from enumerator.core import run_enumeration


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Discover subdomains for a target domain."
    )
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument(
        "--passive-only",
        action="store_true",
        help="Skip DNS brute-forcing, use only crt.sh (faster, stealthier)",
    )
    parser.add_argument(
        "--include-apex",
        action="store_true",
        help="Include the bare domain itself (e.g. example.com) in results",
    )
    parser.add_argument(
        "--output",
        help="Optional file path to save results to",
    )

    args = parser.parse_args()

    print(f"[*] Enumerating subdomains for: {args.domain}")
    if args.passive_only:
        print("[*] Mode: passive only (crt.sh)")
    else:
        print("[*] Mode: passive (crt.sh) + active (DNS brute-force)")

    results = run_enumeration(
        args.domain,
        use_bruteforce=not args.passive_only,
        include_apex=args.include_apex,
    )

    print(f"\n[+] Found {len(results)} live subdomain(s):\n")
    for subdomain in results:
        print(f"    {subdomain}")

    if args.output:
        with open(args.output, "w") as f:
            for subdomain in results:
                f.write(subdomain + "\n")
        print(f"\n[*] Results saved to {args.output}")


if __name__ == "__main__":
    main()