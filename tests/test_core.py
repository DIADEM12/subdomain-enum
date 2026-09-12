"""
test_core.py — tests for the enumeration pipeline.

We deliberately do NOT hit real external services here (crt.sh, real
DNS) — that would make tests slow, flaky, and dependent on network
access. Instead we mock the individual pieces and test the LOGIC:
dedup behavior, filtering dead subdomains, and correct wiring between
components.
"""

import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest.mock as mock

from enumerator.resolver import is_alive
from enumerator.core import run_enumeration


def test_is_alive_returns_false_for_nonexistent_domain():
    """A domain that can't possibly exist should resolve to False."""
    assert is_alive("this-domain-absolutely-does-not-exist-9x8y7z.invalid") is False


def test_run_enumeration_dedupes_overlapping_results():
    """
    If the same subdomain is found by BOTH crt.sh and brute-force,
    it should only appear once in the final results.
    """
    def fake_crtsh(domain, include_apex=False):
        return [f"www.{domain}", f"mail.{domain}"]

    def fake_bruteforce(domain, wordlist_path="wordlists/common_subdomains.txt"):
        return [f"www.{domain}"]  # overlaps with crtsh's result

    with mock.patch("enumerator.sources.crtsh.find", side_effect=fake_crtsh), \
         mock.patch("enumerator.sources.bruteforce.find", side_effect=fake_bruteforce), \
         mock.patch("enumerator.core.resolve_all", return_value=["mail.example.com"]):

        results = run_enumeration("example.com")

    assert results.count("www.example.com") == 1
    assert "mail.example.com" in results


def test_run_enumeration_filters_dead_subdomains():
    """
    A subdomain that crt.sh returns but that no longer resolves
    (e.g. a decommissioned service) should NOT appear in final results.
    """
    def fake_crtsh(domain, include_apex=False):
        return [f"old-decommissioned.{domain}"]

    def fake_bruteforce(domain, wordlist_path="wordlists/common_subdomains.txt"):
        return []

    with mock.patch("enumerator.sources.crtsh.find", side_effect=fake_crtsh), \
         mock.patch("enumerator.sources.bruteforce.find", side_effect=fake_bruteforce), \
         mock.patch("enumerator.core.resolve_all", return_value=[]):

        results = run_enumeration("example.com")

    assert results == []


def test_run_enumeration_passive_only_skips_bruteforce():
    """
    When use_bruteforce=False, bruteforce.find() should never be called
    at all.
    """
    def fake_crtsh(domain, include_apex=False):
        return [f"api.{domain}"]

    with mock.patch("enumerator.sources.crtsh.find", side_effect=fake_crtsh), \
         mock.patch("enumerator.sources.bruteforce.find") as mock_bruteforce, \
         mock.patch("enumerator.core.resolve_all", return_value=["api.example.com"]):

        run_enumeration("example.com", use_bruteforce=False)

    mock_bruteforce.assert_not_called()


def test_run_enumeration_include_apex_flag_passed_through():
    """
    include_apex should be forwarded to crtsh.find() unchanged.
    """
    with mock.patch("enumerator.sources.crtsh.find", return_value=[]) as mock_crtsh, \
         mock.patch("enumerator.sources.bruteforce.find", return_value=[]):

        run_enumeration("example.com", include_apex=True)

    mock_crtsh.assert_called_once_with("example.com", include_apex=True)