from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sparklink_deployer.model import ConfigError
from sparklink_deployer.sni_scan import (
    CandidateResult,
    ScanReport,
    combine_reports,
    load_candidates,
    normalize_candidate,
    recommended_hostname,
    scan_candidates,
    score_candidate,
)


def result(hostname: str, score: float, eligible: bool = True) -> CandidateResult:
    return CandidateResult(
        hostname=hostname,
        attempts=3,
        successes=3 if eligible else 1,
        median_ms=25.0,
        tls_versions=("TLSv1.3",) if eligible else ("TLSv1.2",),
        alpns=("h2",),
        addresses=("203.0.113.10",),
        certificate_names=(hostname,),
        cloudflare_hint=False,
        score=score,
        eligible=eligible,
        error=None,
    )


class SniScanTests(unittest.TestCase):
    def test_candidate_normalization_and_private_port_rejection(self) -> None:
        self.assertEqual(normalize_candidate("WWW.Example.COM.:443"), "www.example.com")
        with self.assertRaisesRegex(ConfigError, "TCP/443"):
            normalize_candidate("www.example.com:8443")

    def test_candidate_file_is_deduplicated_and_keeps_default_first(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "candidates.txt"
            path.write_text("www.apple.com\nwww.example.com # note\nwww.apple.com\n", encoding="utf-8")
            values = load_candidates(path, ["www.microsoft.com"], "www.example.com")
            self.assertEqual(values, ("www.example.com", "www.microsoft.com", "www.apple.com"))

    def test_scoring_requires_reliable_tls13(self) -> None:
        score, eligible = score_candidate(3, 3, 40.0, ["TLSv1.3"], ["h2"], False)
        self.assertTrue(eligible)
        self.assertGreater(score, 90)
        _, tls12_eligible = score_candidate(3, 3, 40.0, ["TLSv1.2"], ["http/1.1"], False)
        self.assertFalse(tls12_eligible)

    def test_dual_vantage_requires_both_and_weights_vps(self) -> None:
        vps = report("vps", result("www.a.example", 90), result("www.b.example", 80))
        local = report("local", result("www.a.example", 60), result("www.b.example", 99, False))
        combined = combine_reports(vps, local)
        self.assertEqual(recommended_hostname(combined), "www.a.example")
        selected = next(item for item in combined if item.hostname == "www.a.example")
        self.assertEqual(selected.score, 79.5)
        self.assertFalse(next(item for item in combined if item.hostname == "www.b.example").eligible)

    def test_report_round_trip(self) -> None:
        original = report("local", result("www.example.com", 88))
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "report.json"
            original.write(path)
            loaded = ScanReport.load(path)
        self.assertEqual(loaded.vantage, "local")
        self.assertEqual(loaded.results[0].hostname, "www.example.com")

    def test_report_rejects_string_eligibility_flag(self) -> None:
        original = report("local", result("www.example.com", 88)).to_dict()
        original["results"][0]["eligible"] = "false"
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "report.json"
            path.write_text(json.dumps(original), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "booleans"):
                ScanReport.load(path)

    def test_report_rejects_non_array_results(self) -> None:
        original = report("local", result("www.example.com", 88)).to_dict()
        original["results"] = "not-an-array"
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "report.json"
            path.write_text(json.dumps(original), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "array"):
                ScanReport.load(path)

    def test_scan_uses_injected_probe_and_sorts(self) -> None:
        def fake_probe(hostname: str, attempts: int, timeout: float) -> CandidateResult:
            return result(hostname, 90 if hostname == "www.fast.example" else 50)

        scanned = scan_candidates(
            ["www.slow.example", "www.fast.example"],
            vantage="test",
            probe=fake_probe,
        )
        self.assertEqual(scanned.results[0].hostname, "www.fast.example")


def report(vantage: str, *results: CandidateResult) -> ScanReport:
    return ScanReport(
        vantage=vantage,
        generated_at="2026-08-12T00:00:00+00:00",
        attempts=3,
        timeout_seconds=5.0,
        results=tuple(results),
    )


if __name__ == "__main__":
    unittest.main()
