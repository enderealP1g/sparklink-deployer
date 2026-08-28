from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sparklink_deployer.model import DeploymentConfig
from sparklink_deployer.sni_scan import CandidateResult, ScanReport
from sparklink_deployer.wizard import prepare_install_config


ROOT = Path(__file__).resolve().parents[1]


class WizardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = DeploymentConfig.load(ROOT / "config" / "host.example.json")

    def test_blank_sni_keeps_default(self) -> None:
        answers = iter(["", "", ""])
        with tempfile.TemporaryDirectory() as raw:
            prepared = prepare_install_config(
                self.config,
                Path(raw) / "prepared.json",
                input_function=lambda _: next(answers),
                output_function=lambda _: None,
            )
        self.assertEqual(prepared.reality.target, self.config.reality.target)

    def test_manual_domains_and_sni_are_applied(self) -> None:
        answers = iter(
            [
                "custom", "Y", "Y", "Y", "Y", "Y", "N", "Y",
                "origin.user.example", "cdn.user.example", "user@example.com", "www.apple.com",
            ]
        )
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "prepared.json"
            prepared = prepare_install_config(
                self.config,
                output,
                input_function=lambda _: next(answers),
                output_function=lambda _: None,
            )
            reloaded = DeploymentConfig.load(output)
        self.assertEqual(prepared.host.direct_domain, "origin.user.example")
        self.assertEqual(prepared.host.cdn_domain, "cdn.user.example")
        self.assertEqual(reloaded.reality.target, "www.apple.com:443")
        self.assertEqual(reloaded.reality.server_names, ("www.apple.com",))

    def test_auto_uses_recommended_candidate_after_confirmation(self) -> None:
        answers = iter(["", "", "auto", ""])

        def fake_scan(*args: object, **kwargs: object) -> ScanReport:
            return ScanReport(
                vantage="vps-install",
                generated_at="2026-08-12T00:00:00+00:00",
                attempts=3,
                timeout_seconds=5.0,
                results=(candidate("www.apple.com", 95), candidate("www.cloudflare.com", 70)),
            )

        with tempfile.TemporaryDirectory() as raw:
            prepared = prepare_install_config(
                self.config,
                Path(raw) / "prepared.json",
                input_function=lambda _: next(answers),
                output_function=lambda _: None,
                scan_function=fake_scan,
            )
        self.assertEqual(prepared.reality.target, "www.apple.com:443")


def candidate(hostname: str, score: float) -> CandidateResult:
    return CandidateResult(
        hostname=hostname,
        attempts=3,
        successes=3,
        median_ms=20.0,
        tls_versions=("TLSv1.3",),
        alpns=("h2",),
        addresses=("203.0.113.10",),
        certificate_names=(hostname,),
        cloudflare_hint=hostname == "www.cloudflare.com",
        score=score,
        eligible=True,
        error=None,
    )


if __name__ == "__main__":
    unittest.main()
