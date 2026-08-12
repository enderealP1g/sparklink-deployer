from __future__ import annotations

import dataclasses
import datetime as dt
import ipaddress
import json
import socket
import ssl
import statistics
import time
from pathlib import Path
from typing import Callable, Iterable

from .model import DOMAIN_RE, ConfigError, split_host_port


REPORT_SCHEMA = 1
DEFAULT_CANDIDATES = (
    "www.microsoft.com",
    "www.apple.com",
    "www.amazon.com",
    "www.cloudflare.com",
    "www.bing.com",
)


@dataclasses.dataclass(frozen=True)
class ProbeSample:
    elapsed_ms: float
    tls_version: str
    alpn: str
    certificate_names: tuple[str, ...]
    cloudflare_hint: bool


@dataclasses.dataclass(frozen=True)
class CandidateResult:
    hostname: str
    attempts: int
    successes: int
    median_ms: float | None
    tls_versions: tuple[str, ...]
    alpns: tuple[str, ...]
    addresses: tuple[str, ...]
    certificate_names: tuple[str, ...]
    cloudflare_hint: bool
    score: float
    eligible: bool
    error: str | None

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, object]) -> "CandidateResult":
        if not isinstance(raw, dict):
            raise ValueError("SNI candidate result must be an object")
        try:
            if not isinstance(raw.get("eligible"), bool) or not isinstance(raw.get("cloudflare_hint", False), bool):
                raise ValueError("eligibility flags must be booleans")
            result = cls(
                hostname=normalize_candidate(str(raw["hostname"])),
                attempts=int(raw["attempts"]),
                successes=int(raw["successes"]),
                median_ms=float(raw["median_ms"]) if raw.get("median_ms") is not None else None,
                tls_versions=tuple(str(value) for value in raw.get("tls_versions", [])),
                alpns=tuple(str(value) for value in raw.get("alpns", [])),
                addresses=tuple(str(value) for value in raw.get("addresses", [])),
                certificate_names=tuple(str(value) for value in raw.get("certificate_names", [])),
                cloudflare_hint=bool(raw.get("cloudflare_hint", False)),
                score=float(raw["score"]),
                eligible=bool(raw["eligible"]),
                error=str(raw["error"]) if raw.get("error") else None,
            )
            if not 1 <= result.attempts <= 10:
                raise ValueError("attempts outside 1..10")
            if not 0 <= result.successes <= result.attempts:
                raise ValueError("successes outside 0..attempts")
            if result.median_ms is not None and result.median_ms < 0:
                raise ValueError("median_ms must not be negative")
            if not 0 <= result.score <= 100:
                raise ValueError("score outside 0..100")
            return result
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid SNI candidate result: {exc}") from exc


@dataclasses.dataclass(frozen=True)
class ScanReport:
    vantage: str
    generated_at: str
    attempts: int
    timeout_seconds: float
    results: tuple[CandidateResult, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": REPORT_SCHEMA,
            "vantage": self.vantage,
            "generated_at": self.generated_at,
            "attempts": self.attempts,
            "timeout_seconds": self.timeout_seconds,
            "privacy": "scanner does not record the vantage public IP",
            "results": [result.to_dict() for result in self.results],
        }

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

    @classmethod
    def load(cls, path: Path) -> "ScanReport":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"could not read SNI report {path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ValueError("SNI report root must be an object")
        if raw.get("schema_version") != REPORT_SCHEMA:
            raise ValueError("unsupported SNI report schema")
        raw_results = raw.get("results", [])
        if not isinstance(raw_results, list):
            raise ValueError("SNI report results must be an array")
        results = tuple(CandidateResult.from_dict(value) for value in raw_results)
        if not results:
            raise ValueError("SNI report contains no candidate results")
        generated_at = str(raw.get("generated_at", ""))
        try:
            parsed_time = dt.datetime.fromisoformat(generated_at)
        except ValueError as exc:
            raise ValueError("SNI report has an invalid timestamp") from exc
        if parsed_time.tzinfo is None:
            raise ValueError("SNI report timestamp must include a timezone")
        if parsed_time.astimezone(dt.timezone.utc) > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
            raise ValueError("SNI report timestamp is unexpectedly in the future")
        report = cls(
            vantage=str(raw.get("vantage", "unknown")),
            generated_at=generated_at,
            attempts=int(raw.get("attempts", 0)),
            timeout_seconds=float(raw.get("timeout_seconds", 0)),
            results=results,
        )
        if not 1 <= report.attempts <= 10:
            raise ValueError("SNI report attempts outside 1..10")
        if not 1.0 <= report.timeout_seconds <= 30.0:
            raise ValueError("SNI report timeout outside 1..30 seconds")
        return report

    def age(self, now: dt.datetime | None = None) -> dt.timedelta:
        generated = dt.datetime.fromisoformat(self.generated_at)
        reference = now or dt.datetime.now(dt.timezone.utc)
        return reference - generated.astimezone(dt.timezone.utc)


@dataclasses.dataclass(frozen=True)
class CombinedResult:
    hostname: str
    score: float
    eligible: bool
    vps_score: float | None
    local_score: float | None
    detail: str


ProbeFunction = Callable[[str, int, float], CandidateResult]


def normalize_candidate(value: str) -> str:
    candidate = value.strip().lower()
    if not candidate:
        raise ConfigError("REALITY candidate must not be empty")
    if ":" in candidate:
        host, port = split_host_port(candidate)
        if port != 443:
            raise ConfigError("REALITY candidates must use TCP/443")
        candidate = host
    candidate = candidate.rstrip(".")
    if not DOMAIN_RE.fullmatch(candidate):
        raise ConfigError(f"invalid REALITY candidate: {value}")
    return candidate


def load_candidates(path: Path | None, extra: Iterable[str] = (), default: str | None = None) -> tuple[str, ...]:
    extra_values = tuple(extra)
    values: list[str] = []
    if default:
        values.append(default)
    values.extend(extra_values)
    if path:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise ConfigError(f"could not read candidate list {path}: {exc}") from exc
        values.extend(line.split("#", 1)[0].strip() for line in lines)
    if not path and not extra_values:
        values.extend(DEFAULT_CANDIDATES)
    normalized: list[str] = []
    for value in values:
        if not value:
            continue
        candidate = normalize_candidate(value)
        if candidate not in normalized:
            normalized.append(candidate)
    if not normalized:
        raise ConfigError("no REALITY SNI candidates were supplied")
    return tuple(normalized)


def scan_candidates(
    candidates: Iterable[str],
    *,
    vantage: str,
    attempts: int = 3,
    timeout: float = 5.0,
    probe: ProbeFunction | None = None,
) -> ScanReport:
    if not 1 <= attempts <= 10:
        raise ValueError("attempts must be between 1 and 10")
    if not 1.0 <= timeout <= 30.0:
        raise ValueError("timeout must be between 1 and 30 seconds")
    probe_function = probe or probe_candidate
    results = [probe_function(normalize_candidate(candidate), attempts, timeout) for candidate in candidates]
    results.sort(key=lambda result: (-int(result.eligible), -result.score, result.hostname))
    return ScanReport(
        vantage=vantage,
        generated_at=dt.datetime.now(dt.timezone.utc).isoformat(),
        attempts=attempts,
        timeout_seconds=timeout,
        results=tuple(results),
    )


def probe_candidate(hostname: str, attempts: int, timeout: float) -> CandidateResult:
    try:
        addresses = _resolve_public_addresses(hostname)
    except OSError as exc:
        return _failed_result(hostname, attempts, type(exc).__name__)
    if not addresses:
        return _failed_result(hostname, attempts, "no public address")

    samples: list[ProbeSample] = []
    errors: list[str] = []
    for index in range(attempts):
        address = addresses[index % len(addresses)]
        try:
            samples.append(_probe_once(hostname, address, timeout))
        except (OSError, ssl.SSLError) as exc:
            errors.append(type(exc).__name__)

    successes = len(samples)
    median_ms = round(statistics.median(sample.elapsed_ms for sample in samples), 2) if samples else None
    tls_versions = tuple(sorted({sample.tls_version for sample in samples}))
    alpns = tuple(sorted({sample.alpn for sample in samples}))
    certificate_names = tuple(sorted({name for sample in samples for name in sample.certificate_names}))
    cloudflare_hint = any(sample.cloudflare_hint for sample in samples)
    score, eligible = score_candidate(attempts, successes, median_ms, tls_versions, alpns, cloudflare_hint)
    return CandidateResult(
        hostname=hostname,
        attempts=attempts,
        successes=successes,
        median_ms=median_ms,
        tls_versions=tls_versions,
        alpns=alpns,
        addresses=addresses,
        certificate_names=certificate_names,
        cloudflare_hint=cloudflare_hint,
        score=score,
        eligible=eligible,
        error=", ".join(sorted(set(errors))) if errors else None,
    )


def score_candidate(
    attempts: int,
    successes: int,
    median_ms: float | None,
    tls_versions: Iterable[str],
    alpns: Iterable[str],
    cloudflare_hint: bool,
) -> tuple[float, bool]:
    success_ratio = successes / attempts if attempts else 0.0
    tls_values = set(tls_versions)
    alpn_values = set(alpns)
    eligible = success_ratio >= 2 / 3 and "TLSv1.3" in tls_values
    score = success_ratio * 60.0
    score += 15.0 if "TLSv1.3" in tls_values else -20.0
    score += 5.0 if "h2" in alpn_values else (2.0 if "http/1.1" in alpn_values else 0.0)
    if median_ms is not None:
        score += max(0.0, 20.0 - min(median_ms, 1000.0) / 50.0)
    if cloudflare_hint:
        score -= 12.0
    return round(max(0.0, min(100.0, score)), 2), eligible


def combine_reports(vps: ScanReport, local: ScanReport | None = None) -> tuple[CombinedResult, ...]:
    vps_by_name = {result.hostname: result for result in vps.results}
    local_by_name = {result.hostname: result for result in local.results} if local else {}
    combined: list[CombinedResult] = []
    for hostname, vps_result in vps_by_name.items():
        local_result = local_by_name.get(hostname)
        if local is None:
            eligible = vps_result.eligible
            score = vps_result.score
            detail = "VPS-only ranking; run a local scan for dual-vantage confidence"
        elif local_result is None:
            eligible = False
            score = vps_result.score * 0.65
            detail = "not measured in local report"
        else:
            eligible = vps_result.eligible and local_result.eligible
            score = vps_result.score * 0.65 + local_result.score * 0.35
            detail = "passed from VPS and local" if eligible else "failed eligibility at one or both vantage points"
        if vps_result.cloudflare_hint or (local_result and local_result.cloudflare_hint):
            detail += "; Cloudflare target warning"
        combined.append(
            CombinedResult(
                hostname=hostname,
                score=round(score, 2),
                eligible=eligible,
                vps_score=vps_result.score,
                local_score=local_result.score if local_result else None,
                detail=detail,
            )
        )
    combined.sort(key=lambda result: (-int(result.eligible), -result.score, result.hostname))
    return tuple(combined)


def recommended_hostname(results: Iterable[CombinedResult]) -> str | None:
    return next((result.hostname for result in results if result.eligible), None)


def format_scan_report(report: ScanReport) -> str:
    lines = [f"REALITY scan vantage={report.vantage} attempts={report.attempts}"]
    for index, result in enumerate(report.results, start=1):
        state = "PASS" if result.eligible else "FAIL"
        latency = f"{result.median_ms:.2f}ms" if result.median_ms is not None else "n/a"
        warning = " CF-WARNING" if result.cloudflare_hint else ""
        lines.append(
            f"{index:>2}. {state} score={result.score:>6.2f} median={latency:>10} "
            f"success={result.successes}/{result.attempts} {result.hostname}{warning}"
        )
    return "\n".join(lines)


def format_combined_results(results: Iterable[CombinedResult]) -> str:
    lines = ["Combined REALITY ranking (VPS 65%, local 35%)"]
    for index, result in enumerate(results, start=1):
        state = "PASS" if result.eligible else "FAIL"
        local = f"{result.local_score:.2f}" if result.local_score is not None else "n/a"
        vps = f"{result.vps_score:.2f}" if result.vps_score is not None else "n/a"
        lines.append(
            f"{index:>2}. {state} score={result.score:>6.2f} vps={vps:>6} local={local:>6} "
            f"{result.hostname} - {result.detail}"
        )
    return "\n".join(lines)


def _resolve_public_addresses(hostname: str) -> tuple[str, ...]:
    answers = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    addresses: list[str] = []
    for answer in answers:
        candidate = answer[4][0]
        parsed = ipaddress.ip_address(candidate)
        if not parsed.is_global:
            raise OSError("candidate resolved to a non-public address")
        if candidate not in addresses:
            addresses.append(candidate)
    return tuple(addresses)


def _probe_once(hostname: str, address: str, timeout: float) -> ProbeSample:
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    started = time.perf_counter()
    with socket.create_connection((address, 443), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with context.wrap_socket(raw, server_hostname=hostname) as wrapped:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            certificate = wrapped.getpeercert()
            names = tuple(
                value.lower()
                for kind, value in certificate.get("subjectAltName", ())
                if kind == "DNS"
            )
            alpn = wrapped.selected_alpn_protocol() or "none"
            cloudflare_hint = _http_cloudflare_hint(wrapped, hostname) if alpn == "http/1.1" else is_known_cloudflare_name(hostname)
            return ProbeSample(
                elapsed_ms=elapsed_ms,
                tls_version=wrapped.version() or "unknown",
                alpn=alpn,
                certificate_names=names,
                cloudflare_hint=cloudflare_hint,
            )


def _http_cloudflare_hint(wrapped: ssl.SSLSocket, hostname: str) -> bool:
    request = (
        f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: SparkLink-SNI-Scanner/0.2\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    try:
        wrapped.settimeout(2.0)
        wrapped.sendall(request)
        response = wrapped.recv(16384).lower()
    except OSError:
        return is_known_cloudflare_name(hostname)
    return is_known_cloudflare_name(hostname) or b"\r\nserver: cloudflare" in response or b"\r\ncf-ray:" in response


def is_known_cloudflare_name(hostname: str) -> bool:
    return hostname.endswith(".cloudflare.com") or hostname == "cloudflare.com"


def _failed_result(hostname: str, attempts: int, error: str) -> CandidateResult:
    return CandidateResult(
        hostname=hostname,
        attempts=attempts,
        successes=0,
        median_ms=None,
        tls_versions=(),
        alpns=(),
        addresses=(),
        certificate_names=(),
        cloudflare_hint=False,
        score=0.0,
        eligible=False,
        error=error,
    )
