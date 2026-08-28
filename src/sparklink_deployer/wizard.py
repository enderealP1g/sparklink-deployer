from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path
from typing import Callable

from .model import DEFAULT_RECOMMENDED_CAPABILITIES, DeploymentConfig, split_host_port
from .sni_scan import (
    ScanReport,
    combine_reports,
    format_combined_results,
    format_scan_report,
    is_known_cloudflare_name,
    load_candidates,
    normalize_candidate,
    recommended_hostname,
    scan_candidates,
)


InputFunction = Callable[[str], str]
OutputFunction = Callable[[str], None]
ScanFunction = Callable[..., ScanReport]


def prepare_install_config(
    config: DeploymentConfig,
    output_path: Path,
    *,
    candidates_path: Path | None = None,
    local_report_path: Path | None = None,
    vps_report_path: Path | None = None,
    attempts: int = 3,
    timeout: float = 5.0,
    input_function: InputFunction = input,
    output_function: OutputFunction = print,
    scan_function: ScanFunction = scan_candidates,
) -> DeploymentConfig:
    raw = config.public_summary()
    host = raw["host"]
    assert isinstance(host, dict)

    output_function("SparkLink interactive setup")
    output_function("Press Enter to keep the value shown in brackets.")
    profile_raw = raw.get("profile") or {}
    mode = _prompt_value("Deployment mode (recommended/custom)", str(profile_raw.get("mode", "recommended")), input_function).lower()
    if mode not in {"recommended", "custom"}:
        raise ValueError("deployment mode must be recommended or custom")
    if mode == "recommended":
        capabilities = list(DEFAULT_RECOMMENDED_CAPABILITIES)
        standby_cores = ["sing-box"]
        output_function("Recommended: Xray Reality with Native + HyTru/WARP; sing-box remains standby.")
    else:
        current = set(profile_raw.get("capabilities") or DEFAULT_RECOMMENDED_CAPABILITIES)
        capabilities = []
        for capability, label, default in (
            ("xray-reality-vision", "Xray VLESS REALITY", "xray-reality-vision" in current),
            ("egress-native", "Origin/Native egress", "egress-native" in current),
            ("egress-hytru-warp", "HyTru/WARP egress", "egress-hytru-warp" in current),
            ("singbox-anytls", "sing-box AnyTLS active ingress", "singbox-anytls" in current),
            ("cdn-vless-ws", "VLESS CDN fallback", "cdn-vless-ws" in current),
            ("hysteria2", "Hysteria2 weak-network capability", "hysteria2" in current),
        ):
            if _prompt_bool(label, default, input_function):
                capabilities.append(capability)
        if not capabilities:
            raise ValueError("Custom must enable at least one capability")
        standby_default = "sing-box" in (profile_raw.get("standby_cores") or ["sing-box"])
        standby_cores = ["sing-box"] if _prompt_bool("Install sing-box as standby", standby_default, input_function) else []
    profile_raw.update(
        {
            "mode": mode,
            "capabilities": capabilities,
            "primary_core": "xray",
            "standby_cores": standby_cores,
        }
    )
    raw["profile"] = profile_raw
    host["direct_domain"] = _prompt_value(
        "Direct DNS-only hostname", str(host["direct_domain"]), input_function
    )
    if "cdn-vless-ws" in capabilities:
        host["cdn_domain"] = _prompt_value(
            "CDN hostname (later proxied through Cloudflare)", str(host.get("cdn_domain", "")), input_function
        )
    else:
        host["cdn_domain"] = str(host.get("cdn_domain", ""))
    if "cdn-vless-ws" in capabilities or "singbox-anytls" in capabilities or "hysteria2" in capabilities:
        host["acme_email"] = _prompt_value("ACME email", str(host.get("acme_email", "")), input_function)
    else:
        host["acme_email"] = str(host.get("acme_email", ""))

    if "xray-reality-vision" in capabilities:
        default_sni, _ = split_host_port(config.reality.target)
        answer = input_function(
            f"REALITY SNI [default={default_sni}; type auto to scan; or enter a hostname]: "
        ).strip()
        selected = default_sni
    else:
        answer = ""
        selected = ""
    if "xray-reality-vision" in capabilities and not answer:
        output_function(f"Using configured default REALITY SNI: {default_sni}")
        _warn_known_cloudflare(default_sni, output_function)
    elif "xray-reality-vision" in capabilities and answer.lower() == "auto":
        local_report = ScanReport.load(local_report_path) if local_report_path else None
        if local_report and local_report.age() > dt.timedelta(days=7):
            output_function(
                f"WARNING: local SNI report is {local_report.age().days} days old; rerun it for current-network confidence."
            )
        extras = tuple(result.hostname for result in local_report.results) if local_report else ()
        candidates = load_candidates(candidates_path, extras, default_sni)
        output_function(f"Scanning {len(candidates)} candidates from this VPS...")
        vps_report = scan_function(
            candidates,
            vantage="vps-install",
            attempts=attempts,
            timeout=timeout,
        )
        if vps_report_path:
            vps_report.write(vps_report_path)
            output_function(f"VPS scan report: {vps_report_path}")
        output_function(format_scan_report(vps_report))
        combined = combine_reports(vps_report, local_report)
        output_function(format_combined_results(combined))
        recommended = recommended_hostname(combined)
        if recommended:
            choice = input_function(
                f"Recommended SNI is {recommended}. Press Enter to use it, type default, or enter another hostname: "
            ).strip()
            if not choice:
                selected = recommended
            elif choice.lower() == "default":
                selected = default_sni
            else:
                selected = normalize_candidate(choice)
        else:
            output_function("No candidate passed the required checks; keeping the configured default.")
    elif "xray-reality-vision" in capabilities:
        selected = normalize_candidate(answer)
        output_function(f"Using manually selected REALITY SNI: {selected}")
        _warn_known_cloudflare(selected, output_function)

    reality = raw["reality"]
    assert isinstance(reality, dict)
    if selected:
        reality["target"] = f"{selected}:443"
        reality["server_names"] = [selected]
    prepared = DeploymentConfig.from_dict(raw)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(prepared.public_summary(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    if sys.platform != "win32":
        output_path.chmod(0o600)
    output_function(f"Prepared install configuration: {output_path}")
    return prepared


def _prompt_value(label: str, current: str, input_function: InputFunction) -> str:
    value = input_function(f"{label} [{current}]: ").strip()
    return value or current


def _prompt_bool(label: str, current: bool, input_function: InputFunction) -> bool:
    default = "Y" if current else "N"
    answer = input_function(f"{label} [Y/N; default={default}]: ").strip().lower()
    if not answer:
        return current
    if answer in {"y", "yes", "1", "true"}:
        return True
    if answer in {"n", "no", "0", "false"}:
        return False
    raise ValueError(f"{label} expects Y or N")


def _warn_known_cloudflare(hostname: str, output_function: OutputFunction) -> None:
    if is_known_cloudflare_name(hostname):
        output_function(
            "WARNING: this is a known Cloudflare target; official Xray guidance warns that fallback forwarding may be abused."
        )
