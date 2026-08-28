from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from . import __version__
from .deploy import install, rollback
from .descriptor import build_node_descriptor
from .inventory import (
    build_adoption_plan,
    collect_remote_inventory,
    load_inventory,
    write_inventory,
    write_manager_inventory,
)
from .model import ConfigError, DeploymentConfig, split_host_port
from .preflight import planned_changes, run_preflight
from .render import render_bundle
from .secrets_store import DeploymentSecrets
from .sni_scan import format_scan_report, load_candidates, scan_candidates
from .verify import verify_runtime, verify_structure
from .wizard import prepare_install_config


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sparklinkctl")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan", help="validate config and preview exact changes")
    plan.add_argument("--config", type=Path, required=True)
    plan.add_argument("--vps", action="store_true", help="run strict live VPS preflight")
    plan.add_argument("--json", action="store_true", help="emit machine-readable output")

    render = subparsers.add_parser("render-example", help="render a dummy non-production bundle")
    render.add_argument("--config", type=Path, required=True)
    render.add_argument("--output", type=Path, required=True)
    render.add_argument("--allow-dummy", action="store_true", required=True)

    scan = subparsers.add_parser("reality-scan", help="rank public TLS/443 targets from this network")
    scan.add_argument("--config", type=Path)
    scan.add_argument("--candidates", type=Path)
    scan.add_argument("--candidate", action="append", default=[])
    scan.add_argument("--attempts", type=int, default=3)
    scan.add_argument("--timeout", type=float, default=5.0)
    scan.add_argument("--vantage", default="local")
    scan.add_argument("--output", type=Path)
    scan.add_argument("--json", action="store_true")

    prepare = subparsers.add_parser("prepare-install", help="interactively prepare domains and REALITY SNI")
    prepare.add_argument("--config", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--candidates", type=Path)
    prepare.add_argument("--local-report", type=Path)
    prepare.add_argument("--vps-report", type=Path)
    prepare.add_argument("--attempts", type=int, default=3)
    prepare.add_argument("--timeout", type=float, default=5.0)

    install_parser = subparsers.add_parser("install", help="install on a fresh supported VPS")
    install_parser.add_argument("--config", type=Path, required=True)
    install_parser.add_argument("--yes", action="store_true")

    verify = subparsers.add_parser("verify", help="verify rendered shape or live VPS")
    verify.add_argument("--config", type=Path, required=True)
    verify.add_argument("--runtime", action="store_true")

    describe = subparsers.add_parser("describe", help="emit a credential-free node descriptor")
    describe.add_argument("--config", type=Path, required=True)
    describe.add_argument("--output", type=Path)

    inventory_collect = subparsers.add_parser(
        "inventory-collect", help="collect a redacted inventory through read-only SSH"
    )
    inventory_collect.add_argument("--target", required=True, help="existing SSH alias or host")
    inventory_collect.add_argument("--name", help="local manager host label")
    inventory_collect.add_argument("--provider", help="optional provider label for the local manager")
    inventory_collect.add_argument("--port", type=int)
    inventory_collect.add_argument("--output", type=Path, required=True)
    inventory_collect.add_argument("--manager-root", type=Path)

    adopt = subparsers.add_parser(
        "adopt-plan", help="report read-only adoption compatibility for a known host layout"
    )
    adopt.add_argument("--inventory", type=Path, required=True)
    adopt.add_argument("--config", type=Path, help="optional desired deployment profile")
    adopt.add_argument("--desired-capability", action="append", default=[])
    adopt.add_argument("--output", type=Path)
    adopt.add_argument("--manager-root", type=Path)

    manager_status = subparsers.add_parser(
        "manager-status", help="summarize locally stored redacted host inventories"
    )
    manager_status.add_argument("--manager-root", type=Path, default=Path("."))
    manager_status.add_argument("--json", action="store_true")

    rollback_parser = subparsers.add_parser("rollback", help="restore one approved transaction")
    rollback_parser.add_argument("--transaction", required=True)
    rollback_parser.add_argument("--yes", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "rollback":
            rollback(args.transaction, args.yes)
            print(f"rollback completed for transaction {args.transaction}")
            return 0

        if args.command == "reality-scan":
            return _scan(args)

        if args.command == "inventory-collect":
            observation = collect_remote_inventory(
                args.target,
                name=args.name,
                provider=args.provider,
                port=args.port,
            )
            write_inventory(observation, args.output)
            manager_path = write_manager_inventory(observation, args.manager_root) if args.manager_root else None
            print(f"redacted inventory written: {args.output}")
            if manager_path:
                print(f"manager inventory written: {manager_path}")
            return 0

        if args.command == "adopt-plan":
            observation = load_inventory(args.inventory)
            desired = tuple(args.desired_capability)
            if args.config:
                desired = DeploymentConfig.load(args.config).profile.capabilities
            plan = build_adoption_plan(observation, desired) if desired else build_adoption_plan(observation)
            value = plan.to_dict()
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
                print(f"adoption plan written: {args.output}")
            if args.manager_root:
                destination = write_manager_inventory(observation, args.manager_root)
                print(f"manager inventory written: {destination}")
            print(f"Host: {plan.host}; family={plan.family}; status={plan.status}")
            print(f"Detected: {', '.join(plan.detected_capabilities) or 'none'}")
            print(f"Gaps: {', '.join(plan.gaps) or 'none'}")
            print("No remote changes were performed; explicit per-host approval is required for any future apply.")
            return 0 if plan.status in {"review-required", "managed"} else 1

        if args.command == "manager-status":
            from .inventory import build_adoption_plan, load_manager_inventories

            plans = [build_adoption_plan(observation) for observation in load_manager_inventories(args.manager_root)]
            value = {"schema_version": 1, "mode": "read-only-manager-status", "hosts": [plan.to_dict() for plan in plans]}
            if args.json:
                print(json.dumps(value, indent=2, ensure_ascii=False))
            else:
                if not plans:
                    print("No local manager inventories found.")
                for plan in plans:
                    print(f"{plan.host}: {plan.family}; {plan.status}; gaps={','.join(plan.gaps) or 'none'}")
            return 0

        config = DeploymentConfig.load(args.config)
        if args.command == "prepare-install":
            if not sys.stdin.isatty():
                raise RuntimeError("prepare-install requires an interactive terminal")
            prepare_install_config(
                config,
                args.output,
                candidates_path=args.candidates,
                local_report_path=args.local_report,
                vps_report_path=args.vps_report,
                attempts=args.attempts,
                timeout=args.timeout,
            )
            return 0
        if args.command == "plan":
            return _plan(config, args.vps, args.json)
        if args.command == "render-example":
            secrets = DeploymentSecrets.dummy()
            secrets.validate()
            digests = render_bundle(config, secrets, args.output, include_private=False)
            print(f"dummy bundle rendered: files={len(digests)} private_delivery=excluded")
            return 0
        if args.command == "install":
            transaction_id = install(config, project_root(), args.yes)
            print(f"server-side install passed; transaction={transaction_id}")
            print("external client, non-Cloudflare firewall, and reboot acceptance remain required")
            return 0
        if args.command == "verify":
            results = verify_runtime(config) if args.runtime else verify_structure(config, DeploymentSecrets.dummy())
            for result in results:
                state = "PASS" if result.passed else "FAIL"
                print(f"{state} {result.name}: {result.detail}")
            return 0 if all(result.passed for result in results) else 1
        if args.command == "describe":
            value = build_node_descriptor(config)
            rendered = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(rendered, encoding="utf-8", newline="\n")
                print(f"node descriptor written: {args.output}")
            else:
                print(rendered, end="")
            return 0
        parser.error("unhandled command")
    except (ConfigError, OSError, RuntimeError, ValueError, PermissionError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 2


def _scan(args: argparse.Namespace) -> int:
    default = None
    if args.config:
        config = DeploymentConfig.load(args.config)
        default, _ = split_host_port(config.reality.target)
    candidates = load_candidates(args.candidates, args.candidate, default)
    report = scan_candidates(
        candidates,
        vantage=args.vantage,
        attempts=args.attempts,
        timeout=args.timeout,
    )
    if args.output:
        report.write(args.output)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(format_scan_report(report))
        if args.output:
            print(f"Report written to {args.output}")
    return 0 if any(result.eligible for result in report.results) else 1


def _plan(config: DeploymentConfig, strict_vps: bool, as_json: bool) -> int:
    report = run_preflight(config, strict_host=strict_vps)
    value = {
        "configuration": config.public_summary(),
        "checks": [
            {"name": check.name, "ok": check.ok, "detail": check.detail}
            for check in report.checks
        ],
        "changes": planned_changes(config),
        "secrets": "generated on VPS; never printed",
        "rollback_root": "/var/backups/sparklink-deployer/<transaction-id>",
        "acceptance": [
            "selected server syntax, services, listeners, and egress health",
            "all selected client paths from Windows",
            "CDN origin unreachable from a non-Cloudflare source when CDN is enabled",
            "repeat all checks after reboot from a new SSH session",
        ],
    }
    if as_json:
        print(json.dumps(value, indent=2, ensure_ascii=False))
    else:
        print(f"SparkLink plan for {config.host.name}")
        print(f"Profile: {config.profile.mode}; capabilities={', '.join(config.profile.capabilities)}")
        print(f"sing-box: {'active' if config.profile.active_singbox else ('standby' if 'sing-box' in config.profile.standby_cores else 'disabled')}")
        for check in report.checks:
            print(f"{'PASS' if check.ok else 'FAIL'} {check.name}: {check.detail}")
        print("Planned changes:")
        for index, change in enumerate(value["changes"], start=1):
            print(f"  {index}. {change}")
        print("Secrets: generated on VPS and never printed")
        print("Rollback: /var/backups/sparklink-deployer/<transaction-id>")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
