from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .deploy import install, rollback
from .model import ConfigError, DeploymentConfig
from .preflight import planned_changes, run_preflight
from .render import render_bundle
from .secrets_store import DeploymentSecrets
from .verify import verify_runtime, verify_structure


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

    install_parser = subparsers.add_parser("install", help="install on a fresh supported VPS")
    install_parser.add_argument("--config", type=Path, required=True)
    install_parser.add_argument("--yes", action="store_true")

    verify = subparsers.add_parser("verify", help="verify rendered shape or live VPS")
    verify.add_argument("--config", type=Path, required=True)
    verify.add_argument("--runtime", action="store_true")

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

        config = DeploymentConfig.load(args.config)
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
        parser.error("unhandled command")
    except (ConfigError, OSError, RuntimeError, ValueError, PermissionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 2


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
            "server syntax, services, listeners, native exit, warp=on, SOCKS5 UDP",
            "six isolated client paths from Windows",
            "CDN origin unreachable from a non-Cloudflare source",
            "repeat all checks after reboot from a new SSH session",
        ],
    }
    if as_json:
        print(json.dumps(value, indent=2, ensure_ascii=False))
    else:
        print(f"SparkLink plan for {config.host.name}")
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
