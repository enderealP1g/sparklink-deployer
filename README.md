# SparkLink Deployer

SparkLink Deployer is a plan-first, capability-driven installer for a **fresh Ubuntu
24.04 x86_64 VPS**. It preserves validated protocol assets while selecting only the
capabilities required by each node.

The default Recommended profile is:

- Xray VLESS + REALITY on TCP/443.
- `Origin` users leave through the VPS native route.
- `HyTru` users leave through a loopback WireProxy SOCKS5 service backed by Cloudflare WARP.
- sing-box AnyTLS is rendered and syntax-checked as a standby core, but is not enabled
  or delivered as a default public entry.

CDN VLESS/WebSocket, active AnyTLS, and Hysteria2 are Custom capabilities. CDN is an
optional fallback on the same VPS, not host-level failover. Hysteria2 is Custom-only and
renders a parameterized sing-box UDP/QUIC listener with separate Native/HyTru identities;
real client and reboot acceptance is still required before production use.

Version 0.4 adds capability profiles, Custom HY2 rendering, and a read-only existing-host
manager on top of the REALITY target-selection extension. It
can scan candidate SNI targets
from the user's computer, scan them again from the VPS, combine both reports, and let the
user accept the recommendation, enter a hostname manually, or keep the configured default.

## Current status

This repository is an alpha implementation extracted from deployments that were
individually validated. The local renderer, model checks, secret boundaries, and tests
are ready. Production installation remains gated on a disposable fresh VPS acceptance
run and a full reboot retest.

The current installer still refuses to mutate an existing x-ui/3x-ui, Xray, sing-box, or
custom Nginx installation. The read-only `inventory-collect` and `adopt-plan` commands can
now record known SparkLink host layouts, report capability gaps, and write a redacted local
manager inventory. A future `adopt-apply` remains per-host and approval-gated.

## Safe workflow

1. Optionally copy `config/host.example.json` to an untracked `config/host.json`.
2. Set only public deployment facts: profile, domains, ports, and REALITY target. Copy
   `config/host.example.json` to an ignored `config/host.json`; schema 2 keeps the
   selected capabilities explicit. CDN and ACME facts are required only when a
   certificate-backed capability is selected.
3. Run a local plan:

   ```bash
   ./sparklinkctl plan --config config/host.json
   ```

4. Optionally create a local-network SNI report on Windows:

   ```powershell
   .\sparklinkctl.ps1 reality-scan `
     --config config\host.json `
     --candidates config\reality-sni-candidates.txt `
     --output build\sni\local.sni-report.json
   ```

5. On a fresh supported VPS, run the interactive installer. It asks for Recommended or
   Custom, and Custom lets you select the capability set. If CDN or active sing-box is
   selected, it then asks for the required domain/certificate facts:

   ```bash
   sudo ./install.sh --config config/host.json \
     --local-sni-report build/sni/local.sni-report.json
   ```

   At the SNI prompt, press Enter for the configured default, type a hostname for manual
   selection, or type `auto` for VPS scanning and optional local+VPS combined ranking.

6. If CDN was selected, proxy only the CDN hostname and apply its hostname-scoped
   Strict TLS, origin-port, and cache-bypass rules from Windows.
7. Run server verification, reboot, then run verification again from a new SSH session.
8. Review the redacted node descriptor at `/var/lib/sparklink/public/node-descriptor.json`
   and import only the generated private delivery entries into an isolated client profile.

For an existing known host, collect only redacted facts through its normal Windows SSH
alias, then review the local plan. These commands do not restart services or write to the
VPS:

```powershell
python -m sparklink_deployer.cli inventory-collect --target racknerd-admin `
  --name racknerd-ny-01 --provider RackNerd --output build\manager\racknerd.inventory.json `
  --manager-root .
python -m sparklink_deployer.cli adopt-plan `
  --inventory build\manager\racknerd.inventory.json `
  --output build\manager\racknerd.adopt-plan.json `
  --manager-root .
python -m sparklink_deployer.cli manager-status --manager-root .
```

See [REALITY target selection](docs/reality-sni.md) for scoring and limitations. Future
VeilShift™ controller boundaries are documented in [the roadmap](docs/veilshift-roadmap.md);
Cloudflare Global API Key reading is intentionally not implemented in this release.

See `docs/architecture.md`, `docs/cloudflare-manual.md`, and `docs/runbook.md` before a
real deployment.

## Security boundaries

- No UUID, password, private key, WARP identity, subscription path, API token, or full
  node URI belongs in Git.
- Runtime secrets are generated on the VPS and stored below
  `/var/lib/sparklink/secure` with root-only permissions.
- Cloudflare credentials stay on the Windows control machine. The VPS-side installer
  does not accept or store a Cloudflare API token.
- Release versions are pinned. Release archives must match the upstream checksum file.
- The installer creates a transaction journal and rollback bundle before it activates
  services.
- `node-descriptor.json` is public and credential-free; it records selected capabilities,
  primary/standby cores, egress semantics, versions, health state, and metering readiness.

## Development checks

```powershell
python -m unittest discover -s tests -v
python -m compileall -q src tests tools
python tools/secret_scan.py .
```
