# SparkLink Deployer

SparkLink Deployer is a plan-first installer for a **fresh Ubuntu 24.04 x86_64 VPS**.
It builds three ingress capabilities with two isolated egress identities:

- Xray VLESS + REALITY on TCP/443.
- sing-box AnyTLS on TCP/9443.
- Xray VLESS + WebSocket behind a Cloudflare-only Nginx origin port.
- `Origin` users leave through the VPS native route.
- `HyTru` users leave through a loopback WireProxy SOCKS5 service backed by Cloudflare WARP.

The result is six private client entries: three Origin and three HyTru. The CDN route
is an alternate entry path on the same VPS; it is **not** host-level failover.

## Current status

This repository is an alpha implementation extracted from deployments that were
individually validated. The local renderer, model checks, secret boundaries, and tests
are ready. Production installation remains gated on a disposable fresh VPS acceptance
run and a full reboot retest.

It intentionally refuses to adopt an existing x-ui/3x-ui, Xray, sing-box, or custom
Nginx installation. Existing-host migration is a separate future workflow.

## Safe workflow

1. Copy `config/host.example.json` to an untracked `config/host.json`.
2. Set only public deployment facts: domains, ACME email, ports, and REALITY target.
   Before install, both hostnames must be `DNS only` and point directly to the new VPS so
   the two-name certificate can be issued without moving a Cloudflare credential to VPS.
3. Run a local plan:

   ```bash
   ./sparklinkctl plan --config config/host.json
   ```

4. On a fresh supported VPS, inspect the plan again and explicitly install:

   ```bash
   sudo ./install.sh --config config/host.json
   ```

5. After server installation, proxy only the CDN hostname and apply its hostname-scoped
   Strict TLS, origin-port, and cache-bypass rules from Windows.
6. Run server verification, reboot, then run verification again from a new SSH session.
7. Import the root-only delivery bundle into an isolated client profile before touching
   a live client database.

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

## Development checks

```powershell
python -m unittest discover -s tests -v
python -m compileall -q src tests tools
python tools/secret_scan.py .
```
