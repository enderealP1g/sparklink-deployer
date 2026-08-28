# Runbook

## Before install

- Use a fresh Ubuntu 24.04 x86_64 VPS with console/rescue access.
- Confirm the intended SSH port and keep the existing SSH session open.
- Select Recommended or Custom. Only enable CDN when a CDN fallback is actually needed;
  only enable active AnyTLS when it is intended as a user-facing entry.
- Complete the Cloudflare handoff only for a selected CDN capability and verify its DNS record.
- Optionally create a current local SNI report, then select `auto`, a manual hostname, or
  the configured default in the install wizard. Treat reports older than seven days as stale.
- Run `sparklinkctl plan` and retain its output.
- Do not proceed if the preflight reports an existing proxy stack or a port collision.

## Existing-host inventory

For the three existing VPSes, use the normal Windows SSH aliases with
`inventory-collect`. The collector reads OS, binary/service state, listeners, known marker
paths, and SHA-256 fingerprints only; it does not read configuration bodies or secrets and
does not restart anything. Review `adopt-plan` output before considering any migration.
RackNerd/x-ui, VMISS/x-ui plus sing-box/WireProxy, and DediRock systemd layouts are
reported separately as recognized layouts. There is no generic `adopt-apply`; a recognized
host is not thereby registered with a future Control Plane.

## Acceptance

Server checks are necessary but not sufficient:

1. Every selected service is active/enabled; standby sing-box is installed but intentionally stopped.
2. Every rendered core and selected reverse proxy configuration passes syntax checks.
3. When HyTru is selected, WireProxy readiness is healthy; TCP and SOCKS5 UDP pass; Cloudflare trace says `warp=on`.
4. Native and HyTru exits differ. Native is the VPS exit; HyTru is treated as dynamic.
5. Every generated private client entry completes its intended real request from an isolated client.
6. When CDN is selected, a non-Cloudflare source cannot connect to the CDN origin port.
7. Reboot the VPS and repeat the applicable checks from a new SSH session.

Hysteria2 is Custom-only. Its rendered sing-box UDP/QUIC listener and Salamander obfuscation
are structurally checked, but real client connectivity, UDP behavior, and reboot recovery
must be accepted on a disposable host before production rollout.

## Rollback

Every install transaction records touched paths and pre-change copies under
`/var/backups/sparklink-deployer/<transaction-id>`. Rollback stops managed services,
restores recorded files, reloads systemd, and reports package changes that require manual
review. Never point rollback at an arbitrary path.
