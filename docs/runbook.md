# Runbook

## Before install

- Use a fresh Ubuntu 24.04 x86_64 VPS with console/rescue access.
- Confirm the intended SSH port and keep the existing SSH session open.
- Complete the Cloudflare handoff and verify both DNS records.
- Optionally create a current local SNI report, then select `auto`, a manual hostname, or
  the configured default in the install wizard. Treat reports older than seven days as stale.
- Run `sparklinkctl plan` and retain its output.
- Do not proceed if the preflight reports an existing proxy stack or a port collision.

## Acceptance

Server checks are necessary but not sufficient:

1. Xray, sing-box, Nginx, WireProxy, watchdog timer, and Certbot timer are active/enabled.
2. Xray, sing-box, and Nginx configuration syntax checks pass.
3. WireProxy readiness is healthy; TCP and SOCKS5 UDP pass; Cloudflare trace says `warp=on`.
4. Native and HyTru exits differ. Native is the VPS exit; HyTru is treated as dynamic.
5. All six private client entries complete real TCP and UDP requests from an isolated client.
6. A non-Cloudflare source cannot connect to the CDN origin port.
7. Reboot the VPS and repeat steps 1 through 6 from a new SSH session.

## Rollback

Every install transaction records touched paths and pre-change copies under
`/var/backups/sparklink-deployer/<transaction-id>`. Rollback stops managed services,
restores recorded files, reloads systemd, and reports package changes that require manual
review. Never point rollback at an arbitrary path.
