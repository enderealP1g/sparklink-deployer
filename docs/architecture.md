# Architecture

## Traffic paths

Each protocol has two credentials. Authentication identity selects the exit; it does not
create a second public listener.

```text
VLESS REALITY ─┐
AnyTLS ────────┼─ Origin identity ── direct ── VPS native exit
VLESS CDN ─────┘

VLESS REALITY ─┐
AnyTLS ────────┼─ HyTru identity ── loopback SOCKS5 ── WireProxy ── WARP
VLESS CDN ─────┘
```

WireProxy is kept as a direct systemd main process. Its SOCKS and readiness ports bind to
loopback only. Xray and sing-box hold weak `Wants` dependencies so native users can still
start if WARP is temporarily unavailable.

## Entry boundaries

- REALITY and AnyTLS connect directly to the VPS address through the direct hostname.
- CDN clients connect to Cloudflare edge TCP/443. Cloudflare uses Strict TLS to reach the
  dedicated Nginx origin port, which proxies only the private WebSocket path to Xray.
- The CDN origin port must accept Cloudflare source ranges only.
- All three entries still terminate on one VPS. A dead VPS or unreachable origin address
  affects every entry and requires another host for real host-level failover.

## Why fresh-host-only

x-ui/3x-ui deployments may have both a database template and a separate live Xray config.
Safely adopting them requires product/version-specific migration and dual-state rollback.
The alpha refuses that risk and owns a small explicit systemd layout on a fresh server.
