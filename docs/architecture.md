# Architecture

## Capability profiles

`DeploymentConfig` schema 2 separates reusable capability assets from the profile chosen
for one VPS. Recommended enables Xray Reality with Native and HyTru identities. Custom can
add active AnyTLS, CDN fallback, or the Custom-only Hysteria2 capability.

sing-box is installed and configuration-checked as a standby core in Recommended, but its
public listener remains disabled until explicitly selected in Custom.

## Local host inventory and adoption boundary

The Deployer workspace can collect a redacted inventory over the operator's existing SSH
alias and produce an `adopt-plan`. The report distinguishes the recognized x-ui/Xray,
x-ui/Xray/sing-box, and systemd Xray/sing-box families, records config fingerprints and
listeners, and lists capability gaps and backup points. It is deliberately not a generic
migration renderer: `adopt-apply` is not implemented in this release. If later approved,
it must be a host-specific adapter with a transaction journal. The local operator workspace
stores only inventory and descriptors under `.sparklink/hosts`; SSH keys, subscriptions,
and runtime secrets remain outside the repo.

## Traffic paths

Each protocol has two credentials. Authentication identity selects the exit; it does not
create a second public listener.

```text
Xray VLESS REALITY ─┐
AnyTLS / CDN (opt.) ┼─ Origin identity ── direct ── VPS native exit

Xray VLESS REALITY ─┐
AnyTLS / CDN (opt.) ┼─ HyTru identity ── loopback SOCKS5 ── WireProxy ── WARP
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

## Node descriptor

Every rendered bundle includes a public, secret-free `node-descriptor.json` describing the
deployment mode, enabled capabilities, primary/standby core, egress semantics, versions,
health state, and metering readiness. It is a Deployer artifact describing one host's
observed/rendered state, not a Control Plane Node registry record or a subscription.

## Why fresh-host-only

x-ui/3x-ui deployments may have both a database template and a separate live Xray config.
Safely adopting them requires product/version-specific migration and dual-state rollback.
The alpha refuses that risk and owns a small explicit systemd layout on a fresh server.
