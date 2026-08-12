# VeilShift™ local-controller roadmap

VeilShift™ automation is future scope. Version 0.2 prepares the installation boundary
but does not read or use a Cloudflare credential.

## Credential boundary

- Cloudflare credentials stay on the user's Windows controller and never reach a VPS.
- Prefer a narrowly scoped API token. A legacy Global API Key may be supported only as
  an explicit fallback requested by the user.
- Read credentials from a secure prompt, Windows credential storage, or an ignored local
  secret file. Never accept them in a command-line argument, print them, write them to a
  scan report, commit them, or include them in client delivery artifacts.
- Clear credential material from process memory as far as the runtime permits after use.

## Future hostname-scoped flow

The future controller may create or update only the selected VeilShift hostname, Worker
route, and hostname-specific settings. It must show a dry-run plan and verify each item
independently. Zone-wide TLS mode, unrelated DNS records, existing Worker routes, current
memberships, and existing VeilShift subscriptions remain out of scope unless separately
approved.

Cloudflare Anycast addresses are entry paths, not proof of a fixed website-visible exit.
VeilShift labels and acceptance must continue to distinguish entry capability from the
Origin or HyTru egress used behind it.
