# Cloudflare handoff

Cloudflare credentials stay on the Windows control machine. The alpha uses two phases so
HTTP-01 certificate issuance never needs a Cloudflare token on the VPS.

## Before VPS install

1. Create the direct hostname as `DNS only` and point it to the new VPS.
2. Create the future CDN hostname as `DNS only` and point it to the same VPS.
3. Confirm both resolve to the VPS native IPv4. Do not enable the CDN origin-port rule yet.

The strict VPS preflight rejects a proxied CDN hostname at this stage.

## After VPS install

1. Keep the direct hostname as `DNS only`.
2. Switch only the CDN hostname to `Proxied`.
3. Apply Strict origin TLS only to the CDN hostname.
4. Map CDN edge HTTPS to the configured origin port (default `2053`).
5. Bypass cache only for the CDN hostname.
6. Preserve unrelated hostnames and zone-wide SSL settings.

The VPS firewall must allow the CDN origin port only from Cloudflare's current official
IPv4 and IPv6 ranges. Do not use the Windows host as the only firewall probe while it is
connected through WARP; confirm from an independent non-Cloudflare source.
