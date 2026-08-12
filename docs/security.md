# Security model

## Assets that never enter Git

- VLESS UUIDs and AnyTLS passwords.
- REALITY private/public key pair and short ID.
- CDN private path and complete client URIs.
- WARP account token, device identity, private key, and WireProxy configuration.
- Cloudflare API tokens, private subscription URLs, certificates, and VPS backups.

Private repository visibility is defense in depth, not permission to commit these assets.
The repository secret scanner also rejects the production domain suffix from the source
tree so historical hostnames cannot accidentally return in examples.

## Installation trust

- The project lock fixes exact upstream release versions.
- Every downloaded archive must match the checksum file from the same official release.
- Archives are rejected if they contain path traversal or link entries.
- Configuration is generated into a staging transaction and validated before services are
  enabled.
- Existing proxy stacks, x-ui state, custom Nginx state, unsupported OS/architecture, DNS
  phase errors, and occupied ports stop the install.

## Remaining limits

- Upstream checksum files share the release hosting trust boundary; a future release may
  add an independently maintained checksum allowlist or signature verification.
- Cloudflare WARP is a dynamic shared exit. `warp=on` proves the tunnel path, not website
  reputation or account safety.
- The initial alpha is not production-accepted until a disposable VPS, isolated client,
  independent firewall probe, and reboot retest all pass.
- Imported SNI reports are untrusted measurements, contain no executable content, and do
  not override configuration without an interactive recommendation confirmation.
- Future VeilShift Cloudflare credentials remain local-controller-only. They must never be
  copied to a VPS, accepted as a command-line argument, logged, or committed.
