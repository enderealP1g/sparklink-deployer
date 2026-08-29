# Fresh-host production acceptance: `hypro02`

> This is a dated acceptance record for the fresh-host run on 2026-08-29. It is not a
> permanent statement of current runtime state and does not register the host with a
> SparkLink Control Plane or promote it to a Resource Pool.

## Scope

The run covered the Deployer's first real fresh-host installation and reboot acceptance
for the new candidate Node. Existing SparkLink VPSes were used only as read-only probe
vantages. No user Portal, billing, subscription, or metering implementation was added.

## Preflight

- Supported fresh-host contract: Ubuntu 24.04.1, x86_64, systemd, SSH with non-interactive
  sudo, and no pre-existing proxy stack or selected-port collision.
- Baseline firewall state was inactive and was restored on failed install attempts.
- The direct and CDN hostnames resolved to the candidate host as `DNS only` for certificate
  issuance. After deployment, only the CDN hostname was switched to `Proxied`.

## Installed topology

- Xray `26.7.28` is the active primary core and listens on TCP `443`.
- sing-box `1.13.16` is rendered and syntax-checked as standby; it remains stopped.
- WireProxy `1.1.3` provides loopback Native/HyTru egress services on the configured
  loopback ports.
- Nginx `1.24.0` serves the CDN origin on TCP `2053` and the ACME HTTP path on TCP `80`.
  The CDN origin is restricted by UFW to the official Cloudflare IPv4/IPv6 ranges.
- The CDN configuration uses hostname-scoped Strict TLS, origin port `2053`, and cache
  bypass. The direct hostname remains `DNS only`.

## Acceptance evidence

- Final installer transaction completed as `20260829T012706Z`; its rollback manifest is
  present under the Deployer rollback root on the host.
- Server verification passed before reboot and from a new SSH session after reboot:
  core/reverse-proxy syntax, service state, WireProxy readiness, HyTru TCP/UDP, Native
  trace, exit separation, and four generated delivery entries.
- Isolated client probes passed for `Origin-Reality`, `HyTru-Reality`, `Origin-CDN`, and
  `HyTru-CDN`. Cloudflare trace reported `warp=off` for Native and `warp=on` for HyTru;
  the observed exit fingerprints differed.
- Isolated SOCKS5 UDP DNS probes passed for `Origin-Reality` and `HyTru-Reality` after
  reboot. The CDN TCP probes passed through the Cloudflare edge.
- Three application-layer Cloudflare trace probes per path succeeded (`3/3`). The
  observed total-time ranges were approximately `0.905–1.307 s` for the direct paths and
  `1.276–2.343 s` for the CDN paths. This is a small latency baseline, not a throughput
  or packet-loss measurement.
- Independent read-only probes from two existing VPS vantage points could not connect to
  the CDN origin port. The Windows control host was not used as the sole firewall probe
  because its active `xray_tun` could use a Cloudflare egress.

## Service-access limits and negative evidence

- The earlier QQG Native preflight returned policy-level `403` responses for OpenAI and
  Anthropic. This remains negative evidence and is not overridden by the Deployer PASS.
- Through the isolated Xray paths, OpenAI and Anthropic returned unauthenticated `401`,
  Gemini returned `403`, Google AI returned `200`, and Google returned `204`. These results
  establish endpoint reachability for this probe; they do not establish account-level
  authorization or product suitability.
- Sustained throughput, a packet-loss baseline, independent China-direction routing and
  `9929` evidence, provider package/cycle facts, and longer-duration stability remain
  `Unknown / Needs Verification`.

## Acceptance-driven fixes

- Normalize a WARP registration endpoint with port `0` to the standard `2408` port and
  reject other invalid endpoint ports.
- Preserve the pre-install UFW active/inactive state during installer rollback.
- Include `certbot.timer` in managed-service rollback and import the existing client-link
  renderer required by runtime verification.
- Reload Nginx after final CDN activation so the live `2053` listener matches the checked
  configuration. The installed host required one manual reload during acceptance; the
  installer and regression test now encode the corrected sequence.

## Qualification status

Deployer fresh-host acceptance: **PASS**.

`hypro02` PREMIUM qualification: **CONDITIONAL**. The tested Xray direct/CDN and HyTru
transport paths are operational, but the available evidence does not yet establish the
full SparkLink Pro/Premium user-experience target. No Resource Pool promotion is implied
by this record.

AnyTLS remains an installable Deployer capability, but it is not accepted as a formal
user-facing service surface without reliable per-user accounting and stable User
attribution.
