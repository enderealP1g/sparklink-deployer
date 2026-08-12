# REALITY target selection

SparkLink 0.2 treats REALITY target selection as a measured, user-confirmed choice.
It does not claim that a public list contains one globally best SNI.

## What is measured

For every candidate the scanner:

- resolves DNS and rejects loopback, private, link-local, and other non-public addresses;
- performs repeated certificate-verified TLS handshakes on TCP/443;
- records success rate, median handshake latency, TLS versions, ALPN, public target
  addresses, and certificate DNS names;
- requires reliable TLS 1.3 before marking a candidate eligible;
- warns and reduces the heuristic score when Cloudflare target behavior is detected.

No report records the public IP address of the computer or VPS running the scan. Reports
contain public target addresses and network timing, so they still belong in ignored local
output rather than source control.

## Local scan

Run this from the network and computer that will use the node:

```powershell
.\sparklinkctl.ps1 reality-scan `
  --config config\host.json `
  --candidates config\reality-sni-candidates.txt `
  --vantage local-windows `
  --output build\sni\local.sni-report.json
```

Edit `config/reality-sni-candidates.txt` to add region-relevant candidates. A candidate
may be a hostname or `hostname:443`; other ports are rejected.

## Interactive VPS install

Copy the optional local report to the fresh VPS with the source tree, then run:

```bash
sudo ./install.sh --config config/host.json \
  --local-sni-report build/sni/local.sni-report.json
```

The installer asks for the direct hostname, CDN hostname, ACME email, and REALITY SNI:

- Press Enter at the SNI prompt to keep the configured default.
- Enter a hostname to use it manually.
- Enter `auto` to scan from the VPS and rank the intersection with the local report.

For combined ranking, the VPS score has 65% weight and the local score has 35%. Only a
candidate eligible from both measured vantage points is labeled a dual-vantage pass. If
no local report is supplied, the output clearly says that the ranking is VPS-only.

The recommended result is shown before it is written. The user can accept it, return to
the configured default, or type a different hostname.

## Limits

This scanner is a preselection tool, not final proof. It does not yet measure ASN
similarity or run Xray's own `xray tls ping`, and it cannot validate end-to-end REALITY
until the node exists. Production acceptance still requires a real client test and a
post-reboot retest.

Official Xray guidance normally keeps `serverNames` consistent with names accepted by
the target certificate and recommends borrowing a target in the same ASN. It also warns
that unauthenticated traffic is forwarded to `target`; a Cloudflare-backed target can
therefore expose the VPS as an unwanted forwarder. The scanner warning must not be read
as permission to ignore that risk.

Reference: [official Xray REALITY documentation](https://xtls.github.io/en/config/transports/reality.html).
