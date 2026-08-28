# SparkLink Responsibility Map

> Status: product vocabulary baseline, 2026-08-28. “Future Control Plane” means a reserved
> responsibility boundary, not an implementation commitment in this repository.

| Area | Owns | Does not own |
| --- | --- | --- |
| Business | User, Plan, Entitlement, Customer Billing Cycle, commercial rules | VPS listeners, protocol credentials, host health |
| Future Control Plane | Node identity, Resource Pool relationships, Desired/Operational State, Capacity, Usage views, Operation intent | Root execution, protocol rendering, direct SSH mechanics |
| Codex/codexop Agentic Operations | Reasoning, approved execution, cross-system investigation, repair, and verification | Durable business/fleet source of truth; unapproved mutation |
| SparkLink Deployer | Single-VPS inspect, deploy, configure, verify, upgrade, repair, rollback, local inventory, adoption planning | Fleet orchestration, entitlement decisions, billing, Control Plane registration |
| Data Plane | Xray, sing-box, WARP, REALITY, AnyTLS, HY2, CDN transport behavior and runtime counters | User identity, Plan membership, Node registry, commercial usage meaning |
| Metering | Collection and attribution of usage facts with explicit perspective | Deciding plans, issuing credentials, or silently changing entitlements |

## Operational interpretation

- `sparklink-deployed` means a host exposes a Deployer-generated descriptor or otherwise
  matches a Deployer-owned layout. `deployer-ready` means a local plan has enough evidence
  for the next Deployer review step. Neither phrase means Control Plane-managed.
- `recognized host` and `known deployment layout` are evidence labels. They may be used in
  `adopt-plan` output without creating a Node record or changing the remote host.
- `node-descriptor.json` is a credential-free Deployer artifact. Its fields are intentionally
  descriptive and must not be treated as a future Control Plane Node schema.
- A `Subscription` is a delivery projection assembled from entitlement, pool, serving-node,
  and credential facts. It is not the source of truth for any of those objects.
