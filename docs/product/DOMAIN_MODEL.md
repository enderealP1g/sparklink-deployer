# SparkLink Domain Model

> Status: conceptual vocabulary only, 2026-08-28. No persistence model or API is defined
> here for the future Control Plane.

| Term | Meaning | Explicit non-equivalence |
| --- | --- | --- |
| **User** | Business identity of a person or customer account | Not a proxy credential, node, or VPS |
| **Plan** | Commercial product definition | Not a direct binding to a Node |
| **Entitlement** | Time-bounded permission a User actually owns | Not the same as a Plan or credential |
| **Customer Billing Cycle** | Historical settlement window for customer usage/entitlement | Historical cycles survive later Plan changes |
| **Credential** | Independently rotated access or delivery secret | Not a User or Entitlement |
| **Infrastructure Resource** | Provider-purchased VPS resource with provider, quota, cost, renewal, and lifecycle facts | Not a Node |
| **Node** | Stable SparkLink operational identity assigned to infrastructure | Not an IP, protocol, VPS subscription, or credential |
| **Resource Pool** | Isolation boundary between Plans/Entitlements and serving Nodes | Not a single host or an implicit Plan→Node edge |
| **Usage** | Fact that consumption occurred | Customer Usage and Infrastructure Usage are different views |
| **Operation** | Control Plane/Codex operational intent or transaction context | Not a chat message or durable business truth by itself |
| **Capability** | A deployable or observable technical ability | Not automatically an entitlement or capacity guarantee |
| **Desired State** | Intended technical/service posture | Not proof that a host has reached it |
| **Observed State** | Measured host/runtime facts | Not a desired-state command or Control Plane registration |
| **Capacity** | Available/allocatable technical or commercial headroom | Not usage and not a protocol count |
| **Subscription** | Projection generated from Entitlement + Resource Pool + Serving Nodes + Credentials | Not a source of truth |

## Relationship ordering

The safe conceptual direction is:

```text
Plan -> Entitlement -> Resource Pool -> serving Node(s)
```

This preserves isolation and time boundaries. A direct `Plan -> Node` shortcut would hide
entitlement changes, pool policy, node replacement, and historical usage attribution.

## Deployer terms

- `local host inventory`: redacted evidence collected by the Deployer workspace.
- `known deployment layout`: a recognized arrangement such as x-ui/Xray or systemd
  Xray/sing-box; recognition is not approval to migrate.
- `sparklink-deployed`: a host-level label indicating a Deployer descriptor/layout was
  observed. It is not a future Node registry state.
- `deployer-ready`: a local readiness label for the next Deployer lifecycle action. It is
  not Control Plane-managed, registered, entitled, or production-accepted.
