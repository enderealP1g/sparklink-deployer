# SparkLink System Map

> Status: knowledge consolidation, 2026-08-28. This document records product boundaries;
> it does not define a Control Plane API, database, or orchestration design.

## Layered view

```text
Business
  User / Plan / Entitlement / Customer Billing Cycle
       |
       v
Future Control Plane (not designed in this repository)
  Node / Resource Pool / Desired State / Operational State / Capacity
  Usage views / Operation intent
       ^                         |
       | facts                   | intent
       |                         v
Metering ------------------> Codex / codexop Agentic Operations
  Customer Usage              reasoning, execution, verification
  Infrastructure Usage              |
                                      v
SparkLink Deployer (single-VPS lifecycle toolkit)
  inspect / deploy / configure / verify / upgrade / repair / rollback
  known-host adoption planning and local host inventory
                                      |
                                      v
Data Plane
  Xray / sing-box / WARP / REALITY / AnyTLS / HY2 / CDN fallback
```

## Boundary rules

- **Deployer** owns deterministic single-host lifecycle work. It can observe and describe
  what a host is running, render a selected profile, and prepare an adoption plan. A local
  inventory is not a registration event and does not assert fleet governance.
- **Codex/codexop** is the future high-privilege Agentic Operator. It reasons over facts,
  executes approved operations, and independently verifies outcomes. It is not the durable
  source of truth for business or fleet state.
- **Control Plane** is a future product boundary for durable global facts, policy, resource
  relationships, and operation intent. Its schema and orchestration behavior are frozen here
  until separately designed and approved.
- **Data Plane** terminates and forwards traffic. Protocols and egress identities are not
  business users, entitlements, nodes, or resource pools.
- **Metering** carries usage facts from data-plane observations toward Business and the
  future Control Plane. Customer Usage and Infrastructure Usage remain distinct views.

## Current deployer state

PR1/PR2/PR3 provide profile-driven rendering, SNI preselection, Custom HY2 rendering,
secret-safe descriptors, read-only SSH inventory collection, and adoption planning. The
three existing VPSes may be recognized locally as known deployment layouts. They are not
described as Control Plane-managed or Unified Management-registered hosts.
