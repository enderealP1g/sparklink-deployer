# ADR-0008: Historical Usage survives Plan changes

## Context

Users can change Plans or Entitlements while previously consumed service remains a fact.

## Decision

Customer Billing Cycles and recorded Usage are historical; later Plan changes do not delete
or rewrite completed cycles.

## Why

Audit, billing reconciliation, refunds, and provider-cost analysis require temporal history.

## Consequences

Deployer must not purge or reinterpret historical usage when rendering, upgrading, repairing,
or planning adoption. Retention and settlement policy remain future product decisions.
