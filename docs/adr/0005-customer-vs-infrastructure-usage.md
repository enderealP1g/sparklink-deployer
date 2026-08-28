# ADR-0005: Customer Usage and Infrastructure Usage are separate views

## Context

The same traffic can be attributed to a customer-facing entitlement and to provider-facing
resource consumption.

## Decision

Keep Customer Usage and Infrastructure Usage as distinct usage perspectives over shared facts.

## Why

Billing, entitlement visibility, provider cost, and capacity operations answer different
questions and have different retention/aggregation needs.

## Consequences

Deployer can expose measurement hooks and local counters, but it does not decide billing,
quotas, or the final metering backend.
