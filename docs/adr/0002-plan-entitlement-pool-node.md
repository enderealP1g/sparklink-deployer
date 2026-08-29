# ADR-0002: Keep Plan → Entitlement → Resource Pool → Node ordering

## Context

A commercial Plan does not directly describe which infrastructure is serving a User at a
given time.

## Decision

Model the conceptual relationship as Plan → Entitlement → Resource Pool → serving Node(s).

## Why

Entitlement time windows and pool isolation explain node replacement, allocation policy, and
historical attribution without coupling a product definition to one machine.

## Consequences

Deployer may describe host capabilities, but it must not invent a Plan-to-Node binding or
claim that an inventory created an entitlement or registry relationship.
