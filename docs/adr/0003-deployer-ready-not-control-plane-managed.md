# ADR-0003: Deployer-ready is not Control-Plane-managed

## Context

Single-host evidence and future global fleet governance are different facts.

## Decision

Use `recognized host`, `known deployment layout`, `sparklink-deployed`, and `deployer-ready`
for local Deployer evidence. Do not use `managed`, `registered`, or `Unified Management`
for that evidence.

## Why

It prevents a local inventory or descriptor from being mistaken for a future Control Plane
Node registration or operational-state assertion.

## Consequences

The CLI uses `inventory-status`; adoption remains planning-only. Any future registration
workflow requires a separately designed Control Plane contract.
