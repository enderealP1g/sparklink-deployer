# ADR-0001: Xray primary, sing-box disaster-recovery baseline

## Context

SparkLink carries Xray and sing-box assets, but protocol presence does not mean equal
production status.

## Decision

Xray remains the production primary. sing-box is the disaster-recovery and technology-hedge
baseline; AnyTLS is its current replaceable DR capability.

## Why

This preserves the validated primary path while keeping an independently renderable fallback
without presenting standby code as an active user entry.

## Consequences

Recommended profiles expose Xray first. sing-box may be installed, checked, and stopped as
standby; activation and delivery require an explicit Custom choice and later acceptance.
