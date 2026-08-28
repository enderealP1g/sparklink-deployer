# ADR-0006: Infrastructure Resource is not Node

## Context

Provider lifecycle facts (quota, cost, renewal, and replacement) differ from SparkLink's
stable operational identity.

## Decision

Keep Infrastructure Resource and Node conceptually separate. A Node is an operational label
assigned to a resource, not its IP, protocol, or provider subscription.

## Why

The distinction survives IP changes, provider replacement, multi-protocol deployment, and
resource retirement.

## Consequences

`node-descriptor.json` describes the current host deployment only; it cannot establish
ownership, billing, capacity, or a future Node registry identity.
