# ADR-0004: Subscription is a projection, not source of truth

## Context

Client delivery changes as entitlements, pools, serving Nodes, or credentials change.

## Decision

Treat Subscription as a generated projection of Entitlement + Resource Pool + Serving Nodes
+ Credentials.

## Why

Regenerating delivery from durable facts avoids making an opaque client artifact the authority
for access or resource relationships.

## Consequences

Deployer may render private delivery links, but it does not own entitlement truth or turn a
subscription file into a registry record.
