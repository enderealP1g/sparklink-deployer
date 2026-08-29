# ADR-0007: Codex is Agentic Operator, not source of truth

## Context

Codex/codexop will need high-privilege reasoning and execution across VPS, Cloudflare, and
delivery systems.

## Decision

Treat Codex as the Agentic Operator: it investigates, reasons, executes approved Operations,
and verifies outcomes. Durable product and fleet facts belong outside the agent transcript.

## Why

Separating reasoning/execution from durable truth supports auditability, replay, and safe
human approval without turning a chat session into a registry.

## Consequences

Deployer remains a deterministic tool invoked by operations. This repository does not design
the future Operation API, orchestration engine, or Control Plane database.
