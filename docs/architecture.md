# Architecture

## Goal

Build a multi-tenant dependency firewall that acts as a policy-aware proxy for npm and OCI registries.

## Top-level shape

The system has two surfaces:

1. Data plane
   - registry-compatible proxy endpoints for package managers
   - npm and OCI protocol adapters

2. Control plane
   - management API for policies, upstreams, and evaluations
   - intended for UI and automation

## Internal layers

### Delivery
- HTTP handlers
- npm and OCI protocol parsing
- protocol-specific response rendering

### Core
- request normalization
- policy evaluation
- enrichment orchestration
- tenant-aware decision making

### Infrastructure
- PostgreSQL repositories
- Valkey cache implementations
- OSV enricher
- upstream registry clients

## Dependency direction

- delivery depends on core
- infrastructure depends on core ports and domain
- core depends on neither delivery nor infrastructure

## Main runtime flow

1. Request enters delivery layer.
2. Delivery resolves tenant and normalizes the request.
3. Core evaluates access using cache, enrichment, and policy.
4. If denied, delivery renders a protocol-specific error.
5. If allowed, delivery streams content from upstream.
