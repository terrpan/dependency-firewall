# Policy Engine

## Objective

Evaluate whether a normalized artifact request should be allowed or denied.

## Inputs
- normalized access request
- enriched metadata
- policies for the tenant

## Output
- allow or deny decision
- matched policy identifier
- user-facing reason
- full set of logged reasons

## Core rules
1. Deny overrides allow.
2. Return the first user-facing deny reason.
3. Log all matched reasons for diagnostics and audit.
4. Keep evaluation deterministic.

## Initial policy types
- minimum package age
- CVSS threshold
- block mutable latest tag
- allowlist or blocklist by namespace or repository

## Non-goals
- no inline artifact scanning
- no deep dependency graph resolution
