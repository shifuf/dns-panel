# DNS Panel Reliability Implementation Plan

This is the initial-stage plan. The user subsequently authorized production deployment, a real renewal cycle, platform binding updates, and Baota installation. See the [final renewal acceptance report](../../full-renewal-cycle-2026-11-14.md) for the completed scope and remaining limitations.

> **For agentic workers:** Use systematic debugging, test-driven development, and verification before completion. The user requested parallel implementation on 2026-11-14.

**Goal:** Correct incomplete Cloudflare domain listings, complete the existing Tunnel workflow, resolve Qiniu certificate deployment authentication, and audit the wider application.

**Architecture:** Keep the existing Vue 3 frontend and Python/SQLite backend. Implement independent provider fixes in parallel, with scoped edits in shared modules and a final integrated review.

**Tech Stack:** Vue 3, TypeScript, Naive UI, TanStack Query, Python standard library HTTP, SQLite.

**Spec:** The user's current request and the Tunnel scope proposed in this chat: account selection, complete listings, route validation, connection status, and actual associated DNS cleanup.

## Global Constraints

- Preserve existing data, credentials, API compatibility, and unrelated workspace changes.
- Do not persist credentials from this conversation or include them in logs/tests.
- Cloud verification is read-only or uses invalid certificate input that cannot create a resource.
- Do not publish, deploy, or modify live DNS records as part of validation.
- Apply minimal patches to shared files; keep new capabilities within the existing workflows.

## Review Focus

- Provider pagination can return fewer rows than requested while more rows remain.
- Cached domain data must refresh after credential changes and explicit refreshes.
- Tunnel public routes can share a hostname across different paths.
- Upstream authorization failures must remain visible and preserve the panel login.
- Failed transactions and request errors must release local resources.

## Task 1: Cloudflare domains

- [x] Reproduce pagination, credential selection, and cache problems using behavior tests.
- [x] Correct domain service pagination and scoped dashboard cache/loading behavior.
- [x] Inspect available local credential metadata and perform permitted read-only checks.
- [x] Verify targeted tests and document the distinction between confirmed bugs and token permissions.

## Task 2: Cloudflare Tunnel

- [x] Add behavior regressions for remote management, complete lists, route validation, and DNS cleanup.
- [x] Implement account selection, meaningful failures, mobile details, and safe route operations.
- [x] Preserve shared-hostname DNS records and unrelated ingress settings.
- [x] Verify backend tests and frontend type checks.

## Task 3: Qiniu

- [x] Compare the actual request authorization with the official SDK and reproduce invalid JSON-body signing.
- [x] Correct request signing and any confirmed certificate/CDN response handling defects.
- [x] Verify signature tests and perform a minimal live authentication check without uploading a certificate.

## Task 4: Global audit and integration

- [x] Baseline backend suite: 179 tests, one skipped, no failures; SQLite resource warnings observed.
- [x] Review authentication, request handling, persistence, backups, provider integration, frontend and release validation.
- [x] Fix additional reproducible defects with focused regression coverage.
- [x] Run all backend tests, frontend typecheck/build, and diff checks; request an independent review.
- [x] Deliver a Chinese audit report with completed fixes, verification evidence, limitations, and prioritized feature suggestions.

## Execution Notes

- Work remains in the user's existing checkout so it can be inspected immediately; no release is triggered.
- Scope and parallel execution were explicitly requested; routine implementation choices proceed without additional approval gates.
- Baseline commit: `6591bcea702827c1ffee83fcd8e88a65d7d07db7`.
- Independent review findings: archive quota failure, stale Tunnel credential caches, and Qiniu renewal disabling force HTTPS. All reproduced and fixed with regressions.
- Additional audit work: compatible dependency updates, pinned compatible vue-tsc 3.0.2; frontend npm audit reduced from 20 findings to zero.
- Final verification: backend 216 tests (one skipped), frontend 38 tests, production build including typecheck passed. See `docs/audit-2026-11-14.md` for limitations and cloud verification evidence.
