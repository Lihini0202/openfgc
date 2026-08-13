# OpenFGC BFF Agent Guide

This is the shared agent policy for `portal/backend`.

## Scope

- Go 1.26.3 BFF code under `portal/backend/**`.
- Portal-facing authentication, self-service consent endpoints, and a hardened proxy to OpenFGC.

## Core Rules

- Use Go `net/http` with method-aware `ServeMux` patterns for HTTP routing.
- Prefer Go standard library where practical.
- Avoid adding third-party packages without clear justification.
- Keep handlers focused on HTTP concerns; place upstream orchestration and business logic in services.
- Keep security-sensitive logic explicit and test-covered.
- Never log tokens, secrets, or key material.
- Use structured `log/slog` logging and avoid logging sensitive user data.
- Keep middleware composable and order-aware.
- Keep code patterns consistent with `consent-server/` when the same concern exists in both services.

## Project Structure

- Keep process startup, HTTP server construction, and dependency wiring in `cmd/server`.
- Keep feature behavior in focused packages under `internal`.
- Keep shared infrastructure and cross-cutting concerns under `internal/system`.
- Keep unit tests beside source as `*_test.go` and service-level integration tests under `tests/integration`.
- Keep the public API contract under `openapi`.

## Quality Gates

- Format changed Go code with `task fmt`.
- Before merge, run `task fmt:check`, `task lint`, `task test`, and `task build` from `portal/backend`.
- Add unit or integration coverage for new behavior and regressions.
- Prefer table-driven tests and `httptest` for HTTP behavior where practical.
- Keep tests deterministic and cover success, validation, authorization, and upstream failure paths as applicable.

## Security Baseline

- Fail closed on security-sensitive errors.
- Apply least-privilege authentication and authorization.
- Keep proxy access deny-by-default.
- Treat client-supplied identity data as untrusted.
- Preserve OIDC validation and secure cookie protections.
- Never allow placeholder identity mode in production.
- Bound requests and sanitize forwarded headers.
- Never expose sensitive data in responses or logs.

## Contracts and Documentation

- Keep `openapi/portal-backend.yaml` synchronized with route, payload, response, and error-contract changes.
- Keep `README.md`, `.env.example`, configuration structs, defaults, and validation rules synchronized.
- Preserve the documented JSON error shape and use stable, explicit error codes.
