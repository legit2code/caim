# CAIM Developer Guide

This guide supplements the repository README with implementation-oriented navigation and setup details.

## 1. Understand the system before changing it

CAIM separates the product into four cooperating layers:

- **Presentation:** `apps/web` renders the user-facing workflows and engineering diagnostics.
- **HTTP boundary:** `apps/server` authenticates requests, applies middleware, and exposes APIs.
- **Domain libraries:** `packages` contains contracts, configuration, auth, data access, ontology, lifecycle, and packaging primitives.
- **Analysis workers:** `workers` contains specialized discovery, static/dynamic analysis, composition, decision, knowledge, lifecycle, and evaluation engines.

The key design rule is that the browser is not an execution environment for privileged analysis. Worker and secret-bearing code belongs behind the server boundary.

## 2. Start locally

```bash
npm install
cp .env.example .env
# Add GEMINI_API_KEY for Gemini-backed operations.
npm run dev
```

Open the local application at `http://localhost:3000`. The development server is started by `server.ts`, which imports `apps/server/index.ts`; the server mounts Vite middleware for the React application.

If startup fails, check the Node version, dependency installation, environment variable syntax, and port availability. The current server configuration sets port 3000 in code; do not assume that setting `PORT` in the example file changes the port without verifying the implementation.

## 3. Build and test

```bash
npm run typecheck
npm test
npm run build
npm run check
```

The root package scripts define the exact supported commands. In particular:
- `lint` and `typecheck` both run `tsc --noEmit`.
- `test:integration` and `test:e2e` currently target the same foundation test file.
- `check` chains typecheck aliases, tests, release checks, and the build.

Use the named test files under `src/__tests__` and package-level test directories to find the right regression suite for a change.

## 4. Configuration and secrets

Configuration schemas and loaders are in `packages/config/src/schema.ts` and `packages/config/src/loaders.ts`.

The main secret and integration settings are documented in `.env.example`. Keep credentials server-side. The public configuration loader is deliberately sanitized; do not add secret fields to its return type.

Optional providers include GitHub, Hugging Face, E2B, Sentry, and Supabase. Provider availability is determined from the presence of credentials; a configured key does not by itself prove that the remote integration is reachable or production-ready.

## 5. Domain ownership

| Concern | Primary location |
|---|---|
| Shared DTOs and event contracts | `packages/contracts`, `packages/api` |
| CAIM envelopes and invariants | `packages/caim` |
| Environment parsing and validation | `packages/config` |
| Authentication, roles, grants, vault access | `packages/auth` |
| Persistence abstractions and repositories | `packages/db` |
| Canonical concepts and normalization | `packages/ontology` |
| Analysis and evidence lifecycle | `packages/lifecycle`, `workers/lifecycle` |
| Source and artifact discovery | `workers/discovery` and source adapters |
| Static analysis and taint | `workers/static-analysis` |
| Dependency, SBOM and AI-BOM | `workers/composition` |
| Dynamic sandboxing | `workers/sandbox-orchestrator` |
| Risk and policy decisions | `workers/decision` |
| Retrieval and grounded synthesis | `workers/knowledge` |
| Golden-corpus verification | `workers/evaluation` |
| Browser workflows | `apps/web/src/components/views` |
| Engineering diagnostics | `apps/web/src/components/dev` |

Follow existing package exports and contracts rather than importing internal files across boundaries without a reason.

## 6. API and data architecture

The HTTP entrypoint and middleware are in `apps/server/index.ts`; the typed API router is in `packages/api`. Inspect the active route declarations for endpoint paths, request schemas, authorization requirements, and response envelopes before integrating a client.

The architecture documents describe the intended PostgreSQL/Supabase schemas, tenant scope inheritance, RLS, and data lifecycle. They are useful design authorities, but the current application bootstrap calls `createTestDb({ applyMigrations: true, applySeed: true })`. This in-memory path must not be confused with a persistent production database. Verify the actual database adapter and deployment wiring before making production claims.

## 7. Security invariants

- Do not import worker implementations into the browser bundle.
- Do not expose Gemini, Supabase service-role, GitHub, Hugging Face, E2B, or signing secrets to the client.
- Treat remote source code and artifacts as untrusted.
- Preserve authentication, role/capability checks, CSRF protections, and rate limiting.
- Keep tenant scope separate from security classification.
- Derived data must inherit scope from authoritative parents; callers must not choose an arbitrary tenant scope.
- Keep evidence, lineage, and audit semantics consistent with the architecture specifications.

## 8. Architecture and implementation references

- `architecture/v2/INDEX.md` establishes the architecture authority hierarchy.
- `architecture/v2/17_Physical_PostgreSQL_Supabase_Data_Architecture.md` explains the physical schema and transaction boundaries.
- `architecture/v2/21_Tenant_Scope_and_Inheritance_Architecture.md` defines tenant isolation and derived-scope rules.
- `implementation/BUILD_STATE.json`, `KNOWN_GAPS.md`, and `DECISIONS_PENDING.md` record the implementation snapshot and decision history.

Some implementation documents are snapshots with dates and status fields. Reconcile them with current source, tests, and deployment configuration before using them as a release attestation.

## 9. Change checklist

Before merging a change:

1. Identify the owning package, worker, route, or UI workflow.
2. Check the related architecture and ADR documents.
3. Update contracts and tests with the implementation.
4. Preserve browser/server/worker isolation and tenant security invariants.
5. Run typecheck, relevant tests, release checks, and build.
6. Update the README or domain documentation if setup, configuration, routes, scripts, or runtime assumptions changed.
