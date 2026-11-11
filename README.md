# CAIM — Agent Lifecycle Intelligence Platform

CAIM (Common Artifact Intelligence Model) is the shared artifact and ontology foundation for an agent lifecycle intelligence platform. The repository combines a React analyst console, an Express API, analysis workers, domain packages, and architecture/implementation specifications for discovering, inspecting, evaluating, governing, and packaging AI agents and their artifacts.

> **Documentation scope:** This guide describes the code and configuration currently present in this repository. Architecture specifications describe the intended V2.0.1 target; they are not, by themselves, proof that every external service or production deployment is connected.

## What the platform is for

The codebase is organized around a lifecycle that can be summarized as:

1. **Discover and ingest** agent repositories and related artifacts.
2. **Normalize identity and syntax** into canonical records and structured representations.
3. **Analyze** source code, control flow, data flow, dependencies, capabilities, and runtime behavior.
4. **Assemble evidence and decisions** with provenance, confidence, risk, and policy context.
5. **Retrieve grounded knowledge** from indexed material and cite supporting evidence.
6. **Manage lifecycle changes** through versioning, comparison, validation, and remediation workflows.
7. **Package and attest** outputs using deterministic manifests and cryptographic signing boundaries.
8. **Evaluate and observe** the platform with tests, telemetry, audit records, and operational diagnostics.

The intended users include security analysts, platform operators, developers, reviewers, and release approvers. The web application groups the workflows into an analyst-facing console and separate engineering diagnostics.

## Repository architecture

```text
.
├── apps/
│   ├── server/              # Express application and API surface
│   └── web/                 # React application and workflow views
├── packages/
│   ├── api/                 # API contracts, router, adapters, OpenAPI
│   ├── auth/                # Authentication, roles, grants, CSRF, rate limiting
│   ├── caim/                # Common Artifact Intelligence Model
│   ├── config/              # Typed configuration and secret boundaries
│   ├── contracts/           # Shared domain contracts and envelopes
│   ├── db/                  # Database types, repositories, migrations
│   ├── lifecycle/           # Lifecycle state and validation logic
│   ├── ontology/             # CANE normalization and concept mappings
│   └── packaging/           # Bundling, manifests, SBOM, signing and verification
├── workers/
│   ├── discovery/            # Source discovery
│   ├── semantic/             # Syntax and semantic processing
│   ├── static-analysis/      # CFG, call graph, rules and taint analysis
│   ├── composition/          # Dependency, SBOM and AI-BOM analysis
│   ├── sandbox-orchestrator/ # Runtime sandbox coordination and evasion signals
│   ├── decision/             # Risk, scoring, policy and recommendations
│   ├── knowledge/            # Retrieval, embeddings and grounded synthesis
│   ├── lifecycle/            # Differential analysis and lifecycle operations
│   └── evaluation/           # Golden-corpus evaluation
├── docs/
│   ├── architecture/v2/      # Controlled architecture specifications
│   └── implementation/       # Build state, decisions and known gaps
├── src/                      # App bootstrap, shared styles and platform tests
├── supabase/                 # SQL migrations and database assets
├── tests/                    # Cross-package and integration tests
├── scripts/                  # Build, verification and release utilities
└── server.ts                 # Development/server entry point
```

The exact set of package folders and files can evolve. Use the repository tree as the source of truth when navigating.

## Technology stack

- **Runtime:** Node.js and TypeScript (the original project README specifies Node.js 20 or newer).
- **Web:** React 19, Vite 6, Tailwind CSS 4, Lucide icons, and Motion.
- **API:** Express 4.
- **Validation/contracts:** Zod 4.
- **AI integration:** Google GenAI SDK; Gemini model names and limits are configurable.
- **Analysis/runtime integrations:** E2B is an optional sandbox provider; GitHub and Hugging Face adapters are optional.
- **Tests/build:** Vitest, TypeScript, Vite, esbuild, and tsx.
- **Data architecture:** PostgreSQL/Supabase and pgvector are specified in the V2 architecture; see the runtime caveat below.

The dependency manifest is authoritative for exact package versions.

## Getting started

### Prerequisites

- Node.js 20 or later.
- npm (the repository includes an npm lockfile); pnpm workspace metadata is also present.
- A Gemini API key for server-side AI features. External provider credentials are optional until their integrations are used.

### Install and run

```bash
npm install
npm run dev
```

The root `server.ts` entry imports `apps/server/index.ts`. The Express application creates a Vite middleware server for the client in development. The current server configuration binds to port **3000**.

### Build and run the production bundle

```bash
npm run build
npm start
```

The build compiles the browser app with Vite and bundles the server entry with esbuild to `dist/server.cjs`. `npm start` runs that server bundle.

### Available package scripts

| Command | What it does |
|---|---|
| `npm run dev` | Starts the TypeScript server entry with tsx. |
| `npm run build` | Builds the Vite client and esbuild server bundle. |
| `npm start` | Runs `dist/server.cjs`. |
| `npm run preview` | Runs Vite's static preview server. |
| `npm run lint` | Runs TypeScript with `--noEmit`; it is currently a typecheck alias, not a separate ESLint pass. |
| `npm run typecheck` | Runs TypeScript with `--noEmit`. |
| `npm test` | Runs the Vitest suite. |
| `npm run test:integration` | Runs `src/__tests__/foundation.test.ts`. |
| `npm run test:e2e` | Also currently runs `src/__tests__/foundation.test.ts`; it is not a separate end-to-end suite yet. |
| `npm run release:check` | Runs the release verification script. |
| `npm run check` | Runs lint, typecheck, tests, release check, and build. |

Run `npm run` to confirm the scripts available in your checkout before relying on a command copied from older project notes.

## Configuration

Copy `.env.example` to `.env` and replace placeholders locally. Never commit real credentials.

| Variable | Purpose |
|---|---|
| `NODE_ENV` | Runtime mode (development, test, staging, production). |
| `APP_URL` | Public application URL used in generated configuration. |
| `GEMINI_API_KEY` | Server-side Gemini access; keep it out of browser code. |
| `GEMINI_MODEL_DEFAULT`, `GEMINI_MODEL_PRO` | Default and higher-capability Gemini model identifiers. |
| `GEMINI_MODEL_EMBEDDING` | Embedding model identifier. |
| `MODEL_TEMPERATURE`, `MODEL_MAX_OUTPUT_TOKENS` | Model generation settings. |
| `SIGNING_KEY_ID`, `SIGNING_ALGORITHM` | Signing key metadata. |
| `SIGNING_PRIVATE_KEY`, `SIGNING_PUBLIC_KEY` | Signing material; private keys must be protected and never committed. |
| `GITHUB_TOKEN`, `HUGGINGFACE_API_KEY`, `E2B_API_KEY`, `SENTRY_DSN` | Optional external integrations. |
| `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | Optional Supabase connection credentials. |
| `FEATURE_*` | Feature switches for sandboxing, evasion detection, taint analysis, RAG, monitoring, remediation, and AI-BOM. |

Configuration is parsed and validated in `packages/config`. `getPublicConfig()` intentionally returns a browser-safe subset and must remain free of secrets.

## Main workflows and subsystems

- **Discovery and identity:** source adapters, web discovery, candidate classification, identity resolution, and recursive expansion.
- **Syntax and static analysis:** language parsing, protocol/framework/config extraction, control-flow graphs, call graphs, rule evaluation, and taint propagation.
- **Composition intelligence:** package-manifest parsing, dependency reachability, vulnerability/advisory correlation, SBOM and AI-BOM generation.
- **Dynamic analysis:** sandbox providers, scenario execution, network controls, synthetic targets, and static-versus-dynamic comparison.
- **Decision intelligence:** capability reconciliation, risk analysis, score models, policy gates, and recommendations.
- **Knowledge and RAG:** chunking, embeddings, hybrid retrieval, reranking, context assembly, citation handling, and grounding validation.
- **Lifecycle and packaging:** version-aware changes, validation, deterministic bundles, manifests, SBOMs, signing, and verification.
- **Evaluation and operations:** golden-corpus checks, queues, audit, observability, traceability, and release checks.

The browser application is assembled from `apps/web/App.tsx` and workflow components under `apps/web/src/components/views`. Engineering diagnostics live under `apps/web/src/components/dev`.

## API and application boundaries

The Express application is bootstrapped by `apps/server/index.ts`. It owns authentication context, CSRF and rate-limit middleware, API handlers, and Vite/static-file integration. API and domain packages provide shared routers and service logic.

The web bundle must communicate with analysis and privileged services through server APIs. It must not import worker implementations or server-only secrets directly. The Vite configuration and architecture tests enforce this separation.

For the exact route implementation, inspect `apps/server/index.ts` and the route registrations in the current checkout. The server exposes health and public-configuration endpoints; the complete API surface is broader and should be documented from the active route definitions rather than inferred from this overview.

## Data model and architecture

The V2.0.1 architecture describes a multi-schema PostgreSQL model with separate areas for security, core identity, source acquisition, ontology, analysis, intelligence/evidence, knowledge, lifecycle, operations, and a curated API schema. Tenant scope and security classification are separate controls. Derived records inherit scope from their authoritative parents.

Start with:

- [Architecture index](architecture/v2/INDEX.md)
- [Physical PostgreSQL/Supabase architecture](architecture/v2/17_Physical_PostgreSQL_Supabase_Data_Architecture.md)
- [Tenant scope and inheritance](architecture/v2/21_Tenant_Scope_and_Inheritance_Architecture.md)
- [Logical ERD](architecture/v2/10_Logical_ERD.md)
- [Physical database dictionary](architecture/v2/18_Physical_Database_Dictionary.md)

**Runtime caveat:** the current `apps/server/index.ts` bootstrap initializes a migrated and seeded `createTestDb()` instance. That is an in-memory test/development database path, not proof of a persistent production PostgreSQL deployment. Treat the SQL architecture and any release-status claims separately from the active server bootstrap. Before production use, verify the database adapter, migrations, tenant isolation, secrets, and external providers in the actual target environment.

## Tests and quality checks

Run:

```bash
npm test
npm run typecheck
npm run build
npm run check
```

Tests are organized under `src/__tests__`, package-specific test folders, and the top-level `tests/` tree. The test names indicate coverage for API contracts, migrations, auth/RLS, discovery, syntax, static analysis, taint, composition, sandboxing, decision policies, RAG, packaging, observability, traceability, and production hardening.

The repository's scripts currently map `test:integration` and `test:e2e` to the same foundation test file. Do not describe those aliases as independent test suites until the scripts are changed.

## Security and operational guidance

- Keep API keys, database URLs, service-role keys, JWT secrets, and private signing keys in a secret manager or local untracked environment file.
- Never expose server-side credentials through Vite variables or public configuration.
- Treat discovered repositories and uploaded artifacts as untrusted input.
- Preserve worker/server/client package boundaries.
- Validate scope and classification on every data access path.
- Use least-privilege credentials for database and external providers.
- Do not enable production traffic based only on a successful local build or a documentation status field.

## Documentation map

- [Developer guide](DEVELOPER_GUIDE.md) — setup, architecture, configuration, tests, and operational caveats.
- [Architecture specifications](architecture/v2/INDEX.md) — governed design documents.
- [Implementation build state](implementation/BUILD_STATE.json) — recorded implementation snapshot.
- [Known gaps](implementation/KNOWN_GAPS.md) — implementation and verification notes.
- [Pending decisions](implementation/DECISIONS_PENDING.md) — ADR status and resolved decisions.

## Contributing

1. Read the architecture index and relevant decision records before changing a domain boundary.
2. Keep changes within the owning package or worker.
3. Add or update tests for behavior and security invariants.
4. Run the relevant test suite, typecheck, and build.
5. Update documentation when scripts, environment variables, API behavior, data contracts, or operational assumptions change.

