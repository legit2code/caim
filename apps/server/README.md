# Server Application

The Express server is CAIM's HTTP and trust boundary. The root `server.ts` entry imports this module, which constructs the application, applies middleware, registers API routes, and mounts Vite in development or compiled static assets in production mode.

## Responsibilities

- Load validated server configuration through `packages/config`.
- Establish request principal context and enforce authorization policies.
- Apply CSRF and rate-limit middleware to protect state-changing and high-volume requests.
- Expose health, public configuration, authentication, diagnostic, and product workflow APIs.
- Delegate domain behavior to shared packages and worker engines.
- Return structured errors and avoid exposing secrets in public configuration.

## Important files

- `../../server.ts` — root runtime entry.
- `index.ts` — Express app initialization, middleware, and route mounting.
- `../../packages/api` — typed API router, contracts, pagination, errors, adapters, and OpenAPI generation.
- `../../packages/auth` — authentication, principal context, roles, grants, CSRF, and rate limiting.
- `../../packages/config` — server and worker configuration schemas/loaders.
- `../../workers` — domain-specific analysis engines.

## Development

From the repository root:

```bash
npm install
npm run dev
```

The current configuration binds the server to port 3000. The development process uses Vite middleware for the web application.

## Runtime and persistence caveat

The current `apps/server/index.ts` bootstrap initializes `createTestDb({ applyMigrations: true, applySeed: true })`. This is an in-memory test/development database path. The PostgreSQL/Supabase architecture documents describe the target physical data model; they do not establish that this particular server bootstrap is connected to persistent production PostgreSQL. Verify the active adapter and deployment wiring before using the server for production data.

## Security rules

- Never return server-only credentials from public configuration.
- Preserve principal resolution, role/capability checks, CSRF protection, and rate limiting.
- Keep heavy analysis and secret-bearing modules out of the browser bundle.
- Treat all remote repositories and uploaded artifacts as untrusted input.
