# Web Application

The web client is the React single-page application for CAIM's agent lifecycle and security-analysis workflows. Its entrypoint is `src/main.tsx`, which renders `apps/web/App.tsx`.

## User-facing areas

The application groups domain workflows into screens for agent/library management, discovery, analysis, evidence, risk and policy, governance, knowledge retrieval, modification, packaging, observability, operations, evaluation, production hardening, and traceability. The concrete screen components are in `src/components/views/`.

Engineering-only diagnostics are implemented under `src/components/dev/` and are protected by server-side authorization. Shared authentication context and API client helpers are under `src/context/` and `src/lib/`.

## Development

Run the application through the root Express/Vite development server:

```bash
npm install
npm run dev
```

The root server serves the React app through Vite middleware during development. For a production client build, run `npm run build` from the repository root; Vite writes the browser assets to `dist/`.

## Architecture boundary

The browser must call bounded `/api/*` server endpoints for privileged operations. It must not import `workers/*`, private signing material, server configuration, or provider secrets. The Vite isolation plugin and architecture tests help enforce this rule.

## Implementation notes

- React and TypeScript power the UI.
- Tailwind CSS provides styling; Lucide icons and Motion are used in the interface.
- The main navigation and workflow component wiring are in `App.tsx`.
- Authentication UI includes login, signup, email verification, and password-change flows.
- The UI is a client of the API; it is not the source of truth for authorization or tenant scope.
