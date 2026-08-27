# Agent Lifecycle Intelligence Platform (CAIM V2.0.1)

Controlled Implementation Baseline for Agent Lifecycle Intelligence, Security Analysis, AI-BOM, Sandboxing, and 71-Engine Verification.

## Architecture & Monorepo Topology
```text
apps/
  web/                  # React + TypeScript client UI
  server/               # Node.js + Express bounded API
workers/
  discovery/            # Source & Web discovery
  semantic/             # AST, grammar, protocol analysis
  static-analysis/      # CFG, call-graph & taint analysis
  composition/          # SBOM, AI-BOM & dependency reachability
  sandbox-orchestrator/ # Isolated execution & evasion telemetry
  decision/             # Risk, claims, confidence & policy gates
  knowledge/            # Corpus, embedding & hybrid RAG
  lifecycle/            # State machine & differential analysis
  evaluation/           # Golden corpus & regression verification
packages/
  contracts/            # Shared Zod schemas & DTOs
  config/               # Typed configuration & secret boundaries
  database/             # Database clients & repositories
  caim/                 # Common Artifact Intelligence Model definitions
  ontology/             # Agent ontology mappings
  provenance/           # Raw provenance & fingerprinting
  lineage/              # Universal lineage graph
  events/               # Outbox, events & queue contracts
  security/             # Signing, attestation & boundary checks
  observability/        # OpenTelemetry & structured metrics
  testing/              # Test utilities & fixtures
```

## Quick Start & Local Commands

### Prerequisites
- Node.js >= 20.0.0
- npm or pnpm

### Commands
```bash
# Install dependencies
npm install

# Run local development server (Express + Vite on port 3000)
npm run dev

# Run strict type checking across all modules
npm run typecheck

# Run linter
npm run lint

# Run unit tests
npm test

# Run integration tests
npm run test:integration

# Run e2e tests
npm run test:e2e

# Run production build
npm run build

# Run all checks (typecheck + lint + test + build)
npm run check
```
