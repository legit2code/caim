# Documentation Index

This folder contains the governed architecture baseline and implementation records for CAIM.

## Start here

- [Developer guide](DEVELOPER_GUIDE.md) — local setup, package ownership, testing, security boundaries, and runtime caveats.
- [Architecture V2 index](architecture/v2/INDEX.md) — authority hierarchy and architecture document map.
- [Implementation build state](implementation/BUILD_STATE.json) — recorded build/verification snapshot.
- [Known gaps](implementation/KNOWN_GAPS.md) — reconciled implementation status and outstanding issues.
- [Pending decisions](implementation/DECISIONS_PENDING.md) — architectural decisions and their resolution states.

## Architecture topics

The V2 architecture set covers logical and physical data design, tenant scope, security classification, RLS, analysis/evidence relationships, lifecycle, and operational records. The architecture index identifies the authority order; read the relevant decision records before changing a locked invariant.

## Status interpretation

Implementation records are point-in-time artifacts. Confirm their timestamps and compare them with the current source, tests, runtime bootstrap, and target infrastructure. A design document or generated status report alone is not a production deployment attestation.
