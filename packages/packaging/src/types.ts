import { z } from 'zod';
import { PolicyOutcomeEnum, FindingSeverityEnum, ScoreRiskBandEnum } from '../../contracts/src/index.ts';

/**
 * P26 — Packaging, Attestation, Signing & Shipping Types
 * Architecture V2.0.1 (Document 17, 18, 21, 21B)
 */

export const PackageStatusEnum = z.enum([
  'GENERATED',
  'VALIDATED',
  'SIGNED',
  'SHIPPED',
  'DEPRECATED',
]);
export type PackageStatus = z.infer<typeof PackageStatusEnum>;

export const ShippingTargetTypeEnum = z.enum([
  'OCI_REGISTRY',
  'S3_STORAGE',
  'WEBHOOK_DEPLOYMENT',
  'LOCAL_STAGING',
]);
export type ShippingTargetType = z.infer<typeof ShippingTargetTypeEnum>;

export const ShipmentStatusEnum = z.enum([
  'PENDING',
  'IN_TRANSIT',
  'DELIVERED',
  'FAILED',
]);
export type ShipmentStatus = z.infer<typeof ShipmentStatusEnum>;

export interface PackageFileEntry {
  path: string;
  content: string | Uint8Array;
  sha256: string;
  sizeBytes: number;
  contentType: string;
  description: string;
}

export const ValidationReferenceSchema = z.object({
  validation_run_id: z.string(),
  validation_plan_version: z.string(),
  status: z.string(),
  verdict: z.string(),
  risk_reduced: z.boolean(),
  capabilities_preserved: z.boolean(),
  completed_at: z.string(),
});
export type ValidationReference = z.infer<typeof ValidationReferenceSchema>;

export const PolicyReferenceSchema = z.object({
  policy_ruleset_version: z.string(),
  policy_outcome: PolicyOutcomeEnum,
  risk_score: z.number(),
  risk_band: ScoreRiskBandEnum,
  policy_allowed: z.boolean(),
  evaluated_at: z.string(),
  override_id: z.string().optional(),
});
export type PolicyReference = z.infer<typeof PolicyReferenceSchema>;

export const ApprovalReferenceSchema = z.object({
  approval_id: z.string(),
  approver_id: z.string(),
  approver_role: z.string(),
  decision: z.enum(['APPROVED', 'REJECTED', 'PENDING', 'REVOKED']),
  decided_at: z.string(),
  rationale: z.string(),
  signature: z.string().optional(),
});
export type ApprovalReference = z.infer<typeof ApprovalReferenceSchema>;

export const ProvenanceReferenceSchema = z.object({
  engine_version: z.string(),
  ruleset_version: z.string(),
  analysis_run_id: z.string(),
  input_hashes: z.array(z.string()),
  generated_at: z.string(),
});
export type ProvenanceReference = z.infer<typeof ProvenanceReferenceSchema>;

export const PackageManifestContentEntrySchema = z.object({
  path: z.string(),
  sha256: z.string(),
  size_bytes: z.number(),
  content_type: z.string(),
  description: z.string(),
});
export type PackageManifestContentEntry = z.infer<typeof PackageManifestContentEntrySchema>;

export const PackageManifestSchema = z.object({
  schema_version: z.string().default('https://caim.security/schema/package-manifest/v1'),
  package_id: z.string(),
  agent_id: z.string(),
  agent_version_id: z.string(),
  version_label: z.string(),
  created_at: z.string(),
  manifest_hash: z.string(),
  contents: z.array(PackageManifestContentEntrySchema),
  metadata: z.object({
    author: z.string(),
    license: z.string(),
    security_classification: z.string(),
    framework: z.string(),
    description: z.string(),
  }),
  validation_reference: ValidationReferenceSchema,
  policy_reference: PolicyReferenceSchema,
  approval_references: z.array(ApprovalReferenceSchema),
  provenance_reference: ProvenanceReferenceSchema,
});
export type PackageManifest = z.infer<typeof PackageManifestSchema>;

export const InTotoSubjectSchema = z.object({
  name: z.string(),
  digest: z.record(z.string(), z.string()), // e.g. { sha256: "..." }
});
export type InTotoSubject = z.infer<typeof InTotoSubjectSchema>;

export const AttestationStatementSchema = z.object({
  _type: z.literal('https://in-toto.io/Statement/v1'),
  subject: z.array(InTotoSubjectSchema),
  predicateType: z.string(),
  predicate: z.object({
    builder: z.object({
      id: z.string(),
      version: z.string(),
    }),
    buildType: z.string(),
    invocation: z.object({
      configSource: z.object({
        uri: z.string(),
        digest: z.record(z.string(), z.string()),
      }),
      parameters: z.record(z.string(), z.any()),
    }),
    materials: z.array(z.object({
      uri: z.string(),
      digest: z.record(z.string(), z.string()),
    })),
    metadata: z.object({
      buildInvocationId: z.string(),
      buildStartedOn: z.string(),
      buildFinishedOn: z.string(),
      completeness: z.object({
        parameters: z.boolean(),
        environment: z.boolean(),
        materials: z.boolean(),
      }),
      reproducible: z.boolean(),
    }),
    validation_summary: z.record(z.string(), z.any()),
    policy_decision: z.record(z.string(), z.any()),
    approvals: z.array(z.record(z.string(), z.any())),
  }),
});
export type AttestationStatement = z.infer<typeof AttestationStatementSchema>;

export const SignatureEnvelopeSchema = z.object({
  signature_id: z.string(),
  target_id: z.string(), // package_id or manifest_hash
  signature_scheme: z.literal('ed25519'),
  key_id: z.string(),
  key_version: z.string(),
  public_key_pem: z.string(),
  signature_base64: z.string(),
  signed_at: z.string(),
  algorithm: z.literal('Ed25519'),
});
export type SignatureEnvelope = z.infer<typeof SignatureEnvelopeSchema>;

export interface SignedPackageBundle {
  package_id: string;
  manifest: PackageManifest;
  manifest_hash: string;
  files: Map<string, PackageFileEntry>;
  attestation: AttestationStatement;
  signature: SignatureEnvelope;
}

export const DeliveryReceiptSchema = z.object({
  shipment_id: z.string(),
  package_id: z.string(),
  target_type: ShippingTargetTypeEnum,
  target_locator: z.string(),
  manifest_hash: z.string(),
  signature_id: z.string(),
  shipped_at: z.string(),
  status: ShipmentStatusEnum,
  receipt_locator: z.string(),
  transfer_size_bytes: z.number(),
  receipt_signature: z.string(),
  audit_trail_id: z.string(),
  metadata: z.record(z.string(), z.any()).optional(),
});
export type DeliveryReceipt = z.infer<typeof DeliveryReceiptSchema>;

export interface PolicyGateResult {
  allowed: boolean;
  gate_name: string;
  reasons: string[];
  blockers: string[];
  evaluated_at: string;
}

export interface ShippingGateResult {
  allowed: boolean;
  target_type: ShippingTargetType;
  reasons: string[];
  blockers: string[];
  signature_valid: boolean;
  evaluated_at: string;
}
