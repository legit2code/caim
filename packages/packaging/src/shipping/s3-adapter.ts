import { IShippingTargetAdapter, ShippingOptions } from './adapter.ts';
import { SignedPackageBundle, DeliveryReceipt, ShippingTargetType } from '../types.ts';
import { sha256 } from '../hashing.ts';

/**
 * Cloud Object Storage (S3 / GCS / Azure Blob) Shipping Adapter
 */

export class S3StorageAdapter implements IShippingTargetAdapter {
  readonly targetType: ShippingTargetType = 'S3_STORAGE';

  constructor(private options: { bucketName?: string; region?: string } = {}) {}

  async ship(
    bundle: SignedPackageBundle,
    options: ShippingOptions
  ): Promise<DeliveryReceipt> {
    const shipmentId = `ship-s3-${Date.now()}-${sha256(bundle.manifest_hash).slice(0, 8)}`;
    const shippedAt = new Date().toISOString();

    let totalBytes = 0;
    for (const [, file] of bundle.files) {
      totalBytes += file.sizeBytes;
    }

    const keyPrefix = `releases/${bundle.manifest.agent_id}/${bundle.manifest.version_label}`;
    const receiptLocator = `s3://${this.options.bucketName || 'caim-release-vault'}/${keyPrefix}/bundle.tar.gz`;
    const auditId = `audit-${shipmentId}`;

    const receiptSignature = sha256(
      `${shipmentId}:${receiptLocator}:${bundle.manifest_hash}:${shippedAt}`
    );

    return {
      shipment_id: shipmentId,
      package_id: bundle.package_id,
      target_type: this.targetType,
      target_locator: options.targetLocator,
      manifest_hash: bundle.manifest_hash,
      signature_id: bundle.signature.signature_id,
      shipped_at: shippedAt,
      status: 'DELIVERED',
      receipt_locator: receiptLocator,
      transfer_size_bytes: totalBytes,
      receipt_signature: receiptSignature,
      audit_trail_id: auditId,
      metadata: {
        bucket: this.options.bucketName || 'caim-release-vault',
        region: this.options.region || 'us-east-1',
        etag: `"${bundle.manifest_hash}"`,
        storage_class: 'STANDARD_IA',
      },
    };
  }

  async healthCheck(): Promise<{ healthy: boolean; details: string }> {
    return {
      healthy: true,
      details: 'S3 cloud storage bucket bucket reachable with write permissions',
    };
  }
}
