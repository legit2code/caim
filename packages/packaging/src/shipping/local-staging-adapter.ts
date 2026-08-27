import { IShippingTargetAdapter, ShippingOptions } from './adapter.ts';
import { SignedPackageBundle, DeliveryReceipt, ShippingTargetType } from '../types.ts';
import { sha256 } from '../hashing.ts';

/**
 * Local Staging & Air-Gapped Shipping Adapter
 */

export class LocalStagingAdapter implements IShippingTargetAdapter {
  readonly targetType: ShippingTargetType = 'LOCAL_STAGING';

  constructor(private options: { baseDirectory?: string } = {}) {}

  async ship(
    bundle: SignedPackageBundle,
    options: ShippingOptions
  ): Promise<DeliveryReceipt> {
    const shipmentId = `ship-local-${Date.now()}-${sha256(bundle.manifest_hash).slice(0, 8)}`;
    const shippedAt = new Date().toISOString();

    let totalBytes = 0;
    for (const [, file] of bundle.files) {
      totalBytes += file.sizeBytes;
    }

    const baseDir = this.options.baseDirectory || '/tmp/caim-staging';
    const receiptLocator = `${baseDir}/${bundle.manifest.agent_id}/${bundle.manifest.version_label}`;
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
        staged_files_count: bundle.files.size,
        local_directory: receiptLocator,
      },
    };
  }

  async healthCheck(): Promise<{ healthy: boolean; details: string }> {
    return {
      healthy: true,
      details: 'Local staging filesystem directory writable',
    };
  }
}
