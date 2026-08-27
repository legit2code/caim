import { IShippingTargetAdapter, ShippingOptions } from './adapter.ts';
import { OciRegistryAdapter } from './oci-adapter.ts';
import { S3StorageAdapter } from './s3-adapter.ts';
import { WebhookShippingAdapter } from './webhook-adapter.ts';
import { LocalStagingAdapter } from './local-staging-adapter.ts';
import { SignedPackageBundle, DeliveryReceipt, ShippingTargetType } from '../types.ts';
import { PackagingPolicyGate } from '../gates.ts';

export class ShippingPolicyViolationError extends Error {
  constructor(message: string, public blockers: string[]) {
    super(`Shipping blocked by policy gate: ${message} (Blockers: ${blockers.join(', ')})`);
    this.name = 'ShippingPolicyViolationError';
  }
}

export class ShippingService {
  private adapters: Map<ShippingTargetType, IShippingTargetAdapter> = new Map();
  private deliveryAuditLog: DeliveryReceipt[] = [];

  constructor(customAdapters?: IShippingTargetAdapter[]) {
    if (customAdapters && customAdapters.length > 0) {
      for (const adapter of customAdapters) {
        this.adapters.set(adapter.targetType, adapter);
      }
    } else {
      // Register default suite of shipping target adapters
      this.registerAdapter(new OciRegistryAdapter());
      this.registerAdapter(new S3StorageAdapter());
      this.registerAdapter(new WebhookShippingAdapter());
      this.registerAdapter(new LocalStagingAdapter());
    }
  }

  registerAdapter(adapter: IShippingTargetAdapter): void {
    this.adapters.set(adapter.targetType, adapter);
  }

  getAdapter(targetType: ShippingTargetType): IShippingTargetAdapter | undefined {
    return this.adapters.get(targetType);
  }

  /**
   * Ships a signed package bundle to the destination after verifying the pre-shipping policy gate.
   */
  async shipBundle(
    bundle: SignedPackageBundle,
    targetType: ShippingTargetType,
    options: ShippingOptions,
    trustedPublicKeyPem?: string
  ): Promise<DeliveryReceipt> {
    const adapter = this.getAdapter(targetType);
    if (!adapter) {
      throw new Error(`Unsupported shipping target type: ${targetType}`);
    }

    // 1. Evaluate Pre-Shipping Policy Gate & Signature Verification
    const gateResult = PackagingPolicyGate.evaluatePreShippingGate(
      bundle,
      targetType,
      trustedPublicKeyPem
    );

    if (!gateResult.allowed) {
      throw new ShippingPolicyViolationError(
        `Pre-shipping checks failed for target ${targetType}`,
        gateResult.blockers
      );
    }

    // 2. Deliver package via adapter
    const receipt = await adapter.ship(bundle, options);

    // 3. Record in immutable delivery audit log
    this.deliveryAuditLog.push(receipt);

    return receipt;
  }

  getAuditLog(): DeliveryReceipt[] {
    return [...this.deliveryAuditLog];
  }

  getShipmentByPackageId(packageId: string): DeliveryReceipt | undefined {
    return this.deliveryAuditLog.find((r) => r.package_id === packageId);
  }
}
