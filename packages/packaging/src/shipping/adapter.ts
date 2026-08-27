import { SignedPackageBundle, DeliveryReceipt, ShippingTargetType } from '../types.ts';

/**
 * Shipping Target Adapter Interface (Architecture V2.0.1)
 */

export interface ShippingOptions {
  targetLocator: string;
  metadata?: Record<string, any>;
  dryRun?: boolean;
}

export interface IShippingTargetAdapter {
  readonly targetType: ShippingTargetType;
  
  ship(
    bundle: SignedPackageBundle,
    options: ShippingOptions
  ): Promise<DeliveryReceipt>;

  healthCheck(): Promise<{ healthy: boolean; details: string }>;
}
