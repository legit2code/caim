import { ISigner, Ed25519Signer } from './signer.ts';
import { PackageManifest, SignatureEnvelope, PolicyGateResult } from '../types.ts';
import { KeyRegistry } from './key-registry.ts';

/**
 * KMS & Isolated Signing Boundary (Threat Model Compliance)
 * 
 * INVARIANT: Private signing keys are strictly confined within this boundary.
 * Neither web requests, general queue workers, nor sandbox environments
 * have access to raw private keys or key material.
 */

export class SigningPolicyViolationError extends Error {
  constructor(message: string, public blockers: string[]) {
    super(`Signing blocked by policy gate: ${message} (Blockers: ${blockers.join(', ')})`);
    this.name = 'SigningPolicyViolationError';
  }
}

export class KmsSignerBoundary {
  private signer: ISigner;
  private keyRegistry: KeyRegistry;

  constructor(signer: ISigner, keyRegistry?: KeyRegistry) {
    this.signer = signer;
    this.keyRegistry = keyRegistry || new KeyRegistry();

    // Register signer's public key in registry
    this.keyRegistry.registerKey({
      keyId: signer.getKeyId(),
      keyVersion: signer.getKeyVersion(),
      publicKeyPem: signer.getPublicKeyPem(),
      algorithm: signer.getAlgorithm(),
      status: 'ACTIVE',
      validFrom: new Date().toISOString(),
      description: 'Primary Release Signing Key (KMS Enclave Isolated)',
    }, true);
  }

  /**
   * Factory method to create an isolated boundary with test or environment signing material.
   */
  static createDefault(keyId: string = 'caim-release-key-01', keyVersion: string = 'v1'): KmsSignerBoundary {
    const { signer } = Ed25519Signer.generateKeyPair(keyId, keyVersion);
    return new KmsSignerBoundary(signer);
  }

  /**
   * Factory method for environment/KMS key material.
   */
  static fromPrivateKeyPem(keyId: string, keyVersion: string, privateKeyPem: string): KmsSignerBoundary {
    const signer = new Ed25519Signer({
      keyId,
      keyVersion,
      privateKeyPem,
    });
    return new KmsSignerBoundary(signer);
  }

  getKeyRegistry(): KeyRegistry {
    return this.keyRegistry;
  }

  getPublicKeyPem(): string {
    return this.signer.getPublicKeyPem();
  }

  getKeyId(): string {
    return this.signer.getKeyId();
  }

  getKeyVersion(): string {
    return this.signer.getKeyVersion();
  }

  /**
   * Signs a PackageManifest ONLY IF the pre-signing policy gate passes.
   * If the gate is rejected (e.g. DENY_SHIPPING, unapproved, regression), throws SigningPolicyViolationError.
   */
  async signManifest(
    manifest: PackageManifest,
    gateResult: PolicyGateResult
  ): Promise<SignatureEnvelope> {
    if (!gateResult.allowed) {
      throw new SigningPolicyViolationError(
        gateResult.gate_name,
        gateResult.blockers
      );
    }

    // Sign the root manifest_hash
    const signatureEnvelope = await this.signer.sign(
      manifest.manifest_hash,
      manifest.package_id
    );

    return signatureEnvelope;
  }
}
