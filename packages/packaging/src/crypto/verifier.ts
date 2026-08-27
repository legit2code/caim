import crypto from 'node:crypto';
import { SignatureEnvelope, SignedPackageBundle, PackageManifest } from '../types.ts';
import { sha256, computeManifestRootHash } from '../hashing.ts';

export interface VerificationResult {
  valid: boolean;
  tampered: boolean;
  keyId: string;
  keyVersion: string;
  algorithm: string;
  manifestHashMatched: boolean;
  contentHashesMatched: boolean;
  signatureVerified: boolean;
  errors: string[];
}

export class SignatureVerifier {
  /**
   * Verifies an Ed25519 signature directly over a data payload.
   */
  static verifySignature(
    data: string | Uint8Array,
    signatureEnvelope: SignatureEnvelope,
    expectedPublicKeyPem?: string
  ): boolean {
    try {
      const publicKeyToUse = expectedPublicKeyPem || signatureEnvelope.public_key_pem;
      if (!publicKeyToUse) {
        return false;
      }

      const pubKeyObj = crypto.createPublicKey(publicKeyToUse);
      const dataBuffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : Buffer.from(data);
      const sigBuffer = Buffer.from(signatureEnvelope.signature_base64, 'base64');

      return crypto.verify(null, dataBuffer, pubKeyObj, sigBuffer);
    } catch {
      return false;
    }
  }

  /**
   * Thoroughly verifies an entire SignedPackageBundle:
   * 1. Verifies each individual content file matches its manifest sha256.
   * 2. Recomputes manifest_hash from content files and verifies it matches manifest.manifest_hash.
   * 3. Verifies cryptographic signature over the manifest_hash or target.
   * 4. Verifies in-toto attestation digest references the manifest_hash.
   */
  static verifyBundle(
    bundle: SignedPackageBundle,
    trustedPublicKeyPem?: string
  ): VerificationResult {
    const errors: string[] = [];
    let manifestHashMatched = true;
    let contentHashesMatched = true;
    let tampered = false;

    const { manifest, files, signature, attestation } = bundle;

    // 1. Check all content files
    const fileEntries: Array<{ path: string; sha256: string }> = [];
    for (const manifestEntry of manifest.contents) {
      const actualFile = files.get(manifestEntry.path);
      if (!actualFile) {
        errors.push(`Missing content file in package bundle: ${manifestEntry.path}`);
        contentHashesMatched = false;
        tampered = true;
        continue;
      }

      const actualHash = sha256(actualFile.content);
      if (actualHash !== manifestEntry.sha256) {
        errors.push(
          `Content hash mismatch for ${manifestEntry.path}. Manifest: ${manifestEntry.sha256}, Actual: ${actualHash}`
        );
        contentHashesMatched = false;
        tampered = true;
      }

      fileEntries.push({ path: manifestEntry.path, sha256: actualHash });
    }

    // Check if extra files exist in bundle that are not in manifest
    const allowedEnvelopeFiles = new Set(['manifest.json', 'attestation.json']);
    for (const [filePath] of files.entries()) {
      if (allowedEnvelopeFiles.has(filePath)) continue;
      const inManifest = manifest.contents.some((c) => c.path === filePath);
      if (!inManifest) {
        errors.push(`Unregistered file present in package bundle: ${filePath}`);
        tampered = true;
      }
    }

    // 2. Recompute manifest root hash
    const recomputedRootHash = computeManifestRootHash(fileEntries);
    if (recomputedRootHash !== manifest.manifest_hash) {
      errors.push(
        `Manifest root hash mismatch. Declared: ${manifest.manifest_hash}, Recomputed: ${recomputedRootHash}`
      );
      manifestHashMatched = false;
      tampered = true;
    }

    // 3. Verify Signature over manifest.manifest_hash
    const signatureVerified = this.verifySignature(
      manifest.manifest_hash,
      signature,
      trustedPublicKeyPem
    );

    if (!signatureVerified) {
      errors.push(`Cryptographic Ed25519 signature verification failed for key ID: ${signature.key_id}`);
      tampered = true;
    }

    // 4. Verify Attestation subject
    const tarSubject = attestation.subject.find((s) => s.name.endsWith('.tar.gz'));
    if (tarSubject && tarSubject.digest.sha256 !== manifest.manifest_hash) {
      errors.push(
        `Attestation subject digest does not match manifest hash: ${tarSubject.digest.sha256} vs ${manifest.manifest_hash}`
      );
      tampered = true;
    }

    const valid = errors.length === 0 && signatureVerified && contentHashesMatched && manifestHashMatched;

    return {
      valid,
      tampered,
      keyId: signature.key_id,
      keyVersion: signature.key_version,
      algorithm: signature.algorithm,
      manifestHashMatched,
      contentHashesMatched,
      signatureVerified,
      errors,
    };
  }
}
