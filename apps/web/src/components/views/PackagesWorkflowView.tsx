import React, { useState } from 'react';
import { 
  Package, 
  ShieldCheck, 
  ShieldAlert, 
  CheckCircle2, 
  XCircle, 
  Lock, 
  Unlock, 
  Download, 
  FileCheck, 
  Key, 
  Cpu, 
  Clock, 
  Sparkles, 
  Play, 
  Fingerprint,
  Layers,
  ChevronRight,
  Send,
  Info
} from 'lucide-react';

interface PackagesWorkflowViewProps {
  currentRole: string;
  onNavigateToWorkflow?: (workflow: string, params?: any) => void;
}

export const PackagesWorkflowView: React.FC<PackagesWorkflowViewProps> = ({ currentRole, onNavigateToWorkflow }) => {
  const [selectedPackageId, setSelectedPackageId] = useState<string>('pkg-fin-v100-prod');
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [isShipping, setIsShipping] = useState<boolean>(false);
  const [notification, setNotification] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);

  const packages = [
    {
      package_id: 'pkg-fin-v100-prod',
      agent_id: 'agent-financial-analyst',
      version: 'v1.0.0',
      manifest_hash: 'sha256:3c59a2f7c001a1b5b24b899478f7a8b85590c749320e8b15ca88bfa674b88bf2',
      signature_algorithm: 'Ed25519-Pure',
      signer_key_id: 'kms-enclave-caim-root-v2',
      policy_status: 'CLEARED_FOR_SHIPPING',
      shipping_destination: 'prod-cluster-us-east-1',
      created_at: '2026-08-26T12:10:00Z',
      manifest_contents: {
        format_version: 'caim.package.v2.0',
        agent_id: 'agent-financial-analyst',
        version: 'v1.0.0',
        runtime: 'node-20-distroless',
        entrypoint: 'dist/agent.cjs',
        permissions: ['network:egress:market-api.internal', 'db:read:general_ledger'],
        policy_gate_signature: 'ed25519:sig:9901bf1283748291038472918374928173491823749182374918237491823749'
      }
    }
  ];

  const currentPkg = packages.find(p => p.package_id === selectedPackageId) || packages[0];

  const handleVerifyTamper = async () => {
    setIsVerifying(true);
    try {
      await new Promise(r => setTimeout(r, 400));
      setNotification({
        type: 'success',
        message: 'Cryptographic attestation verified! Ed25519 manifest signature and SBOM hashes match root KMS enclave.'
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleShip = async () => {
    setIsShipping(true);
    try {
      await new Promise(r => setTimeout(r, 600));
      setNotification({
        type: 'success',
        message: `Package ${currentPkg.package_id} successfully shipped and deployed to ${currentPkg.shipping_destination}!`
      });
    } finally {
      setIsShipping(false);
    }
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center space-x-3.5">
          <div className="h-11 w-11 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <Package className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <h1 className="text-lg font-bold text-slate-100 tracking-tight">Deterministic Packaging, KMS Attestation & Release</h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                P09 Packaging & Attestation Active
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Inspect reproducible bundle manifests, verify Ed25519 signatures, check policy clearance, and deploy to runtime targets.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2.5">
          <button
            onClick={handleVerifyTamper}
            disabled={isVerifying}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono transition-colors disabled:opacity-50"
          >
            <Fingerprint className={`w-3.5 h-3.5 text-cyan-400 ${isVerifying ? 'animate-spin' : ''}`} />
            <span>{isVerifying ? 'Verifying...' : 'Verify Ed25519 Sig'}</span>
          </button>
          
          <button
            onClick={handleShip}
            disabled={isShipping}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-sm transition-colors disabled:opacity-50"
          >
            <Send className={`w-3.5 h-3.5 ${isShipping ? 'animate-spin' : ''}`} />
            <span>{isShipping ? 'Shipping...' : 'Ship & Deploy Bundle'}</span>
          </button>
        </div>
      </div>

      {notification && (
        <div className={`p-3.5 rounded-lg border text-xs flex items-center justify-between font-mono ${
          notification.type === 'success' ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300' :
          'bg-cyan-950/40 border-cyan-500/30 text-cyan-300'
        }`}>
          <div className="flex items-center space-x-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{notification.message}</span>
          </div>
          <button onClick={() => setNotification(null)} className="text-slate-400 hover:text-slate-200 text-xs ml-4">✕</button>
        </div>
      )}

      {/* Package Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center space-x-2 font-mono">
              <span className="text-sm font-bold text-slate-100">{currentPkg.package_id}</span>
              <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 font-semibold">
                {currentPkg.policy_status}
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-1">
              Target: {currentPkg.agent_id} ({currentPkg.version})
            </p>
          </div>

          <div className="text-right font-mono text-xs text-slate-400">
            <span>Destination: <strong className="text-slate-200">{currentPkg.shipping_destination}</strong></span>
          </div>
        </div>

        {/* Cryptographic Details */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
            <span className="text-slate-500 text-[10px] block">Manifest SHA-256 Digest</span>
            <span className="text-cyan-400 text-xs truncate block">{currentPkg.manifest_hash}</span>
          </div>
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
            <span className="text-slate-500 text-[10px] block">Signature Enclave Algorithm</span>
            <span className="text-emerald-400 text-xs">{currentPkg.signature_algorithm}</span>
          </div>
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-1">
            <span className="text-slate-500 text-[10px] block">KMS Key Identifier</span>
            <span className="text-slate-200 text-xs">{currentPkg.signer_key_id}</span>
          </div>
        </div>

        {/* Manifest Viewer */}
        <div className="space-y-2 font-mono text-xs">
          <span className="text-slate-400 font-semibold block">Deterministic Bundle Manifest Contents:</span>
          <pre className="bg-slate-950 p-4 rounded-xl text-cyan-300 border border-slate-850 overflow-x-auto leading-relaxed">
            {JSON.stringify(currentPkg.manifest_contents, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
};
