/**
 * Secret & Credential Leak Scanner
 * P32 — Zero-Leak Credential & Token Scanning Engine
 */

import fs from 'fs';
import path from 'path';

export interface SecretFinding {
  file: string;
  line: number;
  patternName: string;
  matchedSnippet: string;
  severity: 'HIGH' | 'CRITICAL';
}

export interface SecretScanResult {
  passed: boolean;
  totalFilesScanned: number;
  findings: SecretFinding[];
  durationMs: number;
}

const SECRET_PATTERNS: Array<{ name: string; regex: RegExp; severity: 'HIGH' | 'CRITICAL' }> = [
  {
    name: 'Google Cloud / Gemini API Key',
    regex: /\bAIza[0-9A-Za-z\-_]{30,40}\b/,
    severity: 'CRITICAL',
  },
  {
    name: 'Generic AWS / S3 Access Key ID',
    regex: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/,
    severity: 'CRITICAL',
  },
  {
    name: 'Supabase Service Role JWT (Unredacted)',
    regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/,
    severity: 'CRITICAL',
  },
  {
    name: 'Hardcoded Private Key Header',
    regex: /-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----/,
    severity: 'CRITICAL',
  },
  {
    name: 'Generic Hardcoded Token Assignment',
    regex: /(api_key|apikey|secret_key|private_key|auth_token|client_secret)\s*[:=]\s*['"][a-zA-Z0-9_\-]{24,}['"]/i,
    severity: 'HIGH',
  },
];

// Directories and files to ignore in global repo scan
const IGNORED_DIRS = ['node_modules', '.git', 'dist', 'coverage', '.cache', '__tests__'];
const IGNORED_EXTS = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.ico'];

export function scanFileForSecrets(filePath: string, content: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip comments that explicitly mark test mock / redaction or ignore tags
    if (
      line.includes('// redacting') || 
      line.includes('// mock') || 
      line.includes('SIMULATED_') || 
      line.includes('test-only-dummy') ||
      line.includes('// secret-scan:ignore')
    ) {
      continue;
    }

    for (const pattern of SECRET_PATTERNS) {
      if (pattern.regex.test(line)) {
        // Redact matching token for safe reporting
        const match = line.match(pattern.regex);
        const raw = match ? match[0] : 'MATCH';
        const redacted = raw.length > 8 ? `${raw.slice(0, 4)}...${raw.slice(-4)}` : '****';

        findings.push({
          file: filePath,
          line: i + 1,
          patternName: pattern.name,
          matchedSnippet: line.replace(raw, redacted).trim(),
          severity: pattern.severity,
        });
      }
    }
  }

  return findings;
}

export function runSecretScan(rootDir: string = process.cwd()): SecretScanResult {
  const startTime = performance.now();
  const findings: SecretFinding[] = [];
  let totalFilesScanned = 0;

  function walk(dir: string) {
    if (!fs.existsSync(dir)) return;
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relativePath = path.relative(rootDir, fullPath);

      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.includes(entry.name) && !entry.name.startsWith('.')) {
          walk(fullPath);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);
        if (IGNORED_EXTS.includes(ext)) continue;
        if (entry.name.endsWith('.test.ts') || entry.name.endsWith('.test.tsx') || entry.name.endsWith('.spec.ts')) continue;
        if (relativePath.startsWith('scripts/')) continue; // Skip scanning scanner scripts themselves

        try {
          const content = fs.readFileSync(fullPath, 'utf-8');
          totalFilesScanned++;
          const fileFindings = scanFileForSecrets(relativePath, content);
          findings.push(...fileFindings);
        } catch {
          // Skip binary or unreadable files
        }
      }
    }
  }

  walk(rootDir);
  const durationMs = Math.round(performance.now() - startTime);

  return {
    passed: findings.length === 0,
    totalFilesScanned,
    findings,
    durationMs,
  };
}
