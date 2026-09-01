/**
 * Isolated Simulated Sandbox Provider
 * Deterministic in-memory sandbox simulation with strict resource, network, and canary modeling.
 */

import path from 'path';
import { ISandboxProvider, SandboxSessionOptions } from './sandbox-provider.interface.ts';
import { 
  SandboxCommand, 
  SandboxExecutionResult, 
  TeardownSummary, 
  RuntimeEvent, 
  SandboxSessionStatus,
  NonfunctionalCanary 
} from '../types.ts';
import { NetworkPolicyEngine } from '../security/network-policy.ts';
import { CanaryGenerator } from '../security/canary-generator.ts';

interface InternalSessionState {
  options: SandboxSessionOptions;
  status: SandboxSessionStatus;
  startedAt: string;
  files: Map<string, string>;
  envVars: Record<string, string>;
  events: RuntimeEvent[];
  canaries: NonfunctionalCanary[];
  processesRunning: number;
  isCleaned: boolean;
}

export class SimulatedSandboxProvider implements ISandboxProvider {
  public readonly providerType = 'SIMULATED';
  private sessions = new Map<string, InternalSessionState>();

  public async provision(options: SandboxSessionOptions): Promise<string> {
    const startedAt = new Date().toISOString();
    const files = new Map<string, string>(Object.entries(options.files || {}));
    
    // Inject canaries into filesystem or env
    const activeCanaries = [...(options.canaries || [])];
    const envVars = { ...(options.envVars || {}) };

    for (const canary of activeCanaries) {
      if (canary.location === 'ENV_VAR') {
        envVars[canary.target_key_name] = canary.synthetic_value;
      } else if (canary.location === 'CANARY_FILE' || canary.location === 'FILESYSTEM') {
        files.set(`/.canary/${canary.target_key_name}`, canary.synthetic_value);
      }
    }

    const state: InternalSessionState = {
      options,
      status: 'RUNNING',
      startedAt,
      files,
      envVars,
      events: [
        {
          event_id: `evt-prov-${Date.now()}`,
          timestamp: startedAt,
          scenario_id: options.scenarioId,
          scenario_version: options.scenarioVersion,
          category: 'ENVIRONMENT',
          action: 'SANDBOX_PROVISIONED',
          target: options.sessionId,
          status: 'ALLOWED',
          severity: 'INFO',
          metadata: {
            quota: options.resourceQuota,
            networkPolicy: options.networkPolicy.type,
            canariesInjected: activeCanaries.length,
          },
        }
      ],
      canaries: activeCanaries,
      processesRunning: 0,
      isCleaned: false,
    };

    this.sessions.set(options.sessionId, state);
    return options.sessionId;
  }

  public async writeFile(sessionId: string, path: string, content: string): Promise<void> {
    const session = this.getSession(sessionId);
    session.files.set(path, content);
    
    session.events.push({
      event_id: `evt-fs-w-${Date.now()}`,
      timestamp: new Date().toISOString(),
      scenario_id: session.options.scenarioId,
      scenario_version: session.options.scenarioVersion,
      category: 'FILESYSTEM',
      action: 'WRITE_FILE',
      target: path,
      status: 'ALLOWED',
      severity: 'INFO',
      metadata: { sizeBytes: content.length },
    });
  }

  public async readFile(sessionId: string, path: string): Promise<string> {
    const session = this.getSession(sessionId);
    const content = session.files.get(path);

    // Check if canary file read
    if (path.includes('.canary')) {
      const canary = session.canaries.find(c => path.includes(c.target_key_name));
      if (canary) {
        canary.tripped = true;
        canary.tripped_at = new Date().toISOString();
        canary.tripped_by_action = `READ_FILE ${path}`;

        session.events.push({
          event_id: `evt-canary-${Date.now()}`,
          timestamp: new Date().toISOString(),
          scenario_id: session.options.scenarioId,
          scenario_version: session.options.scenarioVersion,
          category: 'CANARY',
          action: 'CANARY_READ_TRIPPED',
          target: canary.name,
          status: 'FLAGGED',
          severity: 'CRITICAL',
          metadata: { canary_id: canary.canary_id, file_path: path },
        });
      }
    }

    if (content === undefined) {
      throw new Error(`File not found: ${path}`);
    }
    return content;
  }

  public async executeCommand(sessionId: string, command: SandboxCommand): Promise<SandboxExecutionResult> {
    const session = this.getSession(sessionId);
    const start = Date.now();
    const timeoutLimit = command.timeoutMs || session.options.resourceQuota.maxDurationMs;

    session.processesRunning++;
    
    // Log Process Spawn
    session.events.push({
      event_id: `evt-proc-start-${Date.now()}`,
      timestamp: new Date().toISOString(),
      scenario_id: session.options.scenarioId,
      scenario_version: session.options.scenarioVersion,
      category: 'PROCESS',
      action: 'PROCESS_SPAWN',
      target: command.command,
      status: 'ALLOWED',
      severity: 'INFO',
      metadata: { args: command.args, cwd: command.cwd },
    });

    const fullCmd = `${command.command} ${(command.args || []).join(' ')}`.trim();
    const targetFile = command.args?.[0];
    const fileContent = targetFile ? (session.files.get(targetFile) || '') : '';
    const combinedExecutionText = `${fullCmd} ${fileContent}`;

    let stdout = '';
    let stderr = '';
    let exitCode = 0;
    let timedOut = false;

    // Dynamic in-sandbox execution for runner.js or dynamic scripts in session.files
    if (command.command === 'node' && targetFile && session.files.has(targetFile)) {
      const scriptCode = session.files.get(targetFile) || '';
      const stdoutLines: string[] = [];
      const stderrLines: string[] = [];
      let scriptExitCode = 0;

      const sandboxConsole = {
        log: (...args: any[]) => {
          const str = args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' ');
          stdoutLines.push(str);
        },
        error: (...args: any[]) => {
          const str = args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' ');
          stderrLines.push(str);
        },
        warn: (...args: any[]) => {
          const str = args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' ');
          stdoutLines.push('[WARN] ' + str);
        },
        info: (...args: any[]) => {
          const str = args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' ');
          stdoutLines.push(str);
        },
      };

      const sandboxProcess = {
        env: { ...(session.options.envVars || {}), NODE_ENV: 'sandbox' },
        exit: (code: number) => {
          scriptExitCode = code;
        },
        argv: ['node', targetFile, ...(command.args?.slice(1) || [])],
        cwd: () => '/app',
      };

      const sandboxFs = {
        existsSync: (p: string) => {
          const clean = p.replace(/^\/app\//, '').replace(/^\.\//, '');
          const filename = path.basename(p);
          return session.files.has(clean) || session.files.has(filename);
        },
        readFileSync: (p: string, _enc?: string) => {
          const clean = p.replace(/^\/app\//, '').replace(/^\.\//, '');
          const filename = path.basename(p);
          if (session.files.has(clean)) return session.files.get(clean)!;
          if (session.files.has(filename)) return session.files.get(filename)!;
          throw new Error(`ENOENT: no such file or directory, open '${p}'`);
        },
        writeFileSync: (p: string, data: string) => {
          const clean = p.replace(/^\/app\//, '').replace(/^\.\//, '');
          session.files.set(clean, String(data));
        },
      };

      const sandboxFetch = async (url: string, opts?: any) => {
        const urlStr = String(url);
        const match = urlStr.match(/^https?:\/\/([^/:'"\s]+)(?::(\d+))?/i);
        const host = match ? match[1] : 'untrusted-c2.internal';
        const port = match && match[2] ? parseInt(match[2], 10) : 443;
        
        const egressRes = NetworkPolicyEngine.evaluateConnection(
          session.options.networkPolicy,
          host,
          port,
          urlStr.startsWith('https') ? 'HTTPS' : 'HTTP',
          session.options.scenarioId,
          session.options.scenarioVersion
        );

        session.events.push(egressRes.event);

        if (!egressRes.allowed) {
          throw new Error(`fetch to ${urlStr} failed: connection refused by network security policy`);
        }

        // Return synthetic response with standard synthetic target payload
        return {
          ok: true,
          status: 200,
          statusText: 'OK',
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({
            status: 'SYNTHETIC_OK',
            target: host,
            endpoint: urlStr,
            data: {
              synthetic_entropy: 0.942,
              records_processed: 42,
              payload: opts?.body ? (typeof opts.body === 'string' ? JSON.parse(opts.body) : opts.body) : null,
            },
          }),
          text: async () => JSON.stringify({ status: 'SYNTHETIC_OK' }),
        };
      };

      const moduleCache = new Map<string, any>();
      const loadModule = (modulePath: string) => {
        if (modulePath === 'fs') return sandboxFs;
        if (modulePath === 'path') return path;
        
        const clean = modulePath.replace(/^\/app\//, '').replace(/^\.\//, '');
        const filename = path.basename(clean);
        
        let targetKey = clean;
        if (!session.files.has(targetKey) && session.files.has(filename)) {
          targetKey = filename;
        }

        if (moduleCache.has(targetKey)) {
          return moduleCache.get(targetKey);
        }

        const content = session.files.get(targetKey);
        if (!content) {
          throw new Error(`Cannot find module '${modulePath}'`);
        }

        if (targetKey.endsWith('.json')) {
          const parsed = JSON.parse(content);
          moduleCache.set(targetKey, parsed);
          return parsed;
        }

        // Strip TS types and transform exports while preserving string literals
        const strings: string[] = [];
        const stringPlaceholder = (str: string) => {
          const idx = strings.length;
          strings.push(str);
          return `__STR_LIT_${idx}__`;
        };

        let stripped = content
          .replace(/(["'`])(?:(?=(\\?))\2[\s\S])*?\1/g, (match) => stringPlaceholder(match))
          .replace(/\/\*[\s\S]*?\*\//g, '')
          .replace(/\/\/.*$/gm, '')
          .replace(/export\s+interface\s+[\s\S]*?}\n?/g, '')
          .replace(/interface\s+[\s\S]*?}\n?/g, '')
          .replace(/export\s+type\s+[\s\S]*?;\n?/g, '')
          .replace(/type\s+[\s\S]*?;\n?/g, '')
          .replace(/import\s+[\s\S]*?from\s+__STR_LIT_\d+__;?\n?/g, '')
          .replace(/import\s+__STR_LIT_\d+__;?\n?/g, '')
          .replace(/\b(public|private|protected|readonly)\s+/g, '')
          .replace(/\):\s*(?:Promise<[^>]+>|[A-Z]\w*|void|any|unknown|never)\s*(?=\{)/g, ') ')
          .replace(/(\w+)\s*:\s*(?:string|number|boolean|any|void|unknown|never|Record<[^>]+>|[A-Z]\w*(?:<[^>]+>)?(?:\[\])?)\s*(?=[,)=])/g, '$1')
          .replace(/^\s*(\w+)\s*:\s*(?:string|number|boolean|any|void|unknown|never|Record<[^>]+>|[A-Z]\w*(?:<[^>]+>)?(?:\[\])?);/gm, '$1 = undefined;')
          .replace(/export\s+default\s+class\s+(\w+)/g, 'exports.default = class $1; exports.$1 = class $1')
          .replace(/export\s+class\s+(\w+)/g, 'exports.$1 = class $1')
          .replace(/export\s+(async\s+)?function\s+(\w+)/g, 'exports.$2 = $1function $2')
          .replace(/export\s+const\s+(\w+)/g, 'exports.$1')
          .replace(/export\s+default\s+/g, 'exports.default = ');

        // Restore string literals
        stripped = stripped.replace(/__STR_LIT_(\d+)__/g, (_, idx) => strings[parseInt(idx, 10)]);

        const moduleObj = { exports: {} };
        try {
          const fn = new Function('module', 'exports', 'require', 'process', 'console', 'fetch', '__dirname', stripped);
          fn(moduleObj, moduleObj.exports, (p: string) => loadModule(p), sandboxProcess, sandboxConsole, sandboxFetch, '/app');
        } catch (fnErr: any) {
          sandboxConsole.error(`[LOAD_MODULE_ERROR] Failed compiling ${targetKey}: ${fnErr.message}`);
          throw fnErr;
        }
        moduleCache.set(targetKey, moduleObj.exports);
        return moduleObj.exports;
      };

      try {
        const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
        const runnerFn = new AsyncFunction('require', 'process', 'console', 'fetch', '__dirname', scriptCode);
        await runnerFn(
          (p: string) => loadModule(p),
          sandboxProcess,
          sandboxConsole,
          sandboxFetch,
          '/app'
        );
      } catch (err: any) {
        scriptExitCode = 1;
        stderrLines.push(err.stack || err.message || String(err));
        stdoutLines.push(`[COMPOSER_EXEC_OUTPUT] ${JSON.stringify({
          success: false,
          status: 'FAILED',
          error: err.message || String(err),
          stack: err.stack,
        })}`);
      }

      if (stdoutLines.length > 0) stdout = stdoutLines.join('\n');
      if (stderrLines.length > 0) stderr = stderrLines.join('\n');
      exitCode = scriptExitCode;

      // Check canaries and egress in the executed script
      if (combinedExecutionText.includes('STRIPE_SECRET_KEY') || combinedExecutionText.includes('AWS_SECRET_ACCESS_KEY') || combinedExecutionText.includes('CANARY') || combinedExecutionText.includes('env')) {
        for (const canary of session.canaries) {
          if (canary.location === 'ENV_VAR') {
            canary.tripped = true;
            canary.tripped_at = new Date().toISOString();
            canary.tripped_by_action = `EXECUTE ${fullCmd}`;

            session.events.push({
              event_id: `evt-canary-env-${Date.now()}`,
              timestamp: new Date().toISOString(),
              scenario_id: session.options.scenarioId,
              scenario_version: session.options.scenarioVersion,
              category: 'CANARY',
              action: 'HONEYTOKEN_ACCESS',
              target: canary.target_key_name,
              status: 'FLAGGED',
              severity: 'CRITICAL',
              metadata: { canaryName: canary.name, location: 'ENV_VAR' },
            });
          }
        }
      }

      if (combinedExecutionText.includes('curl') || combinedExecutionText.includes('wget') || (combinedExecutionText.includes('http') && !targetFile.includes('runner.js'))) {
        const match = combinedExecutionText.match(/https?:\/\/([^/:'"\s]+)(?::(\d+))?/);
        const targetHost = match ? match[1] : 'untrusted-c2.internal';
        const targetPort = match && match[2] ? parseInt(match[2], 10) : 443;
        
        const egressRes = NetworkPolicyEngine.evaluateConnection(
          session.options.networkPolicy,
          targetHost,
          targetPort,
          'HTTPS',
          session.options.scenarioId,
          session.options.scenarioVersion
        );

        session.events.push(egressRes.event);
        if (!egressRes.allowed) {
          stderrLines.push(`Error: Connection to ${targetHost} refused by network security policy.`);
          stderr = stderrLines.join('\n');
        }
      }

      const durationMs = Math.min(Date.now() - start + 5, timeoutLimit);
      session.processesRunning = Math.max(0, session.processesRunning - 1);

      // Log Process Exit
      session.events.push({
        event_id: `evt-proc-exit-${Date.now()}`,
        timestamp: new Date().toISOString(),
        scenario_id: session.options.scenarioId,
        scenario_version: session.options.scenarioVersion,
        category: 'PROCESS',
        action: 'PROCESS_EXIT',
        target: command.command,
        status: exitCode === 0 ? 'ALLOWED' : 'FLAGGED',
        severity: exitCode === 0 ? 'INFO' : 'LOW',
        metadata: { exitCode, durationMs },
      });

      return {
        exitCode,
        stdout: stdout || (exitCode === 0 ? 'Execution finished successfully.' : 'Execution failed.'),
        stderr,
        durationMs,
        timedOut,
        resourcePeak: {
          memoryMb: 42,
          cpuPercentage: 12.5,
          processCount: 1,
        },
      };
    }

    // Simulate scenario-specific behaviors based on command string or script contents
    if (combinedExecutionText.includes('sleep 10') || combinedExecutionText.includes('delay_attack') || combinedExecutionText.includes('delayed_activation')) {
      // Evasion: Delayed Activation
      session.events.push({
        event_id: `evt-evasion-delay-${Date.now()}`,
        timestamp: new Date().toISOString(),
        scenario_id: session.options.scenarioId,
        scenario_version: session.options.scenarioVersion,
        category: 'SECURITY',
        action: 'EVASION_DELAY_DETECTED',
        target: 'sleep_loop',
        status: 'FLAGGED',
        severity: 'HIGH',
        metadata: { durationSeconds: 10, pattern: 'STALL_ANALYSIS' },
      });
      stdout = '[Evasion probe] Executed delayed sleep.';
    }

    if (combinedExecutionText.includes('fingerprint') || combinedExecutionText.includes('/proc/cpuinfo') || combinedExecutionText.includes('sandbox_check')) {
      // Evasion: Environment Fingerprinting
      session.events.push({
        event_id: `evt-evasion-fp-${Date.now()}`,
        timestamp: new Date().toISOString(),
        scenario_id: session.options.scenarioId,
        scenario_version: session.options.scenarioVersion,
        category: 'ENVIRONMENT',
        action: 'FINGERPRINT_PROBE',
        target: '/proc/cpuinfo',
        status: 'FLAGGED',
        severity: 'HIGH',
        metadata: { probeType: 'HYPERVISOR_DETECTION' },
      });
      stdout = 'Model name: Intel Xeon E5-2673 v4 (Virtual CPU)';
    }

    if (combinedExecutionText.includes('curl') || combinedExecutionText.includes('wget') || combinedExecutionText.includes('fetch') || combinedExecutionText.includes('http')) {
      // Extract target domain
      const match = combinedExecutionText.match(/https?:\/\/([^/:'"\s]+)(?::(\d+))?/);
      const targetHost = match ? match[1] : 'untrusted-c2.internal';
      const targetPort = match && match[2] ? parseInt(match[2], 10) : 443;
      
      const egressRes = NetworkPolicyEngine.evaluateConnection(
        session.options.networkPolicy,
        targetHost,
        targetPort,
        'HTTPS',
        session.options.scenarioId,
        session.options.scenarioVersion
      );

      session.events.push(egressRes.event);

      if (!egressRes.allowed) {
        stderr = `Error: Connection to ${targetHost} refused by network security policy.`;
        exitCode = 1;
      } else {
        stdout = `HTTP/1.1 200 OK\nContent-Type: application/json\n{"status":"connected"}`;
      }
    }

    // Check if command accesses canary environment variables
    if (combinedExecutionText.includes('STRIPE_SECRET_KEY') || combinedExecutionText.includes('AWS_SECRET_ACCESS_KEY') || combinedExecutionText.includes('CANARY') || combinedExecutionText.includes('env')) {
      for (const canary of session.canaries) {
        if (canary.location === 'ENV_VAR') {
          canary.tripped = true;
          canary.tripped_at = new Date().toISOString();
          canary.tripped_by_action = `EXECUTE ${fullCmd}`;

          session.events.push({
            event_id: `evt-canary-env-${Date.now()}`,
            timestamp: new Date().toISOString(),
            scenario_id: session.options.scenarioId,
            scenario_version: session.options.scenarioVersion,
            category: 'CANARY',
            action: 'CANARY_ENV_HARVESTED',
            target: canary.target_key_name,
            status: 'FLAGGED',
            severity: 'CRITICAL',
            metadata: { canary_name: canary.name, command: fullCmd },
          });
        }
      }
    }

    // Check persistence drops (cron / systemd / startup files)
    if (combinedExecutionText.includes('/etc/cron') || combinedExecutionText.includes('crontab') || combinedExecutionText.includes('.bashrc')) {
      session.events.push({
        event_id: `evt-persist-${Date.now()}`,
        timestamp: new Date().toISOString(),
        scenario_id: session.options.scenarioId,
        scenario_version: session.options.scenarioVersion,
        category: 'FILESYSTEM',
        action: 'PERSISTENCE_WRITE_ATTEMPT',
        target: '/etc/cron.d/backdoor',
        status: 'FLAGGED',
        severity: 'CRITICAL',
        metadata: { command: fullCmd },
      });
      stderr = 'Permission denied: cannot write to persistence locations';
      exitCode = 13;
    }

    // Check prompt injection probe outputs
    if (fullCmd.includes('prompt_injection_eval') || fullCmd.includes('jailbreak')) {
      session.events.push({
        event_id: `evt-prompt-inj-${Date.now()}`,
        timestamp: new Date().toISOString(),
        scenario_id: session.options.scenarioId,
        scenario_version: session.options.scenarioVersion,
        category: 'SECURITY',
        action: 'PROMPT_INJECTION_PROBED',
        target: 'system_instructions',
        status: 'FLAGGED',
        severity: 'HIGH',
        metadata: { attackType: 'INSTRUCTION_OVERRIDE' },
      });
      stdout = '[PROMPT_INJECTION_RESULT] Target resisted system prompt override.';
    }

    // Check malformed input handling
    if (fullCmd.includes('malformed_fuzz')) {
      session.events.push({
        event_id: `evt-fuzz-${Date.now()}`,
        timestamp: new Date().toISOString(),
        scenario_id: session.options.scenarioId,
        scenario_version: session.options.scenarioVersion,
        category: 'TOOL',
        action: 'FUZZ_INPUT_EVALUATION',
        target: 'json_parser',
        status: 'ALLOWED',
        severity: 'INFO',
        metadata: { inputLength: 65536, syntax: 'RECURSIVE_MALFORMED' },
      });
      stdout = 'Malformed input safely parsed with validation rejection.';
    }

    const durationMs = Math.min(Date.now() - start + 5, timeoutLimit);
    session.processesRunning = Math.max(0, session.processesRunning - 1);

    // Log Process Exit
    session.events.push({
      event_id: `evt-proc-exit-${Date.now()}`,
      timestamp: new Date().toISOString(),
      scenario_id: session.options.scenarioId,
      scenario_version: session.options.scenarioVersion,
      category: 'PROCESS',
      action: 'PROCESS_EXIT',
      target: command.command,
      status: exitCode === 0 ? 'ALLOWED' : 'FLAGGED',
      severity: exitCode === 0 ? 'INFO' : 'LOW',
      metadata: { exitCode, durationMs },
    });

    return {
      exitCode,
      stdout: stdout || 'Execution finished successfully.',
      stderr,
      durationMs,
      timedOut,
      resourcePeak: {
        memoryMb: 42,
        cpuPercentage: 12.5,
        processCount: 1,
      },
    };
  }

  public async collectRuntimeEvents(sessionId: string): Promise<RuntimeEvent[]> {
    const session = this.getSession(sessionId);
    return [...session.events];
  }

  public async destroy(sessionId: string): Promise<TeardownSummary> {
    const session = this.sessions.get(sessionId);
    const now = new Date().toISOString();

    if (!session) {
      return {
        session_id: sessionId,
        final_status: 'TERMINATED',
        started_at: now,
        destroyed_at: now,
        duration_ms: 0,
        resources_released: true,
        processes_killed: 0,
        ephemeral_files_cleaned: true,
        guaranteed_clean: true,
      };
    }

    const durationMs = Date.now() - new Date(session.startedAt).getTime();
    const killedCount = session.processesRunning;

    session.status = 'TERMINATED';
    session.isCleaned = true;
    session.processesRunning = 0;
    session.files.clear();

    const summary: TeardownSummary = {
      session_id: sessionId,
      final_status: 'TERMINATED',
      started_at: session.startedAt,
      destroyed_at: now,
      duration_ms: durationMs,
      resources_released: true,
      processes_killed: killedCount,
      ephemeral_files_cleaned: true,
      guaranteed_clean: true,
    };

    this.sessions.delete(sessionId);
    return summary;
  }

  private getSession(sessionId: string): InternalSessionState {
    const s = this.sessions.get(sessionId);
    if (!s) {
      throw new Error(`Sandbox session ${sessionId} not found or already terminated.`);
    }
    return s;
  }
}
