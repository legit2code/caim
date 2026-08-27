import { describe, it, expect } from 'vitest';
import { 
  EncodingDetector,
  SourceSpanUtil,
  JsTsAdapter,
  PythonAdapter,
  GoAdapter,
  StructuredAdapter,
  ProtocolDetector,
  FrameworkDetector,
  ConfigExtractor,
  ParserRegistry,
  SyntaxIntelligencePipeline,
  ParsedSourceFacts
} from '../../packages/syntax/src/index.ts';

describe('P13 — Language, Syntax, Protocol, Framework & Configuration Intelligence', () => {

  describe('1. File Type & Encoding Detection', () => {
    it('detects UTF-8 text files and programming languages correctly', () => {
      const tsCode = 'const x: number = 42;';
      const ft = EncodingDetector.detect('src/agent.ts', tsCode);
      expect(ft.language).toBe('typescript');
      expect(ft.format_category).toBe('SOURCE_CODE');
      expect(['ascii', 'UTF-8', 'utf-8']).toContain(ft.encoding);
      expect(ft.is_binary).toBe(false);
      expect(ft.byte_size).toBe(tsCode.length);
    });

    it('detects binary magic byte headers for model weights and binaries', () => {
      // Safetensors 8-byte length prefix
      const safeBuffer = Buffer.alloc(16);
      safeBuffer.writeBigUInt64LE(BigInt(8), 0);
      safeBuffer.write('{"__metadata__":{}}', 8);

      const ftSafe = EncodingDetector.detect('model.safetensors', safeBuffer);
      expect(ftSafe.language).toBe('safetensors');
      expect(ftSafe.format_category).toBe('BINARY_COMPILED');
      expect(ftSafe.is_binary).toBe(true);

      // WebAssembly magic bytes: \0asm
      const wasmBuffer = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
      const ftWasm = EncodingDetector.detect('module.wasm', wasmBuffer);
      expect(ftWasm.language).toBe('wasm');
      expect(ftWasm.is_binary).toBe(true);
    });
  });

  describe('2. Source Spans & Binary Search Mapping', () => {
    it('calculates exact 1-indexed line and column coordinates from byte offsets', () => {
      const source = 'line1\nline2 is longer\nline3\n';
      const lineStarts = SourceSpanUtil.createLineIndex(source);

      // Search for "is longer" in line 2
      const offset = source.indexOf('is longer');
      const span = SourceSpanUtil.offsetToSpan('test.txt', source, offset, offset + 'is longer'.length, lineStarts, 'is longer');

      expect(span.file_path).toBe('test.txt');
      expect(span.start_line).toBe(2);
      expect(span.start_col).toBe(7);
      expect(span.end_line).toBe(2);
      expect(span.end_col).toBe(16);
      expect(span.text_slice).toBe('is longer');
    });
  });

  describe('3. JavaScript & TypeScript Adapter', () => {
    it('extracts classes, methods, functions, imports, and calls with spans', () => {
      const tsCode = `import { Agent, Tool } from '@caim/core';
import * as path from 'path';

/**
 * Autonomous coordinator class
 */
export class CoordinatorAgent extends Agent {
  private activeTool: Tool;

  public async executeTask(query: string, timeout: number = 30): Promise<boolean> {
    console.log("Executing", query);
    return true;
  }
}`;

      const out = JsTsAdapter.parse('agent.ts', tsCode);
      expect(out.has_parse_error).toBe(false);
      expect(out.imports.length).toBe(2);
      expect(out.imports[0].module_specifier).toBe('@caim/core');
      expect(out.imports[0].imported_symbols.map(s => s.name)).toContain('Agent');

      const classSym = out.symbols.find(s => s.name === 'CoordinatorAgent');
      expect(classSym).toBeDefined();
      expect(classSym?.kind).toBe('CLASS');
      expect(classSym?.modifiers).toContain('export');
      expect(classSym?.docstring).toContain('Autonomous coordinator class');

      const funcSym = out.symbols.find(s => s.name === 'executeTask');
      expect(funcSym).toBeDefined();
      expect(funcSym?.kind).toBe('METHOD');
      expect(funcSym?.parameters.length).toBe(2);
      expect(funcSym?.parameters[0].name).toBe('query');
      expect(funcSym?.parameters[0].type).toBe('string');
    });
  });

  describe('4. Python Adapter', () => {
    it('extracts Python functions, classes, decorators, docstrings, and imports', () => {
      const pyCode = `import os
from langchain_core.tools import tool
from typing import List, Optional

@tool
def calculate_trajectory(velocity: float, angle: float = 45.0) -> dict:
    """Calculates orbital trajectory parameters."""
    result = math.sin(angle) * velocity
    return {"trajectory": result}

class TrajectorySolver:
    def __init__(self, name: str):
        self.name = name
`;

      const out = PythonAdapter.parse('solver.py', pyCode);
      expect(out.has_parse_error).toBe(false);
      expect(out.imports.length).toBe(3);

      const funcSym = out.symbols.find(s => s.name === 'calculate_trajectory');
      expect(funcSym).toBeDefined();
      expect(funcSym?.decorators).toContain('tool');
      expect(funcSym?.docstring).toContain('Calculates orbital trajectory parameters.');
      expect(funcSym?.parameters.length).toBe(2);
      expect(funcSym?.parameters[0].name).toBe('velocity');
      expect(funcSym?.parameters[1].default_value).toBe('45.0');

      const classSym = out.symbols.find(s => s.name === 'TrajectorySolver');
      expect(classSym).toBeDefined();
      expect(classSym?.kind).toBe('CLASS');
    });
  });

  describe('5. Go Adapter', () => {
    it('extracts Go package, structs, interfaces, methods, and visibility', () => {
      const goCode = `package gateway

import (
	"context"
	"net/http"
)

type ServerConfig struct {
	Port int
}

type AgentInvoker interface {
	Invoke(ctx context.Context, input string) (string, error)
}

func (s *ServerConfig) StartServer() error {
	http.HandleFunc("/health", nil)
	return nil
}
`;

      const out = GoAdapter.parse('server.go', goCode);
      expect(out.has_parse_error).toBe(false);
      expect(out.symbols.some(s => s.name === 'gateway' && s.kind === 'MODULE')).toBe(true);

      const structSym = out.symbols.find(s => s.name === 'ServerConfig');
      expect(structSym?.kind).toBe('STRUCT');
      expect(structSym?.visibility).toBe('PUBLIC');

      const ifaceSym = out.symbols.find(s => s.name === 'AgentInvoker');
      expect(ifaceSym?.kind).toBe('INTERFACE');

      const methodSym = out.symbols.find(s => s.name === 'StartServer');
      expect(methodSym?.kind).toBe('METHOD');
      expect(methodSym?.parent_symbol).toBe('ServerConfig');
    });
  });

  describe('6. Structured Data & Container Intelligence', () => {
    it('parses Dockerfile base images, env variables, expose ports, entrypoint, and cmd', () => {
      const dockerfile = `FROM python:3.11-alpine
WORKDIR /usr/src/app
ENV APP_ENV=production
ENV PORT=8080
EXPOSE 8080 8443
ENTRYPOINT ["python"]
CMD ["app.py"]`;

      const out = StructuredAdapter.parse('Dockerfile', dockerfile, 'dockerfile');
      expect(out.has_parse_error).toBe(false);
      expect(out.deployment?.base_image).toBe('python:3.11-alpine');
      expect(out.deployment?.ports).toEqual([8080, 8443]);
      expect(out.deployment?.workdir).toBe('/usr/src/app');
      expect(out.env_vars.length).toBe(2);
      expect(out.env_vars.map(e => e.name)).toContain('APP_ENV');
    });

    it('parses package.json dependencies and versions', () => {
      const pkgJson = JSON.stringify({
        name: '@caim/test-agent',
        version: '1.0.0',
        dependencies: {
          'langchain': '^0.1.20',
          '@modelcontextprotocol/sdk': '1.0.1'
        },
        devDependencies: {
          'typescript': '^5.4.0'
        }
      });

      const out = StructuredAdapter.parse('package.json', pkgJson, 'json');
      expect(out.has_parse_error).toBe(false);
      expect(out.dependencies.length).toBe(3);
      expect(out.dependencies.find(d => d.name === 'langchain')?.version).toBe('^0.1.20');
    });

    it('records explicit partial coverage and error info on malformed JSON without crashing', () => {
      const badJson = '{"name": "broken", "unclosed: }';
      const out = StructuredAdapter.parse('broken.json', badJson, 'json');
      expect(out.has_parse_error).toBe(true);
      expect(out.error_message).toBeDefined();
    });
  });

  describe('7. Protocol Intelligence Detector', () => {
    it('detects Model Context Protocol (MCP) server tools, transports, and schemas', () => {
      const mcpCode = `import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server({ name: "db-mcp", version: "1.0.0" }, { capabilities: { tools: {} } });
server.tool("search_database", "Performs semantic search across vector DB", async () => {});
const transport = new StdioServerTransport();
await server.connect(transport);`;

      const facts = ProtocolDetector.detect('mcp_server.ts', mcpCode);
      expect(facts.length).toBeGreaterThan(0);
      const mcp = facts.find(f => f.protocol_kind === 'MCP');
      expect(mcp).toBeDefined();
      expect(mcp?.mcp_details?.transports).toContain('stdio');
      expect(mcp?.mcp_details?.tools.some(t => t.name === 'search_database')).toBe(true);
    });

    it('detects Agent-to-Agent (A2A) protocol declarations', () => {
      const a2aJson = JSON.stringify({
        a2a_version: "1.0.0",
        agent_id: "did:agent:caim:test-agent-01",
        name: "SecurityAuditor",
        capabilities: ["STATIC_ANALYSIS", "POLICY_EVALUATION"],
        endpoint: "https://agent.internal.net/a2a"
      });

      const facts = ProtocolDetector.detect('agent-card.json', a2aJson, JSON.parse(a2aJson));
      const a2a = facts.find(f => f.protocol_kind === 'A2A');
      expect(a2a).toBeDefined();
      expect(a2a?.a2a_details?.agent_id).toBe('did:agent:caim:test-agent-01');
      expect(a2a?.a2a_details?.agent_cards[0].capabilities).toContain('STATIC_ANALYSIS');
    });

    it('detects OpenAPI paths and operations', () => {
      const openapiData = {
        openapi: '3.1.0',
        info: { title: 'Agent Gateway API', version: '1.0.0' },
        paths: {
          '/api/v1/invoke': {
            post: {
              operationId: 'invokeAgent',
              summary: 'Invokes autonomous agent workflow',
              parameters: [{ name: 'agent_id' }]
            }
          }
        }
      };

      const facts = ProtocolDetector.detect('openapi.json', JSON.stringify(openapiData), openapiData);
      const oas = facts.find(f => f.protocol_kind === 'OPENAPI');
      expect(oas).toBeDefined();
      expect(oas?.endpoints.length).toBe(1);
      expect(oas?.endpoints[0].method).toBe('POST');
      expect(oas?.endpoints[0].operation_id).toBe('invokeAgent');
    });
  });

  describe('8. Framework Fingerprinting', () => {
    it('detects active agent frameworks with multi-source evidence and confidence', () => {
      const source = `from autogen import ConversableAgent, UserProxyAgent
import os

agent = ConversableAgent(
    name="Coder",
    llm_config={"model": "gpt-4o"}
)`;
      const deps = [{ name: 'pyautogen', version: '0.2.18', kind: 'dependencies' }];
      const fingerprints = FrameworkDetector.detect('agent.py', source, deps);

      const autogen = fingerprints.find(f => f.framework_name === 'AutoGen');
      expect(autogen).toBeDefined();
      expect(autogen?.framework_category).toBe('MULTI_AGENT');
      expect(autogen?.detected_version).toBe('0.2.18');
      expect(autogen?.confidence).toBeGreaterThanOrEqual(0.9);
      expect(autogen?.evidence.some(e => e.type === 'MANIFEST_DEPENDENCY')).toBe(true);
      expect(autogen?.evidence.some(e => e.type === 'IMPORT')).toBe(true);
    });
  });

  describe('9. Configuration, Permissions & Secret Masking', () => {
    it('extracts env variables, model parameters, permissions, and masks secret keys', () => {
      const code = `import os
import requests
import child_process

OPENAI_KEY = os.environ.get("OPENAI_API_KEY", "fallback")
DATABASE_URL = os.getenv("DATABASE_URL")
TIMEOUT = os.getenv("REQUEST_TIMEOUT", "60")

model_name = "claude-3-5-sonnet"
temperature = 0.2
max_tokens = 2048

def run_query():
    requests.get("https://api.openai.com")
    child_process.execSync("ls -la")
`;

      const config = ConfigExtractor.extract('main.py', code);
      expect(config.env_vars.map(e => e.name)).toContain('OPENAI_API_KEY');
      expect(config.env_vars.map(e => e.name)).toContain('DATABASE_URL');

      const claudeModel = config.models.find(m => m.model_id === 'claude-3-5-sonnet');
      expect(claudeModel).toBeDefined();
      expect(claudeModel?.provider).toBe('anthropic');
      expect(claudeModel?.temperature).toBe(0.2);
      expect(claudeModel?.max_tokens).toBe(2048);

      expect(config.permissions.some(p => p.capability === 'NETWORK')).toBe(true);
      expect(config.permissions.some(p => p.capability === 'SUBPROCESS_EXEC')).toBe(true);

      const secretRef = config.secrets.find(s => s.secret_name === 'OPENAI_API_KEY');
      expect(secretRef).toBeDefined();
      expect(secretRef?.category).toBe('API_KEY');
      expect(secretRef?.is_masked).toBe(true);
    });
  });

  describe('10. Parser Registry & Multi-File Pipeline Orchestration', () => {
    it('processes multi-file artifact bundles and computes byte coverage ratio without risk judgments', () => {
      const files = [
        {
          path: 'agent/server.ts',
          content: `import { Server } from "@modelcontextprotocol/sdk/server/index.js";
export const apiKey = process.env.API_KEY;`
        },
        {
          path: 'requirements.txt',
          content: `langchain==0.1.0\nautogen>=0.2.0\n`
        },
        {
          path: 'Dockerfile',
          content: `FROM node:20-alpine\nEXPOSE 3000\n`
        },
        {
          path: 'model_weights.safetensors',
          content: Buffer.alloc(32)
        }
      ];

      const result = SyntaxIntelligencePipeline.processArtifact('artifact-bundle-001', files);

      expect(result.artifact_id).toBe('artifact-bundle-001');
      expect(result.total_files).toBe(4);
      expect(result.byte_coverage_ratio).toBeGreaterThan(0);
      expect(result.file_facts.length).toBe(4);

      // Verify binary file preservation
      const binaryFact = result.file_facts.find(f => f.file_path === 'model_weights.safetensors');
      expect(binaryFact?.status).toBe('BINARY_PRESERVED');

      // Verify strict non-judgement invariant: No vulnerability or risk score fields in result
      expect((result as any).risk_score).toBeUndefined();
      expect((result as any).vulnerabilities).toBeUndefined();
      expect((result as any).security_verdict).toBeUndefined();

      // Cryptographic provenance
      expect(result.provenance.engine_signature).toContain('caim:syntax-intelligence-pipeline');
      expect(result.provenance.input_hashes.length).toBeGreaterThan(0);
    });
  });
});
