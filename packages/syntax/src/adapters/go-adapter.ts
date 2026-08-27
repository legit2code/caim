import { 
  SymbolFact, 
  ImportFact, 
  ExportFact, 
  CallSiteFact, 
  SourceSpan,
  SymbolKind,
  SymbolVisibility,
  ImportedSymbol
} from '../types.ts';
import { SourceSpanUtil } from '../source-span-util.ts';

export interface GoParseOutput {
  symbols: SymbolFact[];
  imports: ImportFact[];
  exports: ExportFact[];
  call_sites: CallSiteFact[];
  has_parse_error: boolean;
  error_message?: string;
  error_location?: { line: number; col: number; offset: number };
}

export class GoAdapter {
  public static readonly ID = 'syntax-adapter:go';
  public static readonly VERSION = '1.0.0';

  /**
   * Parses Go source code into structured AST facts with exact line & column spans
   */
  public static parse(filePath: string, sourceText: string): GoParseOutput {
    const lineStarts = SourceSpanUtil.createLineIndex(sourceText);
    const symbols: SymbolFact[] = [];
    const imports: ImportFact[] = [];
    const exports: ExportFact[] = [];
    const call_sites: CallSiteFact[] = [];

    try {
      this.extractPackageAndImports(filePath, sourceText, lineStarts, imports, symbols);
      this.extractStructsAndInterfaces(filePath, sourceText, lineStarts, symbols, exports);
      this.extractFunctionsAndMethods(filePath, sourceText, lineStarts, symbols, exports);
      this.extractCallSites(filePath, sourceText, lineStarts, call_sites);

      return {
        symbols,
        imports,
        exports,
        call_sites,
        has_parse_error: false,
      };
    } catch (err: any) {
      return {
        symbols,
        imports,
        exports,
        call_sites,
        has_parse_error: true,
        error_message: err?.message || 'Go parser encountered a tokenizing error',
      };
    }
  }

  private static extractPackageAndImports(
    filePath: string,
    source: string,
    lineStarts: number[],
    imports: ImportFact[],
    symbols: SymbolFact[]
  ): void {
    // 1. Package statement: package main
    const pkgRegex = /package\s+([\w]+)/;
    const pkgMatch = pkgRegex.exec(source);
    if (pkgMatch) {
      const pkgName = pkgMatch[1];
      const span = SourceSpanUtil.offsetToSpan(filePath, source, pkgMatch.index, pkgMatch.index + pkgMatch[0].length, lineStarts, pkgName);
      symbols.push({
        name: pkgName,
        kind: 'MODULE',
        visibility: 'PUBLIC',
        span,
        parameters: [],
        modifiers: ['package'],
        decorators: [],
      });
    }

    // 2. Single import: import "fmt" or import mypkg "github.com/org/repo"
    const singleImportRegex = /import\s+(?:([\w]+)\s+)?["']([^"']+)["']/g;
    let match: RegExpExecArray | null;

    while ((match = singleImportRegex.exec(source)) !== null) {
      const alias = match[1];
      const modPath = match[2];
      const startOffset = match.index;
      const endOffset = startOffset + match[0].length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts, modPath);

      imports.push({
        module_specifier: modPath,
        import_kind: 'STATIC',
        imported_symbols: [{
          name: alias || modPath.split('/').pop() || modPath,
          alias,
          is_default: true,
          is_type_only: false,
          is_namespace: false,
        }],
        raw_statement: match[0],
        span,
      });
    }

    // 3. Multi import: import ( ... )
    const multiImportRegex = /import\s*\(([\s\S]*?)\)/g;
    while ((match = multiImportRegex.exec(source)) !== null) {
      const blockContent = match[1];
      const blockStart = match.index;
      const lineItemRegex = /(?:([\w.]+)\s+)?["']([^"']+)["']/g;
      let lineMatch: RegExpExecArray | null;

      while ((lineMatch = lineItemRegex.exec(blockContent)) !== null) {
        const alias = lineMatch[1];
        const modPath = lineMatch[2];
        const itemStart = blockStart + lineMatch.index;
        const itemEnd = itemStart + lineMatch[0].length;
        const span = SourceSpanUtil.offsetToSpan(filePath, source, itemStart, itemEnd, lineStarts, modPath);

        imports.push({
          module_specifier: modPath,
          import_kind: 'STATIC',
          imported_symbols: [{
            name: alias || modPath.split('/').pop() || modPath,
            alias,
            is_default: true,
            is_type_only: false,
            is_namespace: false,
          }],
          raw_statement: lineMatch[0],
          span,
        });
      }
    }
  }

  private static extractStructsAndInterfaces(
    filePath: string,
    source: string,
    lineStarts: number[],
    symbols: SymbolFact[],
    exports: ExportFact[]
  ): void {
    // type Name struct { ... } or type Name interface { ... }
    const typeDeclRegex = /type\s+([\w]+)\s+(struct|interface)\s*\{/g;
    let match: RegExpExecArray | null;

    while ((match = typeDeclRegex.exec(source)) !== null) {
      const name = match[1];
      const kind = match[2];
      const startOffset = match.index;
      const endOffset = startOffset + match[0].length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts, name);

      const isExported = /^[A-Z]/.test(name);
      const visibility: SymbolVisibility = isExported ? 'PUBLIC' : 'PACKAGE';

      symbols.push({
        name,
        kind: kind === 'struct' ? 'STRUCT' : 'INTERFACE',
        visibility,
        span,
        parameters: [],
        modifiers: isExported ? ['export'] : [],
        decorators: [],
      });

      if (isExported) {
        exports.push({
          exported_symbol: name,
          is_default: false,
          is_reexport: false,
          span,
        });
      }
    }
  }

  private static extractFunctionsAndMethods(
    filePath: string,
    source: string,
    lineStarts: number[],
    symbols: SymbolFact[],
    exports: ExportFact[]
  ): void {
    // func (recv Receiver) Name(params) (returns) { or func Name(params) (returns) {
    const funcRegex = /func\s+(?:\(([^)]+)\)\s+)?([\w]+)\s*\(([^)]*)\)(?:\s*(?:\(([^)]+)\)|([\w*.]+)))?\s*\{/g;
    let match: RegExpExecArray | null;

    while ((match = funcRegex.exec(source)) !== null) {
      const receiver = match[1]?.trim();
      const name = match[2];
      const rawParams = match[3];
      const returnGroup = match[4] || match[5];

      const startOffset = match.index;
      const endOffset = startOffset + match[0].length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts, receiver ? `${receiver}.${name}` : name);

      const isExported = /^[A-Z]/.test(name);
      const visibility: SymbolVisibility = isExported ? 'PUBLIC' : 'PACKAGE';

      const isMethod = Boolean(receiver);
      let receiverType: string | undefined;
      if (receiver) {
        const parts = receiver.split(/\s+/);
        receiverType = parts.pop()?.replace(/^\*/, '');
      }

      symbols.push({
        name,
        kind: isMethod ? 'METHOD' : 'FUNCTION',
        visibility,
        parent_symbol: receiverType,
        span,
        parameters: this.parseGoParams(rawParams),
        return_type: returnGroup?.trim(),
        modifiers: isExported ? ['export'] : [],
        decorators: [],
      });

      if (isExported && !isMethod) {
        exports.push({
          exported_symbol: name,
          is_default: false,
          is_reexport: false,
          span,
        });
      }
    }
  }

  private static extractCallSites(
    filePath: string,
    source: string,
    lineStarts: number[],
    call_sites: CallSiteFact[]
  ): void {
    const callRegex = /([\w]+(?:\.[\w]+)*)\s*\(([^)]*)\)/g;
    let match: RegExpExecArray | null;

    while ((match = callRegex.exec(source)) !== null) {
      const fullCallee = match[1];
      const rawArgs = match[2];

      if (['func', 'if', 'for', 'switch', 'select', 'return', 'type', 'range'].includes(fullCallee)) continue;

      const startOffset = match.index;
      const endOffset = startOffset + match[0].length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts, fullCallee);

      let calleeName = fullCallee;
      let receiver: string | undefined;

      if (fullCallee.includes('.')) {
        const parts = fullCallee.split('.');
        calleeName = parts.pop()!;
        receiver = parts.join('.');
      }

      const args = rawArgs.split(',').map(a => a.trim()).filter(Boolean);

      call_sites.push({
        callee_name: calleeName,
        receiver,
        argument_count: args.length,
        arguments_summary: args.slice(0, 5),
        is_await: false,
        span,
      });
    }
  }

  private static parseGoParams(raw?: string) {
    if (!raw || !raw.trim()) return [];
    return raw.split(',').map(p => {
      const trimmed = p.trim();
      const parts = trimmed.split(/\s+/);
      const isRest = parts[1]?.startsWith('...') || parts[0]?.startsWith('...');
      if (parts.length === 1) {
        return { name: parts[0], is_rest: isRest };
      }
      return {
        name: parts[0],
        type: parts.slice(1).join(' '),
        is_rest: isRest,
      };
    }).filter(p => Boolean(p.name));
  }
}
