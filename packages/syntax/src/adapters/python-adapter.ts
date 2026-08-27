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

export interface PythonParseOutput {
  symbols: SymbolFact[];
  imports: ImportFact[];
  exports: ExportFact[];
  call_sites: CallSiteFact[];
  has_parse_error: boolean;
  error_message?: string;
  error_location?: { line: number; col: number; offset: number };
}

export class PythonAdapter {
  public static readonly ID = 'syntax-adapter:python';
  public static readonly VERSION = '1.0.0';

  /**
   * Parses Python source code into structured AST facts with exact line & column spans
   */
  public static parse(filePath: string, sourceText: string): PythonParseOutput {
    const lineStarts = SourceSpanUtil.createLineIndex(sourceText);
    const symbols: SymbolFact[] = [];
    const imports: ImportFact[] = [];
    const exports: ExportFact[] = [];
    const call_sites: CallSiteFact[] = [];

    try {
      this.extractImports(filePath, sourceText, lineStarts, imports);
      this.extractFunctionsAndClasses(filePath, sourceText, lineStarts, symbols, exports);
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
        error_message: err?.message || 'Python parser encountered a tokenizing error',
      };
    }
  }

  private static extractImports(
    filePath: string,
    source: string,
    lineStarts: number[],
    imports: ImportFact[]
  ): void {
    // 1. from module import a, b as c, d
    const fromImportRegex = /(?:from\s+([\w.]+)\s+import\s+([^#\n]+))/g;
    let match: RegExpExecArray | null;

    while ((match = fromImportRegex.exec(source)) !== null) {
      const fullMatch = match[0];
      const moduleSpecifier = match[1];
      const itemsRaw = match[2];

      const startOffset = match.index;
      const endOffset = startOffset + fullMatch.length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts, moduleSpecifier);

      const importedSymbols: ImportedSymbol[] = [];
      const parts = itemsRaw.replace(/[()]/g, '').split(',');

      for (const p of parts) {
        const trimmed = p.trim();
        if (!trimmed) continue;
        if (trimmed.includes(' as ')) {
          const [orig, alias] = trimmed.split(/\s+as\s+/);
          importedSymbols.push({
            name: orig.trim(),
            alias: alias.trim(),
            is_default: false,
            is_type_only: false,
            is_namespace: false,
          });
        } else {
          importedSymbols.push({
            name: trimmed,
            is_default: false,
            is_type_only: false,
            is_namespace: false,
          });
        }
      }

      imports.push({
        module_specifier: moduleSpecifier,
        import_kind: 'STATIC',
        imported_symbols: importedSymbols,
        raw_statement: fullMatch,
        span,
      });
    }

    // 2. import module, module2 as m2
    const directImportRegex = /(?:^|\n)\s*(?:import\s+([^#\n]+))/g;
    while ((match = directImportRegex.exec(source)) !== null) {
      const fullMatch = match[0].trim();
      const itemsRaw = match[1];

      const startOffset = match.index;
      const endOffset = startOffset + match[0].length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts);

      const modules = itemsRaw.split(',');
      for (const m of modules) {
        const trimmed = m.trim();
        if (!trimmed) continue;
        if (trimmed.includes(' as ')) {
          const [orig, alias] = trimmed.split(/\s+as\s+/);
          imports.push({
            module_specifier: orig.trim(),
            import_kind: 'STATIC',
            imported_symbols: [{
              name: orig.trim(),
              alias: alias.trim(),
              is_default: true,
              is_type_only: false,
              is_namespace: false,
            }],
            raw_statement: fullMatch,
            span,
          });
        } else {
          imports.push({
            module_specifier: trimmed,
            import_kind: 'STATIC',
            imported_symbols: [{
              name: trimmed,
              is_default: true,
              is_type_only: false,
              is_namespace: false,
            }],
            raw_statement: fullMatch,
            span,
          });
        }
      }
    }
  }

  private static extractFunctionsAndClasses(
    filePath: string,
    source: string,
    lineStarts: number[],
    symbols: SymbolFact[],
    exports: ExportFact[]
  ): void {
    // Collect docstrings
    const docstringRegex = /(?:"""([\s\S]*?)"""|'''([\s\S]*?)''')/;

    // Match class and def statements with leading decorators
    const statementRegex = /(?:((?:@[^\n]+\n\s*)*))(?:\s*)(class|def|async\s+def)\s+([\w]+)(?:\s*(?:\(([^)]*)\))?)?(?:\s*->\s*([^:]+))?\s*:/g;
    let match: RegExpExecArray | null;

    while ((match = statementRegex.exec(source)) !== null) {
      const fullHeader = match[0];
      const decoratorsRaw = match[1];
      const keyword = match[2];
      const name = match[3];
      const rawParamsOrBases = match[4];
      const returnType = match[5]?.trim();

      const startOffset = match.index;
      const endOffset = startOffset + fullHeader.length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts, name);

      const decorators = decoratorsRaw
        ? decoratorsRaw.split('\n').map(d => d.trim().replace(/^@/, '')).filter(Boolean)
        : [];

      // Lookahead for immediate docstring
      const followingSlice = source.substring(endOffset, Math.min(source.length, endOffset + 500));
      const docMatch = docstringRegex.exec(followingSlice);
      const docstring = docMatch ? (docMatch[1] || docMatch[2]).trim() : undefined;

      const isPrivate = name.startsWith('_') && !name.startsWith('__');
      const isDunder = name.startsWith('__') && name.endsWith('__');
      const visibility: SymbolVisibility = isPrivate ? 'PRIVATE' : 'PUBLIC';

      if (keyword === 'class') {
        const bases = rawParamsOrBases ? rawParamsOrBases.split(',').map(b => b.trim()).filter(Boolean) : [];
        symbols.push({
          name,
          kind: 'CLASS',
          visibility,
          span,
          docstring,
          modifiers: bases.length > 0 ? bases.map(b => `extends:${b}`) : [],
          decorators,
          parameters: [],
        });

        // Top-level classes in Python are implicitly exported if not private
        if (!name.startsWith('_')) {
          exports.push({
            exported_symbol: name,
            is_default: false,
            is_reexport: false,
            span,
          });
        }
      } else {
        const isAsync = keyword.includes('async');
        const params = this.parsePythonParams(rawParamsOrBases);

        symbols.push({
          name,
          kind: isAsync ? 'ASYNC_FUNCTION' : 'FUNCTION',
          visibility: isDunder ? 'INTERNAL' : visibility,
          span,
          docstring,
          return_type: returnType,
          parameters: params,
          modifiers: isAsync ? ['async'] : [],
          decorators,
        });

        if (!name.startsWith('_')) {
          exports.push({
            exported_symbol: name,
            is_default: false,
            is_reexport: false,
            span,
          });
        }
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

      if (['def', 'class', 'if', 'elif', 'while', 'for', 'with', 'except', 'return'].includes(fullCallee)) continue;

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

  private static parsePythonParams(raw?: string) {
    if (!raw || !raw.trim()) return [];
    return raw.split(',').map(p => {
      const trimmed = p.trim();
      const isRest = trimmed.startsWith('*') || trimmed.startsWith('**');
      const clean = trimmed.replace(/^\*+/, '');

      let name = clean;
      let type: string | undefined;
      let defaultVal: string | undefined;

      if (clean.includes('=')) {
        const [left, right] = clean.split('=');
        defaultVal = right.trim();
        if (left.includes(':')) {
          const [n, t] = left.split(':');
          name = n.trim();
          type = t.trim();
        } else {
          name = left.trim();
        }
      } else if (clean.includes(':')) {
        const [n, t] = clean.split(':');
        name = n.trim();
        type = t.trim();
      }

      return {
        name: name.trim(),
        type,
        default_value: defaultVal,
        is_rest: isRest,
      };
    }).filter(p => Boolean(p.name));
  }
}
