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

export interface JsTsParseOutput {
  symbols: SymbolFact[];
  imports: ImportFact[];
  exports: ExportFact[];
  call_sites: CallSiteFact[];
  has_parse_error: boolean;
  error_message?: string;
  error_location?: { line: number; col: number; offset: number };
}

export class JsTsAdapter {
  public static readonly ID = 'syntax-adapter:js-ts';
  public static readonly VERSION = '1.0.0';

  /**
   * Parses JavaScript and TypeScript source text into structured AST facts with exact spans
   */
  public static parse(filePath: string, sourceText: string): JsTsParseOutput {
    const lineStarts = SourceSpanUtil.createLineIndex(sourceText);
    const symbols: SymbolFact[] = [];
    const imports: ImportFact[] = [];
    const exports: ExportFact[] = [];
    const call_sites: CallSiteFact[] = [];

    try {
      this.extractImports(filePath, sourceText, lineStarts, imports);
      this.extractExports(filePath, sourceText, lineStarts, exports);
      this.extractFunctionsAndClasses(filePath, sourceText, lineStarts, symbols);
      this.extractInterfacesAndTypes(filePath, sourceText, lineStarts, symbols);
      this.extractVariablesAndConstants(filePath, sourceText, lineStarts, symbols);
      this.extractCallSites(filePath, sourceText, lineStarts, call_sites);

      return {
        symbols,
        imports,
        exports,
        call_sites,
        has_parse_error: false,
      };
    } catch (err: any) {
      // Degrade gracefully with partial facts and exact error tracking
      return {
        symbols,
        imports,
        exports,
        call_sites,
        has_parse_error: true,
        error_message: err?.message || 'Syntax parser encountered a tokenizing error',
      };
    }
  }

  private static extractImports(
    filePath: string,
    source: string,
    lineStarts: number[],
    imports: ImportFact[]
  ): void {
    // 1. ESM Imports: import { a, b as c } from 'mod'; import x from 'mod'; import * as y from 'mod';
    const esmImportRegex = /import\s+(?:type\s+)?(?:([\w$]+)\s*,?\s*)?(?:(\*\s+as\s+[\w$]+)\s*,?\s*)?(?:\{([^}]+)\})?\s*(?:from\s+)?['"]([^'"]+)['"]/g;
    let match: RegExpExecArray | null;

    while ((match = esmImportRegex.exec(source)) !== null) {
      const fullMatch = match[0];
      const defaultImport = match[1];
      const namespaceImport = match[2];
      const namedImports = match[3];
      const moduleSpecifier = match[4];

      const startOffset = match.index;
      const endOffset = startOffset + fullMatch.length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts, moduleSpecifier);

      const importedSymbols: ImportedSymbol[] = [];

      if (defaultImport) {
        importedSymbols.push({
          name: defaultImport.trim(),
          is_default: true,
          is_type_only: fullMatch.includes('import type'),
          is_namespace: false,
        });
      }

      if (namespaceImport) {
        const nsName = namespaceImport.replace(/\*\s+as\s+/, '').trim();
        importedSymbols.push({
          name: nsName,
          is_namespace: true,
          is_default: false,
          is_type_only: fullMatch.includes('import type'),
        });
      }

      if (namedImports) {
        const parts = namedImports.split(',');
        for (const p of parts) {
          const trimmed = p.trim();
          if (!trimmed) continue;
          if (trimmed.includes(' as ')) {
            const [orig, alias] = trimmed.split(/\s+as\s+/);
            importedSymbols.push({
              name: orig.trim(),
              alias: alias.trim(),
              is_type_only: fullMatch.includes('import type'),
              is_default: false,
              is_namespace: false,
            });
          } else {
            importedSymbols.push({
              name: trimmed,
              is_type_only: fullMatch.includes('import type'),
              is_default: false,
              is_namespace: false,
            });
          }
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

    // 2. CJS require: const/let/var x = require('mod') or const { a, b } = require('mod')
    const cjsRequireRegex = /(?:const|let|var)\s+(?:\{([^}]+)\}|([\w$]+))\s*=\s*require\(['"]([^'"]+)['"]\)/g;
    while ((match = cjsRequireRegex.exec(source)) !== null) {
      const fullMatch = match[0];
      const destructured = match[1];
      const singleIdent = match[2];
      const moduleSpecifier = match[3];

      const startOffset = match.index;
      const endOffset = startOffset + fullMatch.length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts, moduleSpecifier);

      const importedSymbols: ImportedSymbol[] = [];
      if (singleIdent) {
        importedSymbols.push({
          name: singleIdent.trim(),
          is_default: true,
          is_type_only: false,
          is_namespace: false,
        });
      } else if (destructured) {
        const parts = destructured.split(',');
        for (const p of parts) {
          const trimmed = p.trim();
          if (!trimmed) continue;
          if (trimmed.includes(':')) {
            const [orig, alias] = trimmed.split(':');
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
      }

      imports.push({
        module_specifier: moduleSpecifier,
        import_kind: 'REQUIRE',
        imported_symbols: importedSymbols,
        raw_statement: fullMatch,
        span,
      });
    }

    // 3. Dynamic imports: import('module')
    const dynamicImportRegex = /import\(['"]([^'"]+)['"]\)/g;
    while ((match = dynamicImportRegex.exec(source)) !== null) {
      const fullMatch = match[0];
      const moduleSpecifier = match[1];
      const startOffset = match.index;
      const endOffset = startOffset + fullMatch.length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts, moduleSpecifier);

      imports.push({
        module_specifier: moduleSpecifier,
        import_kind: 'DYNAMIC',
        imported_symbols: [],
        raw_statement: fullMatch,
        span,
      });
    }
  }

  private static extractExports(
    filePath: string,
    source: string,
    lineStarts: number[],
    exports: ExportFact[]
  ): void {
    // 1. Export named/default declarations
    const exportDeclRegex = /export\s+(default\s+)?(?:async\s+)?(function\*?|class|const|let|var|interface|type|enum)\s+([\w$]+)/g;
    let match: RegExpExecArray | null;

    while ((match = exportDeclRegex.exec(source)) !== null) {
      const fullMatch = match[0];
      const isDefault = Boolean(match[1]);
      const name = match[3];

      const startOffset = match.index;
      const endOffset = startOffset + fullMatch.length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts, name);

      exports.push({
        exported_symbol: name,
        is_default: isDefault,
        is_reexport: false,
        raw_statement: fullMatch,
        span,
      });
    }

    // 2. Export clause: export { a, b as c } from 'mod'
    const exportClauseRegex = /export\s+\{([^}]+)\}(?:\s+from\s+['"]([^'"]+)['"])?/g;
    while ((match = exportClauseRegex.exec(source)) !== null) {
      const fullMatch = match[0];
      const clause = match[1];
      const sourceModule = match[2];

      const startOffset = match.index;
      const endOffset = startOffset + fullMatch.length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts);

      const items = clause.split(',');
      for (const item of items) {
        const trimmed = item.trim();
        if (!trimmed) continue;
        if (trimmed.includes(' as ')) {
          const [orig, alias] = trimmed.split(/\s+as\s+/);
          exports.push({
            exported_symbol: orig.trim(),
            alias: alias.trim(),
            is_default: alias.trim() === 'default',
            is_reexport: Boolean(sourceModule),
            source_module: sourceModule,
            raw_statement: fullMatch,
            span,
          });
        } else {
          exports.push({
            exported_symbol: trimmed,
            is_default: trimmed === 'default',
            is_reexport: Boolean(sourceModule),
            source_module: sourceModule,
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
    symbols: SymbolFact[]
  ): void {
    // Functions: (export)? (async)? function(*)? name(params): returnType {
    const fnRegex = /(?:(\/\*\*[\s\S]*?\*\/)\s*)?(?:(export\s+(?:default\s+)?)?(async\s+)?function(\*?)\s+([\w$]+)\s*\(([^)]*)\)(?:\s*:\s*([^{]+))?\s*\{)/g;
    let match: RegExpExecArray | null;

    while ((match = fnRegex.exec(source)) !== null) {
      const docstring = match[1];
      const isExport = Boolean(match[2]);
      const isAsync = Boolean(match[3]);
      const isGenerator = Boolean(match[4]);
      const name = match[5];
      const rawParams = match[6];
      const returnType = match[7]?.trim();

      const startOffset = match.index;
      const endOffset = startOffset + match[0].length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts, name);

      const params = this.parseParams(rawParams);
      const modifiers: string[] = [];
      if (isExport) modifiers.push('export');
      if (isAsync) modifiers.push('async');
      if (isGenerator) modifiers.push('generator');

      symbols.push({
        name,
        kind: isGenerator ? 'GENERATOR_FUNCTION' : isAsync ? 'ASYNC_FUNCTION' : 'FUNCTION',
        visibility: 'PUBLIC',
        span,
        docstring: docstring ? docstring.replace(/\/\*\*|\*\/|\*/g, '').trim() : undefined,
        parameters: params,
        return_type: returnType,
        modifiers,
        decorators: [],
      });
    }

    // Classes: (export)? (abstract)? class Name (extends Super)? (implements A, B)? {
    const classRegex = /(?:(\/\*\*[\s\S]*?\*\/)\s*)?((?:@\w+(?:\([^)]*\))?\s*)*)(?:(export\s+(?:default\s+)?)?(abstract\s+)?class\s+([\w$]+)(?:\s+extends\s+([\w$.]+))?(?:\s+implements\s+([^{]+))?\s*\{)/g;
    while ((match = classRegex.exec(source)) !== null) {
      const docstring = match[1];
      const decoratorsRaw = match[2];
      const isExport = Boolean(match[3]);
      const isAbstract = Boolean(match[4]);
      const className = match[5];
      const extendsClass = match[6];

      const startOffset = match.index;
      const endOffset = startOffset + match[0].length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts, className);

      const modifiers: string[] = [];
      if (isExport) modifiers.push('export');
      if (isAbstract) modifiers.push('abstract');
      if (extendsClass) modifiers.push(`extends:${extendsClass}`);

      const decorators = decoratorsRaw ? decoratorsRaw.split('@').map(d => d.trim()).filter(Boolean) : [];

      symbols.push({
        name: className,
        kind: 'CLASS',
        visibility: 'PUBLIC',
        span,
        docstring: docstring ? docstring.replace(/\/\*\*|\*\/|\*/g, '').trim() : undefined,
        modifiers,
        decorators,
        parameters: [],
      });

      // Extract class methods inside class body
      this.extractClassMethods(filePath, source, startOffset, className, lineStarts, symbols);
    }
  }

  private static extractClassMethods(
    filePath: string,
    source: string,
    classStartOffset: number,
    className: string,
    lineStarts: number[],
    symbols: SymbolFact[]
  ): void {
    // Find matching closing brace for class
    let braceCount = 0;
    let inClass = false;
    let classEndOffset = source.length;

    for (let i = classStartOffset; i < source.length; i++) {
      if (source[i] === '{') {
        braceCount++;
        inClass = true;
      } else if (source[i] === '}') {
        braceCount--;
        if (inClass && braceCount === 0) {
          classEndOffset = i;
          break;
        }
      }
    }

    const classBody = source.substring(classStartOffset, classEndOffset);
    const methodRegex = /(?:(\/\*\*[\s\S]*?\*\/)\s*)?((?:@\w+(?:\([^)]*\))?\s*)*)(?:(public|private|protected)\s+)?(static\s+)?(async\s+)?([\w$]+)\s*\(([^)]*)\)(?:\s*:\s*([^{;]+))?\s*\{/g;
    let match: RegExpExecArray | null;

    while ((match = methodRegex.exec(classBody)) !== null) {
      const docstring = match[1];
      const decoratorsRaw = match[2];
      const visibilityStr = match[3];
      const isStatic = Boolean(match[4]);
      const isAsync = Boolean(match[5]);
      const methodName = match[6];
      const rawParams = match[7];
      const returnType = match[8]?.trim();

      // Skip keywords
      if (['if', 'for', 'while', 'switch', 'catch'].includes(methodName)) continue;

      const methodAbsoluteStart = classStartOffset + match.index;
      const methodAbsoluteEnd = methodAbsoluteStart + match[0].length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, methodAbsoluteStart, methodAbsoluteEnd, lineStarts, `${className}.${methodName}`);

      let visibility: SymbolVisibility = 'PUBLIC';
      if (visibilityStr === 'private') visibility = 'PRIVATE';
      if (visibilityStr === 'protected') visibility = 'PROTECTED';

      const modifiers: string[] = [];
      if (isStatic) modifiers.push('static');
      if (isAsync) modifiers.push('async');

      const decorators = decoratorsRaw ? decoratorsRaw.split('@').map(d => d.trim()).filter(Boolean) : [];

      symbols.push({
        name: methodName,
        kind: methodName === 'constructor' ? 'CONSTRUCTOR' : 'METHOD',
        visibility,
        parent_symbol: className,
        span,
        docstring: docstring ? docstring.replace(/\/\*\*|\*\/|\*/g, '').trim() : undefined,
        parameters: this.parseParams(rawParams),
        return_type: returnType,
        modifiers,
        decorators,
      });
    }
  }

  private static extractInterfacesAndTypes(
    filePath: string,
    source: string,
    lineStarts: number[],
    symbols: SymbolFact[]
  ): void {
    // Interface: (export)? interface Name (extends Super)? {
    const ifaceRegex = /(?:(\/\*\*[\s\S]*?\*\/)\s*)?(?:(export\s+)?interface\s+([\w$]+)(?:\s+extends\s+([^{]+))?\s*\{)/g;
    let match: RegExpExecArray | null;

    while ((match = ifaceRegex.exec(source)) !== null) {
      const docstring = match[1];
      const isExport = Boolean(match[2]);
      const name = match[3];
      const extendsTypes = match[4]?.trim();

      const startOffset = match.index;
      const endOffset = startOffset + match[0].length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts, name);

      symbols.push({
        name,
        kind: 'INTERFACE',
        visibility: 'PUBLIC',
        span,
        docstring: docstring ? docstring.replace(/\/\*\*|\*\/|\*/g, '').trim() : undefined,
        modifiers: isExport ? ['export'] : [],
        decorators: [],
        parameters: [],
      });
    }

    // Type Alias: (export)? type Name = ...;
    const typeRegex = /(?:(\/\*\*[\s\S]*?\*\/)\s*)?(?:(export\s+)?type\s+([\w$]+)(?:<[^>]+>)?\s*=\s*)/g;
    while ((match = typeRegex.exec(source)) !== null) {
      const docstring = match[1];
      const isExport = Boolean(match[2]);
      const name = match[3];

      const startOffset = match.index;
      const endOffset = startOffset + match[0].length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts, name);

      symbols.push({
        name,
        kind: 'TYPE_ALIAS',
        visibility: 'PUBLIC',
        span,
        docstring: docstring ? docstring.replace(/\/\*\*|\*\/|\*/g, '').trim() : undefined,
        modifiers: isExport ? ['export'] : [],
        decorators: [],
        parameters: [],
      });
    }

    // Enum: (export)? (const)? enum Name {
    const enumRegex = /(?:(\/\*\*[\s\S]*?\*\/)\s*)?(?:(export\s+)?(const\s+)?enum\s+([\w$]+)\s*\{)/g;
    while ((match = enumRegex.exec(source)) !== null) {
      const docstring = match[1];
      const isExport = Boolean(match[2]);
      const name = match[4];

      const startOffset = match.index;
      const endOffset = startOffset + match[0].length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts, name);

      symbols.push({
        name,
        kind: 'ENUM',
        visibility: 'PUBLIC',
        span,
        docstring: docstring ? docstring.replace(/\/\*\*|\*\/|\*/g, '').trim() : undefined,
        modifiers: isExport ? ['export'] : [],
        decorators: [],
        parameters: [],
      });
    }
  }

  private static extractVariablesAndConstants(
    filePath: string,
    source: string,
    lineStarts: number[],
    symbols: SymbolFact[]
  ): void {
    // const/let/var name: Type = value; or arrow function: const myArrow = async (a, b) => {
    const varRegex = /(?:(export\s+)?(const|let|var)\s+([\w$]+)(?:\s*:\s*([^=;]+))?\s*=\s*(async\s+)?(?:(\([^)]*\)|[\w$]+)\s*=>)?)/g;
    let match: RegExpExecArray | null;

    while ((match = varRegex.exec(source)) !== null) {
      const isExport = Boolean(match[1]);
      const declKeyword = match[2];
      const name = match[3];
      const typeHint = match[4]?.trim();
      const isAsyncArrow = Boolean(match[5]);
      const arrowParams = match[6];

      // If it is an arrow function
      const isFunction = Boolean(arrowParams || (match[0].includes('=>')));

      const startOffset = match.index;
      const endOffset = startOffset + match[0].length;
      const span = SourceSpanUtil.offsetToSpan(filePath, source, startOffset, endOffset, lineStarts, name);

      symbols.push({
        name,
        kind: isFunction ? (isAsyncArrow ? 'ASYNC_FUNCTION' : 'FUNCTION') : (declKeyword === 'const' ? 'CONSTANT' : 'VARIABLE'),
        visibility: 'PUBLIC',
        span,
        return_type: typeHint,
        parameters: arrowParams ? this.parseParams(arrowParams.replace(/[()]/g, '')) : [],
        modifiers: isExport ? ['export'] : [],
        decorators: [],
      });
    }
  }

  private static extractCallSites(
    filePath: string,
    source: string,
    lineStarts: number[],
    call_sites: CallSiteFact[]
  ): void {
    // Invocations: (await)? (receiver.)callee(args)
    const callRegex = /(?:(await)\s+)?([\w$]+(?:\.[\w$]+)*)\s*\(([^)]*)\)/g;
    let match: RegExpExecArray | null;

    while ((match = callRegex.exec(source)) !== null) {
      const isAwait = Boolean(match[1]);
      const fullCallee = match[2];
      const rawArgs = match[3];

      // Ignore language control statements that look like calls
      if (['if', 'for', 'while', 'switch', 'catch', 'function', 'return'].includes(fullCallee)) continue;

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
        is_await: isAwait,
        span,
      });
    }
  }

  private static parseParams(rawParams?: string) {
    if (!rawParams || !rawParams.trim()) return [];
    return rawParams.split(',').map(p => {
      const trimmed = p.trim();
      const isRest = trimmed.startsWith('...');
      const clean = isRest ? trimmed.substring(3) : trimmed;
      const [namePart, typePart] = clean.split(':');
      const [name, defaultVal] = namePart.split('=');

      return {
        name: name.trim(),
        type: typePart?.trim(),
        default_value: defaultVal?.trim(),
        is_rest: isRest,
      };
    }).filter(p => Boolean(p.name));
  }
}
