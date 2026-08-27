/**
 * Control Flow Graph (CFG) Generator
 * P15 — Static Analysis & Control Flow
 */

import { ControlFlowGraph, CfgBasicBlock, CfgBlockTerminatorKind } from './types.ts';
import { SourceSpan } from '../../packages/syntax/src/types.ts';

export class StaticCfgBuilder {
  /**
   * Generates a Control Flow Graph for a function or top-level code block
   */
  public static buildCfg(
    filePath: string,
    functionName: string,
    sourceContent: string,
    functionSpan?: SourceSpan
  ): ControlFlowGraph {
    const cfgId = `cfg_${crypto.randomUUID().slice(0, 8)}`;
    
    // Extract function body text slice
    const rawCode = functionSpan?.text_slice || sourceContent;
    const lines = rawCode.split('\n');
    const startLine = functionSpan?.start_line || 1;

    const blocks: CfgBasicBlock[] = [];
    let cyclomaticComplexity = 1;
    let loopCount = 0;
    let exceptionHandlersCount = 0;
    let hasUnreachableBlocks = false;

    // Entry block
    const entryBlockId = 'block_0_entry';
    const entryBlock: CfgBasicBlock = {
      block_id: entryBlockId,
      label: `ENTRY: ${functionName}`,
      statements: [],
      start_line: startLine,
      end_line: startLine,
      predecessor_ids: [],
      successor_ids: [],
      terminator_kind: 'NORMAL',
      is_entry: true,
      is_exit: false,
      is_dead_code: false,
    };
    blocks.push(entryBlock);

    let currentBlockId = entryBlockId;
    let blockCounter = 1;
    let isCurrentlyReachable = true;

    // Scan lines for control flow constructs
    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i].trim();
      const currentLineNum = startLine + i;

      if (!lineText || lineText.startsWith('//') || lineText.startsWith('#') || lineText.startsWith('/*')) {
        continue;
      }

      // 1. Branch: IF statements
      if (lineText.startsWith('if ') || lineText.startsWith('if(') || lineText.includes(' if ')) {
        cyclomaticComplexity++;
        const branchBlockId = `block_${blockCounter++}_if_branch`;
        const mergeBlockId = `block_${blockCounter++}_if_merge`;

        const currBlock = blocks.find(b => b.block_id === currentBlockId);
        if (currBlock) {
          currBlock.statements.push(lineText);
          currBlock.end_line = currentLineNum;
          currBlock.terminator_kind = 'BRANCH';
          currBlock.successor_ids.push(branchBlockId, mergeBlockId);
        }

        // Branch body block
        blocks.push({
          block_id: branchBlockId,
          label: `THEN_BRANCH (L${currentLineNum})`,
          statements: [`// then block`],
          start_line: currentLineNum,
          end_line: currentLineNum,
          predecessor_ids: [currentBlockId],
          successor_ids: [mergeBlockId],
          terminator_kind: 'NORMAL',
          is_entry: false,
          is_exit: false,
          is_dead_code: !isCurrentlyReachable,
        });

        // Merge block
        blocks.push({
          block_id: mergeBlockId,
          label: `MERGE (L${currentLineNum})`,
          statements: [],
          start_line: currentLineNum,
          end_line: currentLineNum,
          predecessor_ids: [currentBlockId, branchBlockId],
          successor_ids: [],
          terminator_kind: 'NORMAL',
          is_entry: false,
          is_exit: false,
          is_dead_code: !isCurrentlyReachable,
        });

        currentBlockId = mergeBlockId;
        continue;
      }

      // 2. Loops: FOR / WHILE / DO-WHILE
      if (
        lineText.startsWith('for ') || lineText.startsWith('for(') || 
        lineText.startsWith('while ') || lineText.startsWith('while(') ||
        lineText.startsWith('for {')
      ) {
        cyclomaticComplexity++;
        loopCount++;

        const headerBlockId = `block_${blockCounter++}_loop_header`;
        const bodyBlockId = `block_${blockCounter++}_loop_body`;
        const exitBlockId = `block_${blockCounter++}_loop_exit`;

        const currBlock = blocks.find(b => b.block_id === currentBlockId);
        if (currBlock) {
          currBlock.successor_ids.push(headerBlockId);
        }

        // Loop header
        blocks.push({
          block_id: headerBlockId,
          label: `LOOP_HEADER (L${currentLineNum})`,
          statements: [lineText],
          start_line: currentLineNum,
          end_line: currentLineNum,
          predecessor_ids: [currentBlockId, bodyBlockId],
          successor_ids: [bodyBlockId, exitBlockId],
          terminator_kind: 'LOOP_HEADER',
          is_entry: false,
          is_exit: false,
          is_dead_code: !isCurrentlyReachable,
        });

        // Loop body
        blocks.push({
          block_id: bodyBlockId,
          label: `LOOP_BODY (L${currentLineNum})`,
          statements: [`// loop body`],
          start_line: currentLineNum,
          end_line: currentLineNum,
          predecessor_ids: [headerBlockId],
          successor_ids: [headerBlockId],
          terminator_kind: 'LOOP_BACK',
          is_entry: false,
          is_exit: false,
          is_dead_code: !isCurrentlyReachable,
        });

        // Exit block
        blocks.push({
          block_id: exitBlockId,
          label: `LOOP_EXIT (L${currentLineNum})`,
          statements: [],
          start_line: currentLineNum,
          end_line: currentLineNum,
          predecessor_ids: [headerBlockId],
          successor_ids: [],
          terminator_kind: 'NORMAL',
          is_entry: false,
          is_exit: false,
          is_dead_code: !isCurrentlyReachable,
        });

        currentBlockId = exitBlockId;
        continue;
      }

      // 3. Exception Handlers: TRY / CATCH / EXCEPT / FINALLY
      if (lineText.startsWith('try ') || lineText.startsWith('try{') || lineText.startsWith('catch') || lineText.startsWith('except')) {
        exceptionHandlersCount++;
        cyclomaticComplexity++;

        const handlerBlockId = `block_${blockCounter++}_exc_handler`;
        const currBlock = blocks.find(b => b.block_id === currentBlockId);
        if (currBlock) {
          currBlock.successor_ids.push(handlerBlockId);
        }

        blocks.push({
          block_id: handlerBlockId,
          label: `EXC_HANDLER (L${currentLineNum})`,
          statements: [lineText],
          start_line: currentLineNum,
          end_line: currentLineNum,
          predecessor_ids: [currentBlockId],
          successor_ids: [],
          terminator_kind: 'NORMAL',
          is_entry: false,
          is_exit: false,
          is_dead_code: false,
        });

        continue;
      }

      // 4. Return Statements
      if (lineText.startsWith('return ') || lineText === 'return;' || lineText === 'return') {
        const currBlock = blocks.find(b => b.block_id === currentBlockId);
        if (currBlock) {
          currBlock.statements.push(lineText);
          currBlock.end_line = currentLineNum;
          currBlock.terminator_kind = 'RETURN';
          currBlock.is_exit = true;
        }

        // If further code appears after return in the same function scope, it's dead code
        if (i < lines.length - 1 && !lines[i + 1].trim().startsWith('}') && lines[i + 1].trim().length > 0) {
          hasUnreachableBlocks = true;
          isCurrentlyReachable = false;
          const deadBlockId = `block_${blockCounter++}_dead_code`;
          blocks.push({
            block_id: deadBlockId,
            label: `UNREACHABLE_DEAD_CODE (L${currentLineNum + 1})`,
            statements: [lines[i + 1].trim()],
            start_line: currentLineNum + 1,
            end_line: currentLineNum + 1,
            predecessor_ids: [],
            successor_ids: [],
            terminator_kind: 'UNREACHABLE',
            is_entry: false,
            is_exit: false,
            is_dead_code: true,
          });
        }
        continue;
      }

      // 5. Throw / Raise Statements
      if (lineText.startsWith('throw ') || lineText.startsWith('raise ')) {
        const currBlock = blocks.find(b => b.block_id === currentBlockId);
        if (currBlock) {
          currBlock.statements.push(lineText);
          currBlock.end_line = currentLineNum;
          currBlock.terminator_kind = 'THROW';
          currBlock.is_exit = true;
        }
        continue;
      }

      // 6. Normal sequential statements
      const currBlock = blocks.find(b => b.block_id === currentBlockId);
      if (currBlock) {
        currBlock.statements.push(lineText);
        currBlock.end_line = currentLineNum;
      }
    }

    // Identify exit blocks
    const exitBlocks = blocks.filter(b => b.is_exit || b.successor_ids.length === 0);
    const exitBlockIds = exitBlocks.map(b => b.block_id);

    // If no explicit exit block, mark the last block as exit
    if (exitBlockIds.length === 0 && blocks.length > 0) {
      blocks[blocks.length - 1].is_exit = true;
      exitBlockIds.push(blocks[blocks.length - 1].block_id);
    }

    return {
      cfg_id: cfgId,
      file_path: filePath,
      function_name: functionName,
      cyclomatic_complexity: cyclomaticComplexity,
      blocks,
      has_unreachable_blocks: hasUnreachableBlocks,
      loop_count: loopCount,
      exception_handlers_count: exceptionHandlersCount,
      entry_block_id: entryBlockId,
      exit_block_ids: exitBlockIds,
    };
  }
}
