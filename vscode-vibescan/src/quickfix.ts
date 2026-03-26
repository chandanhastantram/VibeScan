/**
 * VibeScan VS Code Extension — Quick Fix Provider
 * Offers "Apply VibeScan Fix" and "Suppress with # nosec" code actions.
 */

import * as vscode from 'vscode';

export class VibeScanQuickFixProvider implements vscode.CodeActionProvider {
    private diagnosticCollection: vscode.DiagnosticCollection;

    constructor(diagnosticCollection: vscode.DiagnosticCollection) {
        this.diagnosticCollection = diagnosticCollection;
    }

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        _token: vscode.CancellationToken
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source !== 'VibeScan') {
                continue;
            }

            // Action 1: Apply VibeScan Fix (if fix info available)
            const fix = (diagnostic as any)._vibescanFix;
            if (fix) {
                const fixAction = new vscode.CodeAction(
                    `VibeScan: Apply Fix — ${(diagnostic as any)._vibescanTitle || 'Fix'}`,
                    vscode.CodeActionKind.QuickFix
                );
                fixAction.diagnostics = [diagnostic];
                fixAction.isPreferred = true;

                // Add the fix as a comment above the problematic line
                const line = diagnostic.range.start.line;
                const insertPos = new vscode.Position(line, 0);
                const lineText = document.lineAt(line).text;
                const indent = lineText.match(/^(\s*)/)?.[1] || '';
                const fixComment = `${indent}# VibeScan Fix: ${fix.split('\n')[0]}\n`;

                fixAction.edit = new vscode.WorkspaceEdit();
                fixAction.edit.insert(document.uri, insertPos, fixComment);

                actions.push(fixAction);
            }

            // Action 2: Suppress with # nosec
            const suppressAction = new vscode.CodeAction(
                'VibeScan: Suppress with # nosec',
                vscode.CodeActionKind.QuickFix
            );
            suppressAction.diagnostics = [diagnostic];

            const line = diagnostic.range.start.line;
            const lineText = document.lineAt(line).text;
            const lineEnd = new vscode.Position(line, lineText.length);

            const cweOrScanner = diagnostic.code ? ` [${diagnostic.code}]` : '';
            const suppressComment = `  # nosec${cweOrScanner}`;

            suppressAction.edit = new vscode.WorkspaceEdit();

            // Only add if not already suppressed
            if (!lineText.includes('# nosec')) {
                suppressAction.edit.insert(document.uri, lineEnd, suppressComment);
            }

            actions.push(suppressAction);

            // Action 3: Suppress entire file
            const suppressFileAction = new vscode.CodeAction(
                'VibeScan: Suppress all findings in this file',
                vscode.CodeActionKind.QuickFix
            );
            suppressFileAction.diagnostics = [diagnostic];
            suppressFileAction.edit = new vscode.WorkspaceEdit();
            
            // Add # vibescan:disable at the top of the file
            const fileStart = new vscode.Position(0, 0);
            const firstLine = document.lineAt(0).text;
            if (!firstLine.includes('vibescan:disable')) {
                suppressFileAction.edit.insert(
                    document.uri,
                    fileStart,
                    '# vibescan:disable — Suppress all VibeScan findings in this file\n'
                );
            }

            actions.push(suppressFileAction);
        }

        return actions;
    }
}
