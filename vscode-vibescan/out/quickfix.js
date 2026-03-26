"use strict";
/**
 * VibeScan VS Code Extension — Quick Fix Provider
 * Offers "Apply VibeScan Fix" and "Suppress with # nosec" code actions.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.VibeScanQuickFixProvider = void 0;
const vscode = __importStar(require("vscode"));
class VibeScanQuickFixProvider {
    constructor(diagnosticCollection) {
        this.diagnosticCollection = diagnosticCollection;
    }
    provideCodeActions(document, range, context, _token) {
        const actions = [];
        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source !== 'VibeScan') {
                continue;
            }
            // Action 1: Apply VibeScan Fix (if fix info available)
            const fix = diagnostic._vibescanFix;
            if (fix) {
                const fixAction = new vscode.CodeAction(`VibeScan: Apply Fix — ${diagnostic._vibescanTitle || 'Fix'}`, vscode.CodeActionKind.QuickFix);
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
            const suppressAction = new vscode.CodeAction('VibeScan: Suppress with # nosec', vscode.CodeActionKind.QuickFix);
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
            const suppressFileAction = new vscode.CodeAction('VibeScan: Suppress all findings in this file', vscode.CodeActionKind.QuickFix);
            suppressFileAction.diagnostics = [diagnostic];
            suppressFileAction.edit = new vscode.WorkspaceEdit();
            // Add # vibescan:disable at the top of the file
            const fileStart = new vscode.Position(0, 0);
            const firstLine = document.lineAt(0).text;
            if (!firstLine.includes('vibescan:disable')) {
                suppressFileAction.edit.insert(document.uri, fileStart, '# vibescan:disable — Suppress all VibeScan findings in this file\n');
            }
            actions.push(suppressFileAction);
        }
        return actions;
    }
}
exports.VibeScanQuickFixProvider = VibeScanQuickFixProvider;
//# sourceMappingURL=quickfix.js.map