"use strict";
/**
 * VibeScan VS Code Extension — Entry Point
 * Registers commands, activates diagnostics, status bar, and code actions.
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
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const diagnostics_1 = require("./diagnostics");
const quickfix_1 = require("./quickfix");
const statusbar_1 = require("./statusbar");
let diagnosticProvider;
let statusBar;
function activate(context) {
    console.log('VibeScan extension activated');
    // Initialize providers
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('vibescan');
    diagnosticProvider = new diagnostics_1.VibeScanDiagnosticProvider(diagnosticCollection);
    statusBar = new statusbar_1.VibeScanStatusBar();
    // Register code action provider (quick fixes)
    const quickFixProvider = new quickfix_1.VibeScanQuickFixProvider(diagnosticCollection);
    const codeActionDisposable = vscode.languages.registerCodeActionsProvider({ scheme: 'file' }, quickFixProvider, { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] });
    // Register commands
    const scanWorkspaceCmd = vscode.commands.registerCommand('vibescan.scanWorkspace', async () => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            vscode.window.showWarningMessage('VibeScan: No workspace folder open.');
            return;
        }
        statusBar.setScanning();
        const findings = await diagnosticProvider.scanDirectory(workspaceFolders[0].uri.fsPath);
        statusBar.setCount(findings);
        vscode.window.showInformationMessage(`VibeScan: Found ${findings} issue(s).`);
    });
    const scanFileCmd = vscode.commands.registerCommand('vibescan.scanFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('VibeScan: No active file.');
            return;
        }
        statusBar.setScanning();
        const findings = await diagnosticProvider.scanFile(editor.document.uri.fsPath);
        statusBar.setCount(findings);
    });
    const clearCmd = vscode.commands.registerCommand('vibescan.clearDiagnostics', () => {
        diagnosticCollection.clear();
        statusBar.setCount(0);
    });
    // Auto-scan on save
    const onSaveDisposable = vscode.workspace.onDidSaveTextDocument(async (doc) => {
        const config = vscode.workspace.getConfiguration('vibescan');
        if (config.get('scanOnSave', true)) {
            statusBar.setScanning();
            const findings = await diagnosticProvider.scanFile(doc.uri.fsPath);
            statusBar.setCount(findings);
        }
    });
    context.subscriptions.push(diagnosticCollection, codeActionDisposable, scanWorkspaceCmd, scanFileCmd, clearCmd, onSaveDisposable, statusBar);
}
function deactivate() {
    console.log('VibeScan extension deactivated');
}
//# sourceMappingURL=extension.js.map