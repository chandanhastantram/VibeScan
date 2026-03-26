/**
 * VibeScan VS Code Extension — Entry Point
 * Registers commands, activates diagnostics, status bar, and code actions.
 */

import * as vscode from 'vscode';
import { VibeScanDiagnosticProvider } from './diagnostics';
import { VibeScanQuickFixProvider } from './quickfix';
import { VibeScanStatusBar } from './statusbar';

let diagnosticProvider: VibeScanDiagnosticProvider;
let statusBar: VibeScanStatusBar;

export function activate(context: vscode.ExtensionContext) {
    console.log('VibeScan extension activated');

    // Initialize providers
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('vibescan');
    diagnosticProvider = new VibeScanDiagnosticProvider(diagnosticCollection);
    statusBar = new VibeScanStatusBar();

    // Register code action provider (quick fixes)
    const quickFixProvider = new VibeScanQuickFixProvider(diagnosticCollection);
    const codeActionDisposable = vscode.languages.registerCodeActionsProvider(
        { scheme: 'file' },
        quickFixProvider,
        { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    );

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
        if (config.get<boolean>('scanOnSave', true)) {
            statusBar.setScanning();
            const findings = await diagnosticProvider.scanFile(doc.uri.fsPath);
            statusBar.setCount(findings);
        }
    });

    context.subscriptions.push(
        diagnosticCollection,
        codeActionDisposable,
        scanWorkspaceCmd,
        scanFileCmd,
        clearCmd,
        onSaveDisposable,
        statusBar
    );
}

export function deactivate() {
    console.log('VibeScan extension deactivated');
}
