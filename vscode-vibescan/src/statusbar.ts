/**
 * VibeScan VS Code Extension — Status Bar
 * Shows scan status and finding count in the VS Code status bar.
 */

import * as vscode from 'vscode';

export class VibeScanStatusBar implements vscode.Disposable {
    private statusBarItem: vscode.StatusBarItem;

    constructor() {
        this.statusBarItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Left,
            100
        );
        this.statusBarItem.command = 'vibescan.scanWorkspace';
        this.statusBarItem.tooltip = 'Click to scan workspace with VibeScan';
        this.setIdle();
        this.statusBarItem.show();
    }

    setIdle(): void {
        this.statusBarItem.text = '$(shield) VibeScan';
        this.statusBarItem.backgroundColor = undefined;
    }

    setScanning(): void {
        this.statusBarItem.text = '$(loading~spin) VibeScan: Scanning...';
        this.statusBarItem.backgroundColor = undefined;
    }

    setCount(count: number): void {
        if (count === 0) {
            this.statusBarItem.text = '$(shield) VibeScan: ✓ Clean';
            this.statusBarItem.backgroundColor = undefined;
        } else {
            this.statusBarItem.text = `$(warning) VibeScan: ${count} issue${count === 1 ? '' : 's'}`;
            this.statusBarItem.backgroundColor = new vscode.ThemeColor(
                'statusBarItem.warningBackground'
            );
        }
    }

    dispose(): void {
        this.statusBarItem.dispose();
    }
}
