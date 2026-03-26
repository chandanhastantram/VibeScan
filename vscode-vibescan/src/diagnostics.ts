/**
 * VibeScan VS Code Extension — Diagnostics Provider
 * Runs `vibescan scan --format json` and maps findings to VS Code diagnostics.
 */

import * as vscode from 'vscode';
import { execFile } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';

const execFileAsync = promisify(execFile);

interface VibeScanFinding {
    file: string;
    line: number;
    severity: string;
    title: string;
    description: string;
    code_snippet: string;
    cwe_id: string | null;
    fix: string;
    scanner: string;
}

interface VibeScanResult {
    findings: VibeScanFinding[];
    summary: {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
}

const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
    'CRITICAL': vscode.DiagnosticSeverity.Error,
    'HIGH': vscode.DiagnosticSeverity.Error,
    'MEDIUM': vscode.DiagnosticSeverity.Warning,
    'LOW': vscode.DiagnosticSeverity.Information,
    'INFO': vscode.DiagnosticSeverity.Hint,
};

export class VibeScanDiagnosticProvider {
    private diagnosticCollection: vscode.DiagnosticCollection;

    constructor(diagnosticCollection: vscode.DiagnosticCollection) {
        this.diagnosticCollection = diagnosticCollection;
    }

    async scanDirectory(dirPath: string): Promise<number> {
        return this._runScan(dirPath);
    }

    async scanFile(filePath: string): Promise<number> {
        const dir = path.dirname(filePath);
        return this._runScan(dir, filePath);
    }

    private async _runScan(targetPath: string, _singleFile?: string): Promise<number> {
        const config = vscode.workspace.getConfiguration('vibescan');
        const pythonPath = config.get<string>('pythonPath', 'python');
        const severity = config.get<string>('severity', 'INFO');

        try {
            const args = [
                '-m', 'vibescan', 'scan', targetPath,
                '--format', 'json',
                '--severity', severity,
                '--no-save',
            ];

            const { stdout } = await execFileAsync(pythonPath, args, {
                cwd: targetPath,
                maxBuffer: 10 * 1024 * 1024,
                timeout: 120000,
            });

            // Parse JSON output (skip any non-JSON preamble lines)
            let jsonStr = stdout.trim();
            const jsonStart = jsonStr.indexOf('{');
            if (jsonStart > 0) {
                jsonStr = jsonStr.substring(jsonStart);
            }

            const result: VibeScanResult = JSON.parse(jsonStr);
            return this._applyDiagnostics(result);

        } catch (error: any) {
            // Try to parse partial output even on non-zero exit (findings cause exit code 1)
            if (error.stdout) {
                try {
                    let jsonStr = error.stdout.trim();
                    const jsonStart = jsonStr.indexOf('{');
                    if (jsonStart >= 0) {
                        jsonStr = jsonStr.substring(jsonStart);
                    }
                    const result: VibeScanResult = JSON.parse(jsonStr);
                    return this._applyDiagnostics(result);
                } catch {
                    // Fall through to error message
                }
            }

            const msg = error.message || String(error);
            if (msg.includes('ENOENT') || msg.includes('not found')) {
                vscode.window.showErrorMessage(
                    'VibeScan: Python/vibescan not found. Install with: pip install chandan-vibescan'
                );
            } else {
                vscode.window.showErrorMessage(`VibeScan scan failed: ${msg.substring(0, 200)}`);
            }
            return 0;
        }
    }

    private _applyDiagnostics(result: VibeScanResult): number {
        // Group findings by file
        const fileMap = new Map<string, vscode.Diagnostic[]>();

        for (const finding of result.findings) {
            const filePath = finding.file;
            const line = Math.max(0, (finding.line || 1) - 1);  // VS Code is 0-indexed

            const range = new vscode.Range(line, 0, line, 200);
            const severity = SEVERITY_MAP[finding.severity] ?? vscode.DiagnosticSeverity.Warning;

            const diagnostic = new vscode.Diagnostic(
                range,
                `${finding.title}\n${finding.description}`,
                severity
            );
            diagnostic.source = 'VibeScan';
            diagnostic.code = finding.cwe_id || finding.scanner;

            // Store fix info in the diagnostic for the quick-fix provider
            if (finding.fix) {
                (diagnostic as any)._vibescanFix = finding.fix;
                (diagnostic as any)._vibescanTitle = finding.title;
            }

            if (!fileMap.has(filePath)) {
                fileMap.set(filePath, []);
            }
            fileMap.get(filePath)!.push(diagnostic);
        }

        // Clear old diagnostics and apply new ones
        this.diagnosticCollection.clear();
        for (const [filePath, diagnostics] of fileMap) {
            const uri = vscode.Uri.file(filePath);
            this.diagnosticCollection.set(uri, diagnostics);
        }

        return result.findings.length;
    }
}
