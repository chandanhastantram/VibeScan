"use strict";
/**
 * VibeScan VS Code Extension — Diagnostics Provider
 * Runs `vibescan scan --format json` and maps findings to VS Code diagnostics.
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
exports.VibeScanDiagnosticProvider = void 0;
const vscode = __importStar(require("vscode"));
const child_process_1 = require("child_process");
const util_1 = require("util");
const path = __importStar(require("path"));
const execFileAsync = (0, util_1.promisify)(child_process_1.execFile);
const SEVERITY_MAP = {
    'CRITICAL': vscode.DiagnosticSeverity.Error,
    'HIGH': vscode.DiagnosticSeverity.Error,
    'MEDIUM': vscode.DiagnosticSeverity.Warning,
    'LOW': vscode.DiagnosticSeverity.Information,
    'INFO': vscode.DiagnosticSeverity.Hint,
};
class VibeScanDiagnosticProvider {
    constructor(diagnosticCollection) {
        this.diagnosticCollection = diagnosticCollection;
    }
    async scanDirectory(dirPath) {
        return this._runScan(dirPath);
    }
    async scanFile(filePath) {
        const dir = path.dirname(filePath);
        return this._runScan(dir, filePath);
    }
    async _runScan(targetPath, _singleFile) {
        const config = vscode.workspace.getConfiguration('vibescan');
        const pythonPath = config.get('pythonPath', 'python');
        const severity = config.get('severity', 'INFO');
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
            const result = JSON.parse(jsonStr);
            return this._applyDiagnostics(result);
        }
        catch (error) {
            // Try to parse partial output even on non-zero exit (findings cause exit code 1)
            if (error.stdout) {
                try {
                    let jsonStr = error.stdout.trim();
                    const jsonStart = jsonStr.indexOf('{');
                    if (jsonStart >= 0) {
                        jsonStr = jsonStr.substring(jsonStart);
                    }
                    const result = JSON.parse(jsonStr);
                    return this._applyDiagnostics(result);
                }
                catch {
                    // Fall through to error message
                }
            }
            const msg = error.message || String(error);
            if (msg.includes('ENOENT') || msg.includes('not found')) {
                vscode.window.showErrorMessage('VibeScan: Python/vibescan not found. Install with: pip install chandan-vibescan');
            }
            else {
                vscode.window.showErrorMessage(`VibeScan scan failed: ${msg.substring(0, 200)}`);
            }
            return 0;
        }
    }
    _applyDiagnostics(result) {
        // Group findings by file
        const fileMap = new Map();
        for (const finding of result.findings) {
            const filePath = finding.file;
            const line = Math.max(0, (finding.line || 1) - 1); // VS Code is 0-indexed
            const range = new vscode.Range(line, 0, line, 200);
            const severity = SEVERITY_MAP[finding.severity] ?? vscode.DiagnosticSeverity.Warning;
            const diagnostic = new vscode.Diagnostic(range, `${finding.title}\n${finding.description}`, severity);
            diagnostic.source = 'VibeScan';
            diagnostic.code = finding.cwe_id || finding.scanner;
            // Store fix info in the diagnostic for the quick-fix provider
            if (finding.fix) {
                diagnostic._vibescanFix = finding.fix;
                diagnostic._vibescanTitle = finding.title;
            }
            if (!fileMap.has(filePath)) {
                fileMap.set(filePath, []);
            }
            fileMap.get(filePath).push(diagnostic);
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
exports.VibeScanDiagnosticProvider = VibeScanDiagnosticProvider;
//# sourceMappingURL=diagnostics.js.map