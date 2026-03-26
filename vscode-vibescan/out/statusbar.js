"use strict";
/**
 * VibeScan VS Code Extension — Status Bar
 * Shows scan status and finding count in the VS Code status bar.
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
exports.VibeScanStatusBar = void 0;
const vscode = __importStar(require("vscode"));
class VibeScanStatusBar {
    constructor() {
        this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
        this.statusBarItem.command = 'vibescan.scanWorkspace';
        this.statusBarItem.tooltip = 'Click to scan workspace with VibeScan';
        this.setIdle();
        this.statusBarItem.show();
    }
    setIdle() {
        this.statusBarItem.text = '$(shield) VibeScan';
        this.statusBarItem.backgroundColor = undefined;
    }
    setScanning() {
        this.statusBarItem.text = '$(loading~spin) VibeScan: Scanning...';
        this.statusBarItem.backgroundColor = undefined;
    }
    setCount(count) {
        if (count === 0) {
            this.statusBarItem.text = '$(shield) VibeScan: ✓ Clean';
            this.statusBarItem.backgroundColor = undefined;
        }
        else {
            this.statusBarItem.text = `$(warning) VibeScan: ${count} issue${count === 1 ? '' : 's'}`;
            this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        }
    }
    dispose() {
        this.statusBarItem.dispose();
    }
}
exports.VibeScanStatusBar = VibeScanStatusBar;
//# sourceMappingURL=statusbar.js.map