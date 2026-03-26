"""
VibeScan — Infrastructure as Code (IaC) Scanner
Detects misconfigurations in Dockerfiles, docker-compose, Terraform, and Kubernetes manifests.
"""

import re
import os
from .base import BaseScanner
from ..models import Finding, Severity


class IaCScanner(BaseScanner):
    name = "IaCScanner"
    SUPPORTED_EXTENSIONS = (
        ".yml", ".yaml", ".tf", ".hcl", ".json",
    )

    def supports_file(self, filepath: str) -> bool:
        basename = os.path.basename(filepath).lower()
        if basename == "dockerfile" or basename.startswith("dockerfile."):
            return True
        return super().supports_file(filepath)

    # ── Dockerfile rules ──────────────────────────────────────────────────────

    _DOCKER_RULES = [
        {
            "pattern": re.compile(r"^\s*USER\s+root\s*$", re.IGNORECASE),
            "severity": Severity.HIGH,
            "title": "Container running as root",
            "desc": "Running containers as root increases the attack surface. Use a non-root user.",
            "cwe": "CWE-250",
            "fix": "Add a non-root user: RUN adduser --disabled-password appuser && USER appuser",
        },
        {
            "pattern": re.compile(r"^\s*FROM\s+\S+:latest\b", re.IGNORECASE),
            "severity": Severity.MEDIUM,
            "title": "Using 'latest' tag in base image",
            "desc": "The :latest tag is mutable and can introduce unexpected changes. Pin a specific version.",
            "cwe": "CWE-829",
            "fix": "Pin image version, e.g. FROM python:3.11-slim instead of FROM python:latest",
        },
        {
            "pattern": re.compile(r"^\s*ADD\s+https?://", re.IGNORECASE),
            "severity": Severity.MEDIUM,
            "title": "Using ADD with remote URL",
            "desc": "ADD with URLs can introduce unverified content. Use COPY + curl/wget for better control.",
            "cwe": "CWE-829",
            "fix": "Replace ADD with RUN curl -o /path <URL> && verify checksum",
        },
        {
            "pattern": re.compile(
                r"^\s*ENV\s+\S*(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*=",
                re.IGNORECASE,
            ),
            "severity": Severity.HIGH,
            "title": "Secret exposed in Dockerfile ENV",
            "desc": "Secrets in ENV instructions are baked into image layers and visible in docker history.",
            "cwe": "CWE-798",
            "fix": "Use Docker secrets, build args with --secret, or runtime environment variables instead.",
        },
        {
            "pattern": re.compile(r"^\s*EXPOSE\s+(22|23|3389|5900)\b"),
            "severity": Severity.MEDIUM,
            "title": "Sensitive port exposed in Dockerfile",
            "desc": "Exposing SSH (22), Telnet (23), RDP (3389), or VNC (5900) ports may indicate insecure access.",
            "cwe": "CWE-200",
            "fix": "Remove EXPOSE for management ports; use overlay networks instead.",
        },
        {
            "pattern": re.compile(r"^\s*RUN\s+.*curl\s+.*\|\s*sh", re.IGNORECASE),
            "severity": Severity.HIGH,
            "title": "Piping curl to shell in Dockerfile",
            "desc": "Downloading and executing scripts without verification is a supply chain risk.",
            "cwe": "CWE-829",
            "fix": "Download the script, verify its checksum, then execute it.",
        },
    ]

    # ── docker-compose rules ──────────────────────────────────────────────────

    _COMPOSE_RULES = [
        {
            "pattern": re.compile(r"privileged\s*:\s*true", re.IGNORECASE),
            "severity": Severity.CRITICAL,
            "title": "Privileged container in docker-compose",
            "desc": "privileged: true gives the container full host access, equivalent to running as root on the host.",
            "cwe": "CWE-250",
            "fix": "Remove privileged: true. Use specific capabilities with cap_add if needed.",
        },
        {
            "pattern": re.compile(r"network_mode\s*:\s*['\"]?host['\"]?", re.IGNORECASE),
            "severity": Severity.HIGH,
            "title": "Host network mode in docker-compose",
            "desc": "Host network mode bypasses Docker's network isolation.",
            "cwe": "CWE-668",
            "fix": "Use bridge or overlay networks instead of host network mode.",
        },
        {
            "pattern": re.compile(r"pid\s*:\s*['\"]?host['\"]?", re.IGNORECASE),
            "severity": Severity.HIGH,
            "title": "Host PID namespace in docker-compose",
            "desc": "Sharing the host PID namespace allows container processes to see and interact with host processes.",
            "cwe": "CWE-668",
            "fix": "Remove pid: host unless absolutely required for debugging.",
        },
    ]

    # ── Terraform rules ───────────────────────────────────────────────────────

    _TERRAFORM_RULES = [
        {
            "pattern": re.compile(r"cidr_blocks\s*=\s*\[?\s*\"0\.0\.0\.0/0\"\s*\]?"),
            "severity": Severity.HIGH,
            "title": "Security group open to 0.0.0.0/0",
            "desc": "Ingress rule allows traffic from any IP address, exposing the resource publicly.",
            "cwe": "CWE-284",
            "fix": "Restrict cidr_blocks to specific IP ranges needed for access.",
        },
        {
            "pattern": re.compile(r"acl\s*=\s*\"public-read\"", re.IGNORECASE),
            "severity": Severity.CRITICAL,
            "title": "Public S3 bucket ACL",
            "desc": "S3 bucket with public-read ACL exposes data to the internet.",
            "cwe": "CWE-284",
            "fix": "Use acl = \"private\" and manage access via IAM policies.",
        },
        {
            "pattern": re.compile(r"encrypted\s*=\s*false", re.IGNORECASE),
            "severity": Severity.HIGH,
            "title": "Encryption disabled in Terraform resource",
            "desc": "Resource configured without encryption at rest, violating data protection best practices.",
            "cwe": "CWE-311",
            "fix": "Set encrypted = true and configure a KMS key.",
        },
        {
            "pattern": re.compile(r"publicly_accessible\s*=\s*true", re.IGNORECASE),
            "severity": Severity.HIGH,
            "title": "Database publicly accessible",
            "desc": "RDS/database instance is publicly accessible, allowing connections from the internet.",
            "cwe": "CWE-284",
            "fix": "Set publicly_accessible = false and use VPC + VPN for access.",
        },
    ]

    # ── Kubernetes rules ──────────────────────────────────────────────────────

    _K8S_RULES = [
        {
            "pattern": re.compile(r"privileged\s*:\s*true", re.IGNORECASE),
            "severity": Severity.CRITICAL,
            "title": "Privileged container in Kubernetes",
            "desc": "Privileged pods have unrestricted host access. This is a major security risk.",
            "cwe": "CWE-250",
            "fix": "Set securityContext.privileged: false and use specific capabilities.",
        },
        {
            "pattern": re.compile(r"runAsUser\s*:\s*0\b"),
            "severity": Severity.HIGH,
            "title": "Container running as root (UID 0) in Kubernetes",
            "desc": "Running as root inside a container increases the attack surface.",
            "cwe": "CWE-250",
            "fix": "Set runAsUser to a non-root UID (e.g., 1000) and runAsNonRoot: true.",
        },
        {
            "pattern": re.compile(r"hostNetwork\s*:\s*true", re.IGNORECASE),
            "severity": Severity.HIGH,
            "title": "Host network enabled in Kubernetes pod",
            "desc": "hostNetwork: true exposes the pod to the host's network stack.",
            "cwe": "CWE-668",
            "fix": "Remove hostNetwork: true unless strictly required.",
        },
        {
            "pattern": re.compile(r"hostPID\s*:\s*true", re.IGNORECASE),
            "severity": Severity.HIGH,
            "title": "Host PID namespace in Kubernetes pod",
            "desc": "hostPID: true allows processes inside the container to see host processes.",
            "cwe": "CWE-668",
            "fix": "Remove hostPID: true.",
        },
        {
            "pattern": re.compile(r"allowPrivilegeEscalation\s*:\s*true", re.IGNORECASE),
            "severity": Severity.HIGH,
            "title": "Privilege escalation allowed in Kubernetes",
            "desc": "allowPrivilegeEscalation: true permits the process to gain more privileges than its parent.",
            "cwe": "CWE-250",
            "fix": "Set allowPrivilegeEscalation: false in securityContext.",
        },
        {
            "pattern": re.compile(
                r"readOnlyRootFilesystem\s*:\s*false", re.IGNORECASE
            ),
            "severity": Severity.MEDIUM,
            "title": "Writable root filesystem in Kubernetes container",
            "desc": "A writable root filesystem allows attackers to modify binaries inside the container.",
            "cwe": "CWE-732",
            "fix": "Set readOnlyRootFilesystem: true and use emptyDir volumes for writable paths.",
        },
    ]

    # ── Scan dispatcher ───────────────────────────────────────────────────────

    def scan_file(self, filepath: str, content: str, lines: list[str]) -> list[Finding]:
        basename = os.path.basename(filepath).lower()

        if basename == "dockerfile" or basename.startswith("dockerfile."):
            return self._run_rules(filepath, lines, self._DOCKER_RULES)

        if basename in ("docker-compose.yml", "docker-compose.yaml"):
            return self._run_rules(filepath, lines, self._COMPOSE_RULES)

        ext = os.path.splitext(filepath)[1].lower()
        if ext in (".tf", ".hcl"):
            return self._run_rules(filepath, lines, self._TERRAFORM_RULES)

        # Kubernetes YAML heuristic: contains "kind:" and "apiVersion:"
        if ext in (".yml", ".yaml"):
            if "apiVersion:" in content and "kind:" in content:
                return self._run_rules(filepath, lines, self._K8S_RULES)
            # Also check compose-like files by presence of 'services:'
            if "services:" in content:
                return self._run_rules(filepath, lines, self._COMPOSE_RULES)

        return []

    def _run_rules(self, filepath: str, lines: list[str], rules: list[dict]) -> list[Finding]:
        findings = []
        for rule in rules:
            for lineno, line in enumerate(lines, start=1):
                if rule["pattern"].search(line):
                    findings.append(Finding(
                        file=filepath,
                        line=lineno,
                        severity=rule["severity"],
                        title=rule["title"],
                        description=rule["desc"],
                        code_snippet=line.rstrip(),
                        cwe_id=rule.get("cwe"),
                        fix=rule.get("fix", ""),
                        scanner=self.name,
                    ))
        return findings
