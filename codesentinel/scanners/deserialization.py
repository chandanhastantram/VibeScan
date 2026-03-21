"""
CodeSentinel — Insecure Deserialization Scanner
Detects unsafe use of pickle, yaml.load, marshal, and shelve with untrusted data.
"""

import re
from .base import BaseScanner
from ..models import Finding, Severity


# pickle.loads / pickle.load
_PICKLE_LOADS_RE = re.compile(r"\bpickle\.(loads?|Unpickler)\s*\(")

# yaml.load without SafeLoader or Loader=yaml.SafeLoader
_YAML_LOAD_RE = re.compile(
    r"\byaml\.load\s*\([^)]*\)",
)
_YAML_SAFE_RE = re.compile(r"SafeLoader|Loader\s*=\s*yaml\.SafeLoader")

# marshal.loads
_MARSHAL_RE = re.compile(r"\bmarshal\.(loads?|load)\s*\(")

# shelve (uses pickle internally)
_SHELVE_RE = re.compile(r"\bshelve\.open\s*\(")

# jsonpickle
_JSONPICKLE_RE = re.compile(r"\bjsonpickle\.(decode|loads?)\s*\(")

# PHP unserialize
_PHP_UNSERIALIZE_RE = re.compile(r"\bunserialize\s*\(")

# Java ObjectInputStream
_JAVA_OIS_RE = re.compile(r"\bnew ObjectInputStream\s*\(")

# Node.js: node-serialize, serialize-to-js
_NODE_SERIALIZE_RE = re.compile(r"\brequire\s*\(\s*['\"]node-serialize['\"]")


class DeserializationScanner(BaseScanner):
    name = "DeserializationScanner"
    SUPPORTED_EXTENSIONS = (".py", ".php", ".java", ".js", ".ts")

    def scan_file(self, filepath: str, content: str, lines: list[str]) -> list[Finding]:
        findings = []

        if filepath.endswith(".py"):
            findings += self._regex_findings(
                filepath, lines, _PICKLE_LOADS_RE,
                Severity.CRITICAL,
                "Insecure Deserialization — pickle.load(s)",
                "pickle.load(s) executes arbitrary Python code embedded in the serialized data. "
                "Deserializing data from any untrusted source (network, user upload, database) "
                "leads to Remote Code Execution.",
                cwe_id="CWE-502",
                fix=(
                    "Replace pickle with a safe format like JSON or msgpack. "
                    "If pickle must be used, sign the data with HMAC and verify before deserializing:\n"
                    "  import hmac, hashlib\n"
                    "  # Reject data if HMAC verification fails"
                ),
            )

            findings += self._regex_findings(
                filepath, lines, _MARSHAL_RE,
                Severity.CRITICAL,
                "Insecure Deserialization — marshal.load(s)",
                "marshal.load() can execute arbitrary bytecode. "
                "Python docs explicitly state this module is not safe against untrusted data.",
                cwe_id="CWE-502",
                fix="Use JSON or another safe serialization format instead of marshal.",
            )

            findings += self._regex_findings(
                filepath, lines, _SHELVE_RE,
                Severity.HIGH,
                "Insecure Deserialization — shelve (uses pickle internally)",
                "shelve uses pickle under the hood. Opening a shelve file from an "
                "untrusted source is equivalent to running pickle.load() on it.",
                cwe_id="CWE-502",
                fix="Use a proper database or a safe serialization format for external data.",
            )

            # yaml.load is only dangerous without SafeLoader
            for lineno, line in enumerate(lines, start=1):
                if _YAML_LOAD_RE.search(line) and not _YAML_SAFE_RE.search(line):
                    findings.append(self._make_yaml_finding(filepath, lineno, line))

            findings += self._regex_findings(
                filepath, lines, _JSONPICKLE_RE,
                Severity.CRITICAL,
                "Insecure Deserialization — jsonpickle.decode",
                "jsonpickle can execute arbitrary Python code during deserialization. "
                "Do not use on untrusted input.",
                cwe_id="CWE-502",
                fix="Use plain json.load() instead. jsonpickle is not safe for untrusted data.",
            )

        if filepath.endswith(".php"):
            findings += self._regex_findings(
                filepath, lines, _PHP_UNSERIALIZE_RE,
                Severity.CRITICAL,
                "Insecure Deserialization — PHP unserialize()",
                "PHP unserialize() on user-controlled data allows attackers to trigger "
                "PHP Object Injection, often leading to RCE via magic methods (__destruct, __wakeup).",
                cwe_id="CWE-502",
                fix=(
                    "Use json_decode() instead of unserialize(). "
                    "If unserialize() is required, use allowed_classes parameter:\n"
                    "  unserialize($data, ['allowed_classes' => false])"
                ),
            )

        if filepath.endswith(".java"):
            findings += self._regex_findings(
                filepath, lines, _JAVA_OIS_RE,
                Severity.CRITICAL,
                "Insecure Deserialization — Java ObjectInputStream",
                "Java native deserialization is a well-known RCE vector (Apache Commons, Log4Shell ancestry). "
                "Deserializing untrusted byte streams is extremely dangerous.",
                cwe_id="CWE-502",
                fix=(
                    "Use SerialKiller or a serialization filter (Java 9+ ObjectInputFilter) "
                    "to whitelist allowed classes. Prefer JSON/Protobuf for data exchange."
                ),
            )

        if filepath.endswith((".js", ".ts")):
            findings += self._regex_findings(
                filepath, lines, _NODE_SERIALIZE_RE,
                Severity.CRITICAL,
                "Insecure Deserialization — node-serialize",
                "The node-serialize package has a known RCE vulnerability (CVE-2017-5941). "
                "Deserializing attacker-controlled JSON with this library executes arbitrary code.",
                cwe_id="CWE-502",
                fix="Remove node-serialize entirely. Use JSON.parse() with schema validation.",
            )

        return findings

    def _make_yaml_finding(self, filepath: str, lineno: int, line: str):
        from ..models import Finding, Severity
        return Finding(
            file=filepath,
            line=lineno,
            severity=Severity.CRITICAL,
            title="Insecure Deserialization — yaml.load() without SafeLoader",
            description=(
                "yaml.load() with the default Loader can execute arbitrary Python code "
                "embedded in the YAML document (via !!python/object tags). "
                "This is exploitable if the YAML comes from any untrusted source."
            ),
            code_snippet=line.rstrip(),
            cwe_id="CWE-502",
            fix=(
                "Use yaml.safe_load() or explicitly pass SafeLoader:\n"
                "  yaml.load(data, Loader=yaml.SafeLoader)\n"
                "  # or simply:\n"
                "  yaml.safe_load(data)"
            ),
            scanner=self.name,
        )
