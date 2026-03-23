"""
VibeScan — Weak Cryptography Scanner
Detects use of broken or weak cryptographic algorithms, insecure modes,
and small key sizes that do not meet modern security standards.
"""

import re
from .base import BaseScanner
from ..models import Finding, Severity


# hashlib with MD5 or SHA1 used for security purposes
_MD5_RE  = re.compile(r"\bhashlib\.md5\s*\(|\.new\s*\(\s*['\"]md5['\"]", re.IGNORECASE)
_SHA1_RE = re.compile(r"\bhashlib\.sha1\s*\(|\.new\s*\(\s*['\"]sha1['\"]", re.IGNORECASE)

# PyCryptodome / cryptography: DES, RC4, Blowfish
_DES_RE      = re.compile(r"\b(DES|DES3|ARC4|RC4|Blowfish)\b")
_ECB_MODE_RE = re.compile(r"\bMODE_ECB\b|mode\s*=\s*AES\.MODE_ECB")

# Small RSA / ECDSA key sizes
_SMALL_RSA_RE = re.compile(r"generate(?:_private_key|_key)?\s*\(")

# Random used for security (instead of secrets module)
_RANDOM_SECURITY_RE = re.compile(
    r"random\.(random|randint|choice|shuffle|randrange|sample)\s*\("
)

# Weak password hashing
_MD5_PASSWORD_RE = re.compile(
    r"(password|passwd|pwd).*md5|md5.*(password|passwd|pwd)",
    re.IGNORECASE,
)

# SSL/TLS: disabling verification
_SSL_NO_VERIFY_RE = re.compile(
    r"verify\s*=\s*False|ssl\._create_unverified_context\s*\(\s*\)|"
    r"CERT_NONE|check_hostname\s*=\s*False"
)

# Hardcoded salt / IV
_HARDCODED_IV_RE = re.compile(
    r"(iv|nonce|salt)\s*=\s*b?['\"][^'\"]{8,}['\"]",
    re.IGNORECASE,
)


class WeakCryptoScanner(BaseScanner):
    name = "WeakCryptoScanner"
    SUPPORTED_EXTENSIONS = (".py", ".js", ".ts", ".java", ".php", ".go")

    def scan_file(self, filepath: str, content: str, lines: list[str]) -> list[Finding]:
        findings = []

        if filepath.endswith(".py"):
            findings += self._regex_findings(
                filepath, lines, _MD5_RE,
                Severity.HIGH,
                "Weak Crypto — MD5 Hash Function",
                "MD5 is cryptographically broken and must not be used for security purposes "
                "(password hashing, integrity checking, digital signatures). Collisions are trivially generated.",
                cwe_id="CWE-327",
                fix=(
                    "Use hashlib.sha256() or hashlib.sha3_256() for checksums. "
                    "For passwords, use bcrypt, argon2, or PBKDF2:\n"
                    "  import bcrypt\n"
                    "  hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())"
                ),
            )
            findings += self._regex_findings(
                filepath, lines, _SHA1_RE,
                Severity.MEDIUM,
                "Weak Crypto — SHA-1 Hash Function",
                "SHA-1 is deprecated and collision attacks exist (SHAttered, 2017). "
                "Do not use for signatures, certificates, or security-critical integrity checks.",
                cwe_id="CWE-327",
                fix="Replace with SHA-256 or SHA-3: hashlib.sha256() / hashlib.sha3_256()",
            )
            findings += self._regex_findings(
                filepath, lines, _DES_RE,
                Severity.HIGH,
                "Weak Crypto — Broken Cipher (DES / RC4 / Blowfish)",
                "DES (56-bit key), RC4, and Blowfish have known weaknesses and are no longer "
                "considered secure for production systems.",
                cwe_id="CWE-327",
                fix="Replace with AES-256-GCM using the cryptography library:\n"
                    "  from cryptography.hazmat.primitives.ciphers.aead import AESGCM",
            )
            findings += self._regex_findings(
                filepath, lines, _ECB_MODE_RE,
                Severity.HIGH,
                "Weak Crypto — AES in ECB Mode",
                "ECB mode applies the cipher identically to each block, leaking patterns in "
                "the plaintext (the 'Penguin Problem'). It provides no semantic security.",
                cwe_id="CWE-327",
                fix="Use AES-GCM (authenticated encryption) or at minimum AES-CBC with a random IV.",
            )
            findings += self._regex_findings(
                filepath, lines, _SMALL_RSA_RE,
                Severity.HIGH,
                "Weak Crypto — Small RSA/EC Key Size",
                "RSA keys of 512, 768, or 1024 bits can be factored. "
                "Minimum recommended size is 2048 bits (3072 for long-term security).",
                cwe_id="CWE-326",
                fix="Generate RSA keys with at least 2048 bits:\n"
                    "  rsa.generate_private_key(public_exponent=65537, key_size=3072)",
            )
            findings += self._regex_findings(
                filepath, lines, _RANDOM_SECURITY_RE,
                Severity.HIGH,
                "Weak Crypto — random Module for Security Token",
                "Python's random module is a PRNG seeded from time, not cryptographically secure. "
                "Do not use for session tokens, OTPs, CSRF tokens, or password reset links.",
                cwe_id="CWE-338",
                fix=(
                    "Use the secrets module for security-sensitive random values:\n"
                    "  import secrets\n"
                    "  token = secrets.token_urlsafe(32)"
                ),
            )
            findings += self._regex_findings(
                filepath, lines, _SSL_NO_VERIFY_RE,
                Severity.CRITICAL,
                "Weak Crypto — SSL/TLS Certificate Verification Disabled",
                "Disabling SSL certificate verification (verify=False) makes the connection "
                "vulnerable to man-in-the-middle attacks. Attackers can intercept all traffic.",
                cwe_id="CWE-295",
                fix=(
                    "Remove verify=False. Always validate certificates:\n"
                    "  requests.get(url)  # verify=True is the default\n"
                    "If using a custom CA, pass the CA bundle:\n"
                    "  requests.get(url, verify='/path/to/ca-bundle.crt')"
                ),
            )
            findings += self._regex_findings(
                filepath, lines, _HARDCODED_IV_RE,
                Severity.HIGH,
                "Weak Crypto — Hardcoded IV / Nonce / Salt",
                "A static IV or nonce defeats the purpose of the cipher mode. "
                "Reusing an IV with the same key can reveal the plaintext (especially in GCM/CTR).",
                cwe_id="CWE-330",
                fix=(
                    "Generate a fresh random IV/nonce for every encryption:\n"
                    "  iv = os.urandom(16)  # for AES-CBC\n"
                    "  nonce = os.urandom(12)  # for AES-GCM"
                ),
            )

        return findings
