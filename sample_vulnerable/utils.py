"""
sample_vulnerable/utils.py — More vulnerable patterns for testing.
"""
import ssl
import requests
from Crypto.Cipher import DES, AES

# [FLAW] Hardcoded JWT secret (Redacted)
JWT_SECRET = "jwt_secret=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"

# [FLAW] Hardcoded Stripe key (Redacted for GH push)
STRIPE_KEY = "sk" + "_live_XXXXXXXXXXXXXXXXXXXXXXXX"

# [FLAW] Hardcoded private key snippet (Redacted)
PRIVATE_KEY_HEADER = "-----BEGIN RSA REDACTED KEY-----"

# [FLAW] Insecure SSL — disable certificate verification
def fetch_data(url):
    response = requests.get(url, verify=False)
    return response.json()

# [FLAW] AES in ECB mode
def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

# [FLAW] DES cipher (broken)
def encrypt_des(data: bytes, key: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)

# [FLAW] Hardcoded IV
iv = b"1234567890abcdef"

# [FLAW] Logging a password
import logging
logger = logging.getLogger(__name__)

def authenticate(username, password):
    logger.info(f"Login attempt: username={username} password={password}")
    return True
