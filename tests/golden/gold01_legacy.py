"""
GOLD-01: Legacy Django application instance.
Contains legacy MD5 password hashing and RSA-1024 private key generation.
Spec target: Grade F, fails CI.
"""
import hashlib
from Crypto.PublicKey import RSA

def legacy_hash(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

def generate_legacy_key():
    return RSA.generate(1024)
