import os
import re
import ast
from typing import List, Set, Dict, Optional

# Import CryptoAsset from sibling models module
from .models import CryptoAsset

# Helper to deduce key size from algorithm name
def _key_size_from_algorithm(algorithm: str) -> int:
    # RSA-2048, AES-256, SHA-1, SHA-256, MD5, ECDSA-P256, X25519, ED25519, ML-KEM-768, ML-DSA-65
    if m := re.match(r"RSA-(\d+)", algorithm):
        return int(m.group(1))
    if m := re.match(r"AES-(\d+)", algorithm):
        return int(m.group(1))
    if m := re.match(r"SHA-(\d+)", algorithm):
        return int(m.group(1))
    if algorithm == "MD5":
        return 128
    if m := re.match(r"ECDSA-P(\d+)", algorithm):
        return int(m.group(1))
    if algorithm in ("X25519", "ED25519"):
        return 256
    if m := re.match(r"ML-(KEM|DSA)-(\d+)", algorithm):
        return int(m.group(2))
    # default fallback
    return 256

# Helper to decide quantum vulnerability and CNSA2 deadline
def _quantum_vulnerable_and_deadline(algorithm: str):
    pqc_set = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}
    if algorithm in pqc_set:
        return False, None
    # Quantum-resistant symmetric & hash per CNSA 2.0 / NIST
    if algorithm in {"AES-256", "SHA-256", "SHA-384", "SHA-512"}:
        return False, None
    # Legacy algorithms are quantum vulnerable
    if algorithm in {"MD5", "SHA-1"}:
        return True, 2026
    if algorithm.startswith("RSA-"):
        return True, 2031
    # For other legacy (ECDSA-P256, AES-128) we mark vulnerable but no deadline
    return True, None

def make_asset(algorithm: str, file_path: str, line_number: int, protocol: Optional[str] = None, abstraction_isolated: Optional[bool] = None) -> CryptoAsset:
    # Known algorithms (case‑insensitive)
    known = {
        "RSA-1024",
        "RSA-2048",
        "RSA-3072",
        "RSA-4096",
        "ECDSA-P256",
        "ECDSA-P384",
        "ECDSA-P521",
        "MD5",
        "SHA-1",
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "AES-128",
        "AES-192",
        "AES-256",
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "X25519",
        "ED25519",
    }
    alg_norm = algorithm.upper()
    # Accept literals exactly as in known set; reject unknown
    if alg_norm not in known:
        m = re.match(r"^RSA-(\d+)$", alg_norm)
        if not m:
            raise ValueError(f"Unknown algorithm {algorithm}")
    key_size = _key_size_from_algorithm(alg_norm)
    is_vuln, deadline = _quantum_vulnerable_and_deadline(alg_norm)
    asset_id = f"{file_path}:{line_number}"
    if abstraction_isolated is None:
        abstraction_isolated = not is_vuln
    return CryptoAsset(
        asset_id=asset_id,
        algorithm=alg_norm,
        key_size=key_size,
        protocol=protocol,
        file_path=file_path,
        line_number=line_number,
        is_quantum_vulnerable=is_vuln,
        cnsa2_deadline_year=deadline,
        abstraction_isolated=abstraction_isolated,
    )

class DiscoveryResult:
    def __init__(self, file_path: str, assets: List[CryptoAsset]):
        self.file_path = file_path
        self.assets = assets

    @property
    def asset_count(self) -> int:
        return len(self.assets)

    def get_algorithms(self) -> List[str]:
        return [a.algorithm for a in self.assets]

    def to_dict(self) -> Dict:
        return {
            "file_path": self.file_path,
            "assets": [
                {
                    "algorithm": a.algorithm,
                    "key_size": a.key_size,
                    "line_number": a.line_number,
                    "is_quantum_vulnerable": a.is_quantum_vulnerable,
                    "cnsa2_deadline_year": a.cnsa2_deadline_year,
                    "protocol": a.protocol,
                }
                for a in self.assets
            ],
        }

# ------------------------------------------------------------
# AST based discovery – parses Python source
# ------------------------------------------------------------
class ASTDiscovery:
    def scan(self, source: str, file_path: str) -> List[CryptoAsset]:
        if not isinstance(source, str):
            raise TypeError("source must be a string")
        tree = ast.parse(source)
        assets: List[CryptoAsset] = []
        for node in ast.walk(tree):
            # hashlib calls (md5, sha1, sha256)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                    name = node.func.attr.upper()
                    if name in {"MD5", "SHA1", "SHA256"}:
                        alg = name.replace("1", "-1").replace("256", "-256")
                        assets.append(make_asset(alg, file_path, node.lineno))
            # hashlib.new('md5'), hashlib.new('sha1'), etc.
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                    if node.func.attr == "new" and node.args:
                        # First argument should be the algorithm name as string
                        if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                            alg_name = node.args[0].value.upper()
                            if alg_name == "MD5":
                                assets.append(make_asset("MD5", file_path, node.lineno))
                            elif alg_name == "SHA1":
                                assets.append(make_asset("SHA-1", file_path, node.lineno))
                            elif alg_name == "SHA256":
                                assets.append(make_asset("SHA-256", file_path, node.lineno))
            # Crypto.PublicKey.RSA.generate(bits) - handles both:
            #   import Crypto.PublicKey.RSA; RSA.generate(2048)
            #   from Crypto.PublicKey import RSA; RSA.generate(2048)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "generate" and isinstance(node.func.value, ast.Name):
                    # Check if this is RSA.generate by seeing if the name refers to RSA
                    # We need to trace the import - for simplicity, check if the name could be RSA
                    # This is a heuristic: if the function name is 'generate' and the object is named 'RSA'
                    # and we're in a context where RSA likely refers to the crypto library
                    if node.func.value.id == "RSA":
                        # look for integer argument (bits)
                        bits = None
                        for arg in node.args:
                            if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                                bits = arg.value
                        for kw in node.keywords:
                            if kw.arg in {"bits", "key_size"} and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                                bits = kw.value.value
                        if bits:
                            assets.append(make_asset(f"RSA-{bits}", file_path, node.lineno))
            # cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "rsa"
                    and node.func.attr == "generate_private_key"
                ):
                    keysize = None
                    for kw in node.keywords:
                        if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                            keysize = kw.value.value
                    if keysize:
                        assets.append(make_asset(f"RSA-{keysize}", file_path, node.lineno))
            # ECDSA via ec.generate_private_key(ec.SECP256R1())
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "ec"
                    and node.func.attr == "generate_private_key"
                ):
                    for arg in node.args:
                        if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
                            if arg.func.attr in {"SECP256R1", "SECP256K1"}:
                                assets.append(make_asset("ECDSA-P256", file_path, node.lineno))
            # AES via Crypto.Cipher.AES.new(...) - handles both:
            #   from Crypto.Cipher import AES; AES.new(...)
            #   import Crypto.Cipher; Crypto.Cipher.AES.new(...)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                # Check if this is AES.new by seeing if the object is named AES
                if node.func.attr == "new" and isinstance(node.func.value, ast.Name):
                    if node.func.value.id == "AES":
                        # Detect key size from arguments if present, fall back to 256
                        ks = 256
                        for kw in node.keywords:
                            if kw.arg == "key_size" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                                ks = kw.value.value
                        assets.append(make_asset(f"AES-{ks}", file_path, node.lineno))
            # PQC imports (from pqcrypto.kem import ml_kem_768, etc.)
            if isinstance(node, ast.ImportFrom):
                if node.module and "pqcrypto" in node.module:
                    for alias in node.names:
                        name = alias.name.upper()
                        if name in {"ML_KEM_768", "ML_DSA_65"}:
                            alg = name.replace("_", "-")
                            assets.append(make_asset(alg, file_path, node.lineno))
        # Deduplicate by (algorithm,line)
        seen: Set[tuple] = set()
        uniq: List[CryptoAsset] = []
        for a in assets:
            key = (a.algorithm, a.line_number)
            if key not in seen:
                seen.add(key)
                uniq.append(a)
        return uniq

# ------------------------------------------------------------
# Regex based discovery – works on any text file
# ------------------------------------------------------------
class RegexDiscovery:
    _patterns = {
        "RSA-1024": re.compile(r"rsa[-_]?1024|<openssl/rsa\.h>", re.I),
        "RSA-2048": re.compile(r"rsa[-_]?2048", re.I),
        "MD5": re.compile(r"\bmd5\b", re.I),
        "SHA-1": re.compile(r"sha[-_]?1", re.I),
        "SHA-256": re.compile(r"sha[-_]?256", re.I),
        "AES-256": re.compile(r"aes[-_]?256", re.I),
        "ECDSA-P256": re.compile(r"ecdsa.*?p[-_]?256", re.I),  # More flexible to match "curve P-256"
        "ML-KEM-768": re.compile(r"ml[-_]?kem[-_]?768", re.I),
        "ML-DSA-65": re.compile(r"ml[-_]?dsa[-_]?65", re.I),
        "X25519": re.compile(r"x25519", re.I),
        "ED25519": re.compile(r"ed25519", re.I),
    }

    def scan(self, source: str, file_path: str) -> List[CryptoAsset]:
        if not source:
            return []
        assets: List[CryptoAsset] = []
        lines = source.splitlines()
        for idx, line in enumerate(lines, start=1):
            for alg, pat in self._patterns.items():
                if pat.search(line):
                    assets.append(make_asset(alg, file_path, idx))
        # Deduplicate
        seen: Set[tuple] = set()
        uniq: List[CryptoAsset] = []
        for a in assets:
            key = (a.algorithm, a.line_number)
            if key not in seen:
                seen.add(key)
                uniq.append(a)
        return uniq

# ------------------------------------------------------------
# High‑level orchestrator
# ------------------------------------------------------------
class Discovery:
    def __init__(self):
        self.ast = ASTDiscovery()
        self.regex = RegexDiscovery()

    def discover_source(self, source: str, file_path: str) -> DiscoveryResult:
        if not isinstance(source, str):
            raise TypeError("source must be a string")
        ast_assets = []
        if file_path.endswith(".py"):
            ast_assets = self.ast.scan(source, file_path)
        regex_assets = self.regex.scan(source, file_path)
        # Combine and dedupe
        combined: List[CryptoAsset] = []
        seen: Set[tuple] = set()
        for a in ast_assets + regex_assets:
            key = (a.algorithm, a.line_number)
            if key not in seen:
                seen.add(key)
                combined.append(a)
        return DiscoveryResult(file_path, combined)

    def discover_file(self, path: str) -> DiscoveryResult:
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        try:
            with open(path, "r", encoding="utf-8") as f:
                src = f.read()
        except UnicodeDecodeError:
            with open(path, "r", encoding="latin-1", errors="replace") as f:
                src = f.read()
        return self.discover_source(src, path)

__all__ = ["make_asset", "ASTDiscovery", "RegexDiscovery", "Discovery", "DiscoveryResult"]