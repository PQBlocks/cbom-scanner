"""Live TLS handshake cipher-suite analyzer; does not inspect certificates.

Ideas follow the pqc-migrator `tls` subcommand pattern (connect, read the
negotiated cipher, classify quantum-vulnerability); no code is ported.
Standard library only (ssl, socket): no new dependencies.

Honest limitation: stdlib getpeercert() dicts omit the certificate
signature algorithm, so the live connector does not inspect the certificate
and reports cipher-derived assets only; cert_to_asset()
classifies normalized caller-supplied dicts with explicit sig_alg/key_size.
"""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .models import CryptoAsset

TLS_DEFAULT_PORT = 443

_PQC_PREFIXES = ("ML-KEM", "ML-DSA")

# Connector injection type: returns ((cipher, version, bits), cert-or-None).
Connector = Callable[[str, int, float],
                     Tuple[Tuple[str, str, int], Optional[Dict]]]


def _tls_path(host: str, port: int) -> str:
    return f"tls://{host}:{port}"


def _vuln_deadline(algorithm: str) -> Tuple[bool, Optional[int]]:
    upper = algorithm.upper()
    if upper.startswith(_PQC_PREFIXES):
        return False, None
    if upper in {"MD5", "SHA-1"}:
        return True, 2026
    if upper.startswith("RSA-"):
        return True, 2031
    return True, None


def parse_cipher_suite(cipher_name: str) -> List[Tuple[str, int]]:
    """Extract (algorithm, key_size) primitives from an IANA cipher name."""
    if not isinstance(cipher_name, str):
        raise TypeError("cipher_name must be a string")
    if not cipher_name:
        raise ValueError("cipher_name must be a non-empty string")
    upper = cipher_name.upper()
    found: List[Tuple[str, int]] = []
    if "MLKEM" in upper.replace("-", "").replace("_", "") or "ML-KEM" in upper or "KYBER" in upper:
        found.append(("ML-KEM-768", 768))
    if "X25519" in upper:
        found.append(("X25519", 255))
    if "ECDSA" in upper:
        found.append(("ECDSA-P256", 256))
    elif "RSA" in upper:
        found.append(("RSA-2048", 2048))
    if "AES_256" in upper or "AES256" in upper:
        found.append(("AES-256", 256))
    elif "AES_128" in upper or "AES128" in upper:
        found.append(("AES-128", 128))
    if "CHACHA20" in upper:
        found.append(("CHACHA20", 256))
    if "SHA384" in upper or "SHA_384" in upper:
        found.append(("SHA-384", 384))
    elif "SHA256" in upper or "SHA_256" in upper:
        found.append(("SHA-256", 256))
    elif "SHA1" in upper.replace("_", "").replace("-", "") and "SHA384" not in upper and "SHA256" not in upper:
        found.append(("SHA-1", 160))
    if "MD5" in upper:
        found.append(("MD5", 128))
    if not found:
        raise ValueError(f"no known primitives in cipher {cipher_name!r}")
    return found


def cipher_to_assets(cipher_name: str, host: str, port: int = TLS_DEFAULT_PORT) -> List[CryptoAsset]:
    """Build one CryptoAsset per primitive parsed from a cipher-suite name."""
    path = _tls_path(host, port)
    assets: List[CryptoAsset] = []
    for i, (alg, size) in enumerate(parse_cipher_suite(cipher_name), start=1):
        vuln, deadline = _vuln_deadline(alg)
        assets.append(CryptoAsset(
            asset_id=f"{path}:{i}",
            algorithm=alg,
            key_size=size,
            protocol="TLS",
            file_path=path,
            line_number=i,
            is_quantum_vulnerable=vuln,
            cnsa2_deadline_year=deadline,
            abstraction_isolated=False,
        ))
    return assets


def cert_to_asset(cert: Dict, host: str, port: int = TLS_DEFAULT_PORT) -> CryptoAsset:
    """Classify a normalized peer-cert dict into a CryptoAsset."""
    if not isinstance(cert, dict):
        raise TypeError("cert must be a dict")
    sig = cert.get("sig_alg")
    if not isinstance(sig, str) or not sig:
        raise ValueError("cert must carry a non-empty 'sig_alg' string")
    size = cert.get("key_size")
    if not isinstance(size, int) or isinstance(size, bool):
        raise ValueError("cert must carry an integer 'key_size'")
    upper = sig.upper()
    path = _tls_path(host, port)
    if "ML-DSA" in upper or "ML-KEM" in upper:
        alg = sig.upper()
        vuln, deadline = False, None
    elif "X25519" in upper:
        alg, vuln, deadline = "X25519", True, None
    elif "ECDSA" in upper:
        alg = "ECDSA-P384" if size == 384 else "ECDSA-P521" if size == 521 else "ECDSA-P256"
        vuln, deadline = True, None
    elif "RSA" in upper:
        alg = f"RSA-{size}"
        vuln, deadline = True, 2026 if "MD5" in upper else 2031
    else:
        raise ValueError(f"Unknown certificate signature algorithm {sig!r}")
    return CryptoAsset(
        asset_id=f"{path}:cert",
        algorithm=alg,
        key_size=size,
        protocol="TLS",
        file_path=path,
        line_number=1,
        is_quantum_vulnerable=vuln,
        cnsa2_deadline_year=deadline,
        abstraction_isolated=False,
    )


def _live_connector(host: str, port: int, timeout: float) -> Tuple[Tuple[str, str, int], Optional[Dict]]:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            cipher = tls.cipher()
            if not cipher:
                raise RuntimeError(f"TLS handshake with {host}:{port} returned no cipher")
            return (cipher[0], cipher[1], int(cipher[2])), None


@dataclass
class ProbeResult:
    host: str
    port: int
    cipher_name: str
    protocol_version: str
    assets: List[CryptoAsset] = field(default_factory=list)

    @property
    def asset_count(self) -> int:
        return len(self.assets)

    def to_dict(self) -> Dict:
        return {
            "host": self.host,
            "port": self.port,
            "cipher": self.cipher_name,
            "protocol_version": self.protocol_version,
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


def probe_endpoint(host: str, port: int = TLS_DEFAULT_PORT,
                   timeout: float = 5.0,
                   connector: Optional[Connector] = None) -> ProbeResult:
    """Probe a TLS endpoint; connector injectable so tests avoid the network."""
    if not isinstance(host, str) or not host:
        raise ValueError("host must be a non-empty string")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer in 1..65535")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise ValueError("timeout must be positive")
    connect = connector or _live_connector
    cipher_tuple, cert = connect(host, port, float(timeout))
    cipher_name = cipher_tuple[0]
    version = cipher_tuple[1] if len(cipher_tuple) > 1 else "unknown"
    assets = cipher_to_assets(cipher_name, host, port)
    if cert is not None:
        asset = cert_to_asset(cert, host, port)
        asset.line_number = len(assets) + 1
        asset.asset_id = f"{_tls_path(host, port)}:{asset.line_number}"
        assets.append(asset)
    return ProbeResult(host=host, port=port, cipher_name=cipher_name,
                       protocol_version=version, assets=assets)


__all__ = ["TLS_DEFAULT_PORT", "ProbeResult", "parse_cipher_suite",
           "cipher_to_assets", "cert_to_asset", "probe_endpoint"]
