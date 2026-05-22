from __future__ import annotations

_MASK = 2**250 - 1


def _k256(data: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak as _k
        h = _k.new(digest_bits=256); h.update(data); return h.digest()
    except ImportError: pass
    try:
        from eth_hash.auto import keccak; return keccak(data)
    except ImportError: pass
    import hashlib, warnings
    warnings.warn("pycryptodome missing — using sha3_256 (demo only)")
    return hashlib.sha3_256(data).digest()


def sn_keccak(name: str) -> int:
    return int.from_bytes(_k256(name.encode()), "big") & _MASK
