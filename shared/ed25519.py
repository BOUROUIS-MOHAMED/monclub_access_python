"""Pure-Python Ed25519 (RFC 8032 section 5.1): sign and verify.

The only Ed25519 implementation in this repo (design: docs/access-updater-v2 section 5.1).
The client verifies release manifests with it; tools/release_sign.py signs with it.
No native dependency: the build venv has no ``cryptography`` (Python 3.14, 32-bit).

Not constant-time. Signing runs only on the owner's build PC with the owner's own key;
verification handles public data only.
"""

from __future__ import annotations

import hashlib

__all__ = ["public_key_from_seed", "sign", "verify"]

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

# Base point in extended homogeneous coordinates (X, Y, Z, T), x = X/Z, y = Y/Z, xy = T/Z.
_GY = (4 * pow(5, _P - 2, _P)) % _P


def _recover_x(y: int, sign_bit: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        if sign_bit:
            return None
        return 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign_bit:
        x = _P - x
    return x


_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)
_IDENTITY = (0, 1, 1, 0)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s: int, p):
    q = _IDENTITY
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _equal(p, q) -> bool:
    if (p[0] * q[2] - q[0] * p[2]) % _P != 0:
        return False
    return (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _compress(p) -> bytes:
    zinv = pow(p[2], _P - 2, _P)
    x = p[0] * zinv % _P
    y = p[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign_bit = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign_bit)  # refuses y >= p: non-canonical encodings
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _sha512_int(*parts: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def _expand_seed(seed: bytes) -> tuple[int, bytes]:
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(bytes(seed)).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key_from_seed(seed32: bytes) -> bytes:
    """The 32-byte public key of a 32-byte private seed."""
    a, _prefix = _expand_seed(seed32)
    return _compress(_mul(a, _G))


def sign(seed32: bytes, message: bytes) -> bytes:
    """The 64-byte Ed25519 signature of ``message`` under the 32-byte private seed."""
    a, prefix = _expand_seed(seed32)
    public = _compress(_mul(a, _G))
    msg = bytes(message)
    r = _sha512_int(prefix, msg) % _L
    big_r = _compress(_mul(r, _G))
    k = _sha512_int(big_r, public, msg) % _L
    s = (r + k * a) % _L
    return big_r + int.to_bytes(s, 32, "little")


def verify(public_key32: bytes, message: bytes, signature64: bytes) -> bool:
    """True only for a valid signature. Never raises: any malformed input is False."""
    try:
        if not isinstance(public_key32, (bytes, bytearray)) or len(public_key32) != 32:
            return False
        if not isinstance(signature64, (bytes, bytearray)) or len(signature64) != 64:
            return False
        if not isinstance(message, (bytes, bytearray)):
            return False
        public_key32 = bytes(public_key32)
        signature64 = bytes(signature64)
        a_point = _decompress(public_key32)
        if a_point is None:
            return False
        r_bytes = signature64[:32]
        r_point = _decompress(r_bytes)
        if r_point is None:
            return False
        s = int.from_bytes(signature64[32:], "little")
        if s >= _L:
            return False
        k = _sha512_int(r_bytes, public_key32, bytes(message)) % _L
        # [S]B == R + [k]A  (the cofactorless check of RFC 8032 section 5.1.7)
        return _equal(_mul(s, _G), _add(r_point, _mul(k, a_point)))
    except Exception:
        return False
