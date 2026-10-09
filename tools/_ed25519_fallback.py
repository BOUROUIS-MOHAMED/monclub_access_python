"""TEMPORARY Ed25519 (RFC 8032) for tools/release_sign.py until lane L3's shared/ed25519.py lands.

Design.md section 5.1: there is ONE Ed25519 implementation, ``shared/ed25519.py``, owned by
lane L3. Lane L2's signing tool imports it; this module exists only so L2 can build and test
before L3 lands, behind exactly the agreed API (L2/L3, 2026-10-09):

    public_key_from_seed(seed32: bytes) -> bytes        # 32 bytes
    sign(seed32: bytes, message: bytes) -> bytes        # 64 bytes
    verify(public_key32: bytes, message: bytes, signature64: bytes) -> bool   # never raises

L4: delete this file once ``shared/ed25519.py`` is merged (tools/release_sign.py prefers it).

The arithmetic is the reference implementation of RFC 8032 section 6 (pure Python, no native
dependency); tests/test_updater_v2_release_sign.py checks it against the RFC 8032 section 7.1
vectors. Not constant-time: it runs only on the owner's build PC and in tests.
"""
from __future__ import annotations

import hashlib

_p = 2**255 - 19
_q = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, _p - 2, _p)


_d = -121665 * _inv(121666) % _p
_sqrt_m1 = pow(2, (_p - 1) // 4, _p)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _sha512_modq(data: bytes) -> int:
    return int.from_bytes(_sha512(data), "little") % _q


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F, G * H, F * G, E * H)


def _mul(s: int, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P, Q) -> bool:
    if (P[0] * Q[2] - Q[0] * P[2]) % _p != 0:
        return False
    return (P[1] * Q[2] - Q[1] * P[2]) % _p == 0


def _recover_x(y: int, sign: int):
    if y >= _p:
        return None
    x2 = (y * y - 1) * _inv(_d * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * _sqrt_m1 % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


_gy = 4 * _inv(5) % _p
_gx = _recover_x(_gy, 0)
_G = (_gx, _gy, 1, _gx * _gy % _p)


def _compress(P) -> bytes:
    zinv = _inv(P[2])
    x = P[0] * zinv % _p
    y = P[1] * zinv % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _p)


def _expand(seed: bytes):
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = _sha512(bytes(seed))
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key_from_seed(seed32: bytes) -> bytes:
    a, _prefix = _expand(seed32)
    return _compress(_mul(a, _G))


def sign(seed32: bytes, message: bytes) -> bytes:
    a, prefix = _expand(seed32)
    A = _compress(_mul(a, _G))
    r = _sha512_modq(prefix + bytes(message))
    Rs = _compress(_mul(r, _G))
    h = _sha512_modq(Rs + A + bytes(message))
    s = (r + h * a) % _q
    return Rs + int.to_bytes(s, 32, "little")


def verify(public_key32: bytes, message: bytes, signature64: bytes) -> bool:
    try:
        if len(public_key32) != 32 or len(signature64) != 64:
            return False
        A = _decompress(bytes(public_key32))
        if A is None:
            return False
        Rs = bytes(signature64[:32])
        R = _decompress(Rs)
        if R is None:
            return False
        s = int.from_bytes(signature64[32:], "little")
        if s >= _q:
            return False
        h = _sha512_modq(Rs + bytes(public_key32) + bytes(message))
        return _equal(_mul(s, _G), _add(R, _mul(h, A)))
    except Exception:
        return False


__all__ = ["public_key_from_seed", "sign", "verify"]
