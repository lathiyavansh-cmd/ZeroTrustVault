"""Encoding helpers shared by the Python core and (by contract) the TypeScript client."""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any


def b64u(data: bytes) -> str:
    """base64url without padding (RFC 4648 section 5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8, no NaN.

    The TypeScript client implements the identical function so that signatures
    over manifests, certificates and grants verify on both sides.
    Only str / int / bool / None / list / dict are allowed (no floats).
    """
    _check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _check(obj: Any) -> None:
    if isinstance(obj, float):
        raise TypeError("floats are not allowed in canonical JSON (use ints or strings)")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TypeError("dict keys must be strings")
            _check(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _check(v)
    elif obj is not None and not isinstance(obj, (str, int, bool)):
        raise TypeError(f"unsupported type in canonical JSON: {type(obj)!r}")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
