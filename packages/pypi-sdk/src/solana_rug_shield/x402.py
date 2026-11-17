"""Solana x402 HTTP 402 challenge parser, Ed25519 tx builder, and auto-upgrade engine."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import inspect
import json
import os
import re
import struct
import time
import urllib.request
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

from .constants import (
    DEFAULT_SOLANA_RPC_URL,
    FREE_PINGS_LIMIT,
    OPTION_A_LAMPORTS,
    OPTION_A_PRO_PASS,
    OPTION_A_SOL,
    OPTION_A_USD,
    OPTION_B_LAMPORTS,
    OPTION_B_SINGLE_SCAN,
    OPTION_B_SOL,
    OPTION_B_USD,
    TREASURY_WALLET,
    X402_NETWORK,
    X402_SCHEME,
    X402_TIERS,
    X402_VERSION,
)

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_MAP = {ch: idx for idx, ch in enumerate(_B58_ALPHABET)}


def b58encode(data: bytes) -> str:
    """Encode raw bytes into Bitcoin/Solana Base58."""
    if not data:
        return ""
    leading_zeros = 0
    for b in data:
        if b == 0:
            leading_zeros += 1
        else:
            break
    num = int.from_bytes(data, "big")
    chars: List[str] = []
    while num > 0:
        num, rem = divmod(num, 58)
        chars.append(_B58_ALPHABET[rem])
    return ("1" * leading_zeros) + "".join(reversed(chars))


def b58decode(text: str) -> bytes:
    """Decode Bitcoin/Solana Base58 string into raw bytes."""
    clean = text.strip()
    if not clean:
        return b""
    leading_ones = 0
    for ch in clean:
        if ch == "1":
            leading_ones += 1
        else:
            break
    num = 0
    for ch in clean:
        if ch not in _B58_MAP:
            raise ValueError(f"Invalid Base58 character: {ch!r}")
        num = num * 58 + _B58_MAP[ch]
    body = b"" if num == 0 else num.to_bytes((num.bit_length() + 7) // 8, "big")
    return (b"\x00" * leading_ones) + body


# Pure-Python RFC 8032 Ed25519 fallback (used only when solders and cryptography are absent)
_ED_P = (1 << 255) - 19
_ED_L = (1 << 252) + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    x = pow(xx, (_ED_P + 3) // 8, _ED_P)
    if (x * x - xx) % _ED_P != 0:
        x = (x * _ED_I) % _ED_P
    if x % 2 != 0:
        x = _ED_P - x
    return x


_ED_BY = (4 * pow(5, _ED_P - 2, _ED_P)) % _ED_P
_ED_BX = _ed_xrecover(_ED_BY)
_ED_B = (_ED_BX % _ED_P, _ED_BY % _ED_P, 1, (_ED_BX * _ED_BY) % _ED_P)


def _ed_add(p1: Tuple[int, int, int, int], p2: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _ED_P
    b = ((y1 + x1) * (y2 + x2)) % _ED_P
    c = (t1 * 2 * _ED_D * t2) % _ED_P
    d = (z1 * 2 * z2) % _ED_P
    e = (b - a) % _ED_P
    f = (d - c) % _ED_P
    g = (d + c) % _ED_P
    h = (b + a) % _ED_P
    return (e * f) % _ED_P, (g * h) % _ED_P, (f * g) % _ED_P, (e * h) % _ED_P


def _ed_scalarmult(pt: Tuple[int, int, int, int], e: int) -> Tuple[int, int, int, int]:
    res = (0, 1, 1, 0)
    cur = pt
    while e > 0:
        if e & 1:
            res = _ed_add(res, cur)
        cur = _ed_add(cur, cur)
        e >>= 1
    return res


def _ed_encodepoint(pt: Tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, _ED_P - 2, _ED_P)
    xp = (x * zi) % _ED_P
    yp = (y * zi) % _ED_P
    out = bytearray(yp.to_bytes(32, "little"))
    if xp & 1:
        out[31] |= 0x80
    return bytes(out)


def _pure_ed25519_pubkey(seed32: bytes) -> bytes:
    h = hashlib.sha512(seed32).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _ed_encodepoint(_ed_scalarmult(_ED_B, a))


def _pure_ed25519_sign(seed32: bytes, message: bytes) -> bytes:
    h = hashlib.sha512(seed32).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    pub = _ed_encodepoint(_ed_scalarmult(_ED_B, a))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _ED_L
    r_pt = _ed_encodepoint(_ed_scalarmult(_ED_B, r))
    k = int.from_bytes(hashlib.sha512(r_pt + pub + message).digest(), "little") % _ED_L
    s = (r + k * a) % _ED_L
    return r_pt + s.to_bytes(32, "little")


def ed25519_pubkey_from_seed(seed32: bytes) -> bytes:
    """Derive 32-byte Ed25519 public key from 32-byte seed."""
    if len(seed32) != 32:
        raise ValueError(f"Expected 32-byte Ed25519 seed, got {len(seed32)} bytes")
    try:
        from solders.keypair import Keypair  # type: ignore

        return bytes(Keypair.from_seed(seed32).pubkey())
    except Exception:
        pass
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # type: ignore
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # type: ignore

        priv = Ed25519PrivateKey.from_private_bytes(seed32)
        return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    except Exception:
        pass
    return _pure_ed25519_pubkey(seed32)


def ed25519_sign(seed32: bytes, message: bytes) -> bytes:
    """Sign message bytes with 32-byte Ed25519 seed, returning 64-byte signature."""
    if len(seed32) != 32:
        raise ValueError(f"Expected 32-byte Ed25519 seed, got {len(seed32)} bytes")
    try:
        from solders.keypair import Keypair  # type: ignore

        return bytes(Keypair.from_seed(seed32).sign_message(message))
    except Exception:
        pass
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # type: ignore

        priv = Ed25519PrivateKey.from_private_bytes(seed32)
        return priv.sign(message)
    except Exception:
        pass
    return _pure_ed25519_sign(seed32, message)


@dataclasses.dataclass(frozen=True)
class SolanaKeyMaterial:
    seed32: bytes
    pubkey32: bytes
    pubkey_b58: str


def parse_solana_private_key(secret: Union[str, bytes, List[int]]) -> SolanaKeyMaterial:
    """Parse Solana private key from Base58, JSON byte array, hex, or raw bytes."""
    raw: bytes
    if isinstance(secret, (bytes, bytearray)):
        raw = bytes(secret)
    elif isinstance(secret, list):
        raw = bytes(int(x) for x in secret)
    elif isinstance(secret, str):
        trimmed = secret.strip()
        if not trimmed:
            raise ValueError("Empty Solana private key provided.")
        if trimmed.startswith("["):
            arr = json.loads(trimmed)
            if not isinstance(arr, list) or any(not isinstance(x, int) or x < 0 or x > 255 for x in arr):
                raise ValueError("SOLANA_PRIVATE_KEY JSON array must contain byte integers 0..255.")
            raw = bytes(arr)
        else:
            hex_cand = trimmed[2:] if trimmed.startswith(("0x", "0X")) else trimmed
            if len(hex_cand) in (64, 128) and re.fullmatch(r"[0-9a-fA-F]+", hex_cand):
                raw = bytes.fromhex(hex_cand)
            else:
                raw = b58decode(trimmed)
    else:
        raise TypeError(f"Unsupported Solana private key type: {type(secret)!r}")

    if len(raw) == 64:
        seed32 = raw[:32]
        derived_pub = ed25519_pubkey_from_seed(seed32)
        if raw[32:] != derived_pub:
            raise ValueError("Invalid 64-byte Solana keypair: public key half does not match Ed25519 seed.")
        return SolanaKeyMaterial(seed32=seed32, pubkey32=derived_pub, pubkey_b58=b58encode(derived_pub))
    if len(raw) == 32:
        derived_pub = ed25519_pubkey_from_seed(raw)
        return SolanaKeyMaterial(seed32=raw, pubkey32=derived_pub, pubkey_b58=b58encode(derived_pub))
    raise ValueError(f"Unexpected Solana secret key byte length {len(raw)}; expected 64 or 32 bytes.")


def _encode_compact_u16(value: int) -> bytes:
    if value < 0 or value > 0xFFFF:
        raise ValueError(f"compact-u16 out of range: {value}")
    out = bytearray()
    rem = value
    while True:
        elem = rem & 0x7F
        rem >>= 7
        if rem == 0:
            out.append(elem)
            break
        out.append(elem | 0x80)
    return bytes(out)


def build_solana_transfer_transaction(
    seed32: bytes,
    pubkey32: bytes,
    to_pubkey_b58: str,
    lamports: int,
    recent_blockhash_b58: str,
) -> Tuple[bytes, str]:
    """Build and Ed25519-sign a Legacy Solana SystemProgram.transfer wire transaction."""
    if lamports <= 0:
        raise ValueError(f"Transfer lamports must be positive, got {lamports}")
    to_bytes = b58decode(to_pubkey_b58)
    if len(to_bytes) != 32:
        raise ValueError(f"Destination Solana pubkey must decode to 32 bytes, got {len(to_bytes)}")
    bh_bytes = b58decode(recent_blockhash_b58)
    if len(bh_bytes) != 32:
        raise ValueError(f"Recent blockhash must decode to 32 bytes, got {len(bh_bytes)}")

    sys_prog = b"\x00" * 32
    ix_data = struct.pack("<IQ", 2, int(lamports))  # SystemInstruction::Transfer = 2

    if pubkey32 == to_bytes:
        header = bytes([1, 0, 1])
        accounts = [pubkey32, sys_prog]
        prog_idx = 1
        acc_indices = bytes([0, 0])
    else:
        header = bytes([1, 0, 1])
        accounts = [pubkey32, to_bytes, sys_prog]
        prog_idx = 2
        acc_indices = bytes([0, 1])

    msg = bytearray()
    msg.extend(header)
    msg.extend(_encode_compact_u16(len(accounts)))
    for acc in accounts:
        msg.extend(acc)
    msg.extend(bh_bytes)
    msg.extend(_encode_compact_u16(1))
    msg.append(prog_idx)
    msg.extend(_encode_compact_u16(len(acc_indices)))
    msg.extend(acc_indices)
    msg.extend(_encode_compact_u16(len(ix_data)))
    msg.extend(ix_data)

    message_bytes = bytes(msg)
    sig64 = ed25519_sign(seed32, message_bytes)
    wire_tx = _encode_compact_u16(1) + sig64 + message_bytes
    return wire_tx, b58encode(sig64)


def normalize_x402_option(raw: Optional[str]) -> str:
    """Normalize x402 payment option string into option_a_pro_pass or option_b_single_scan."""
    val = (raw or "").strip().lower()
    if val in (
        OPTION_B_SINGLE_SCAN,
        "option_b",
        "single_scan",
        "single",
        "b",
        "0.0003",
        "300000",
    ):
        return OPTION_B_SINGLE_SCAN
    return OPTION_A_PRO_PASS


def decode_base64_json(encoded: str) -> Optional[Dict[str, Any]]:
    """Decode standard or URL-safe Base64 JSON (with optional missing '=' padding)."""
    clean = (encoded or "").strip()
    if not clean:
        return None
    if clean.startswith("{") and clean.endswith("}"):
        try:
            parsed = json.loads(clean)
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            pass
    try:
        normalized = clean.replace("-", "+").replace("_", "/")
        pad_len = (4 - (len(normalized) % 4)) % 4
        raw = base64.b64decode(normalized + ("=" * pad_len))
        parsed = json.loads(raw.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def encode_x_payment_header(
    signature: str,
    payer: str,
    option: str,
    lamports: int,
    pay_to: str = TREASURY_WALLET,
    network: str = X402_NETWORK,
    scheme: str = X402_SCHEME,
) -> str:
    """Encode X-Payment base64 JSON header per STRICT_CONTRACT_SPEC.json."""
    envelope = {
        "x402Version": X402_VERSION,
        "scheme": scheme,
        "network": network,
        "payload": {
            "signature": signature,
            "payer": payer,
            "option": option,
            "lamports": int(lamports),
            "payTo": pay_to,
        },
    }
    raw_json = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw_json).decode("ascii")


def decode_x_payment_header(header_value: str) -> Optional[Dict[str, Any]]:
    """Decode an X-Payment / Payment-Signature base64 header back into a dict."""
    return decode_base64_json(header_value)


@dataclasses.dataclass
class X402Option:
    option: str
    lamports: int
    sol: float
    usd: float
    pay_to: str = TREASURY_WALLET
    scheme: str = X402_SCHEME
    network: str = X402_NETWORK
    unlimited: bool = False
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "option": self.option,
            "id": self.option,
            "lamports": self.lamports,
            "maxAmountRequired": str(self.lamports),
            "sol": self.sol,
            "amountSol": self.sol,
            "usd": self.usd,
            "priceUsd": self.usd,
            "payTo": self.pay_to,
            "treasury": self.pay_to,
            "scheme": self.scheme,
            "network": self.network,
            "unlimited": self.unlimited,
            "description": self.description,
        }


@dataclasses.dataclass
class X402Challenge:
    x402_version: int
    treasury: str
    treasury_verified: bool
    free_pings_limit: int
    free_pings_used: int
    free_pings_remaining: int
    option_a: X402Option
    option_b: X402Option
    accepts: List[Dict[str, Any]]
    www_authenticate: Optional[str] = None
    raw_header: Optional[Dict[str, Any]] = None
    raw_body: Optional[Any] = None

    def get_option(self, option_id: str) -> X402Option:
        norm = normalize_x402_option(option_id)
        return self.option_b if norm == OPTION_B_SINGLE_SCAN else self.option_a

    def to_dict(self) -> Dict[str, Any]:
        return {
            "x402Version": self.x402_version,
            "status": 402,
            "treasury": self.treasury,
            "treasuryVerified": self.treasury_verified,
            "freePingsLimit": self.free_pings_limit,
            "freePingsUsed": self.free_pings_used,
            "freePingsRemaining": self.free_pings_remaining,
            "wwwAuthenticate": self.www_authenticate,
            "options": {
                OPTION_A_PRO_PASS: self.option_a.to_dict(),
                OPTION_B_SINGLE_SCAN: self.option_b.to_dict(),
            },
            "accepts": self.accepts,
            "instructions": {
                "summary": (
                    f"10 free pings exhausted. Transfer {OPTION_A_SOL} SOL ({OPTION_A_LAMPORTS} lamports, "
                    f"$1.99 Unlimited Pro Pass) or {OPTION_B_SOL} SOL ({OPTION_B_LAMPORTS} lamports, "
                    f"$0.02 single scan) to {TREASURY_WALLET}."
                ),
                "manualRetry": (
                    "Pass payment_signature='<solana_tx_sig>' or pro_pass_token='<cached_token>' "
                    "to retry immediately."
                ),
                "autoPayEnv": (
                    "Set SOLANA_PRIVATE_KEY (or X402_SOLANA_PRIVATE_KEY) and optional "
                    "X402_OPTION=option_a_pro_pass|option_b_single_scan for automatic 402 payment."
                ),
            },
        }


class X402PaymentRequired(RuntimeError):
    """Structured exception raised on HTTP 402 when no auto-pay signer is configured."""

    def __init__(
        self,
        challenge: X402Challenge,
        headers: Optional[Mapping[str, str]] = None,
        body: Any = None,
    ) -> None:
        self.status_code: int = 402
        self.challenge: X402Challenge = challenge
        self.treasury: str = challenge.treasury
        self.option_a: X402Option = challenge.option_a
        self.option_b: X402Option = challenge.option_b
        self.headers: Dict[str, str] = dict(headers or {})
        self.body: Any = body
        msg = (
            f"HTTP 402 Payment Required (Solana x402): treasury={challenge.treasury} | "
            f"Option A ({OPTION_A_PRO_PASS}): {challenge.option_a.sol} SOL ({challenge.option_a.lamports} lamports, $1.99 Unlimited Pro Pass) | "
            f"Option B ({OPTION_B_SINGLE_SCAN}): {challenge.option_b.sol} SOL ({challenge.option_b.lamports} lamports, $0.02 Single Scan)"
        )
        super().__init__(msg)

    def to_dict(self) -> Dict[str, Any]:
        payload = self.challenge.to_dict()
        payload["ok"] = False
        payload["code"] = "PAYMENT_REQUIRED"
        payload["error"] = "payment_required"
        payload["paymentRequired"] = True
        return payload


def _ci_header(headers: Mapping[str, str], name: str) -> Optional[str]:
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target and v is not None:
            return str(v)
    return None


def _extract_lamports(entry: Mapping[str, Any], default_lamports: int) -> int:
    for key in ("lamports", "maxAmountRequired", "amountLamports", "required_lamports", "amount"):
        val = entry.get(key)
        if val is not None:
            try:
                num = float(val)
                if num >= 1000:
                    return int(round(num))
                if 0 < num < 10:
                    return int(round(num * 1_000_000_000))
            except Exception:
                continue
    return default_lamports


def parse_402_challenge(
    headers: Mapping[str, str],
    body: Union[bytes, str, Mapping[str, Any], None],
    fallback_used_pings: int = FREE_PINGS_LIMIT,
    expected_treasury: str = TREASURY_WALLET,
) -> X402Challenge:
    """Parse HTTP 402 headers (Payment-Required / X-Payment-Required) and JSON body."""
    hdr_b64 = _ci_header(headers, "payment-required") or _ci_header(headers, "x-payment-required")
    decoded_hdr = decode_base64_json(hdr_b64) if hdr_b64 else None

    body_obj: Dict[str, Any] = {}
    raw_body_parsed: Any = body
    if isinstance(body, (bytes, bytearray)):
        try:
            raw_body_parsed = json.loads(body.decode("utf-8", errors="replace"))
            if isinstance(raw_body_parsed, dict):
                body_obj = raw_body_parsed
        except Exception:
            raw_body_parsed = body.decode("utf-8", errors="replace")
    elif isinstance(body, str):
        try:
            raw_body_parsed = json.loads(body)
            if isinstance(raw_body_parsed, dict):
                body_obj = raw_body_parsed
        except Exception:
            raw_body_parsed = body
    elif isinstance(body, Mapping):
        body_obj = dict(body)
        raw_body_parsed = body_obj

    merged: Dict[str, Any] = {}
    if isinstance(decoded_hdr, dict):
        merged.update(decoded_hdr)
    merged.update(body_obj)

    accepts_list: List[Dict[str, Any]] = []
    for cand in (merged.get("accepts"), (decoded_hdr or {}).get("accepts"), body_obj.get("accepts")):
        if isinstance(cand, list) and cand:
            accepts_list = [dict(x) for x in cand if isinstance(x, Mapping)]
            break

    www_auth = _ci_header(headers, "www-authenticate")
    hdr_treasury = _ci_header(headers, "x-402-treasury")

    treasury = str(
        merged.get("treasury")
        or merged.get("payTo")
        or hdr_treasury
        or ""
    ).strip()
    if not treasury and www_auth:
        m = re.search(r'treasury="([^"]+)"', www_auth)
        if m:
            treasury = m.group(1).strip()
    if not treasury and accepts_list:
        for item in accepts_list:
            cand_t = item.get("payTo") or item.get("treasury") or item.get("recipient")
            if isinstance(cand_t, str) and cand_t.strip():
                treasury = cand_t.strip()
                break
    if not treasury:
        treasury = expected_treasury

    opt_a = X402Option(
        option=OPTION_A_PRO_PASS,
        lamports=OPTION_A_LAMPORTS,
        sol=OPTION_A_SOL,
        usd=OPTION_A_USD,
        pay_to=treasury,
        scheme=X402_SCHEME,
        network=X402_NETWORK,
        unlimited=True,
        description=str(X402_TIERS[OPTION_A_PRO_PASS]["description"]),
    )
    opt_b = X402Option(
        option=OPTION_B_SINGLE_SCAN,
        lamports=OPTION_B_LAMPORTS,
        sol=OPTION_B_SOL,
        usd=OPTION_B_USD,
        pay_to=treasury,
        scheme=X402_SCHEME,
        network=X402_NETWORK,
        unlimited=False,
        description=str(X402_TIERS[OPTION_B_SINGLE_SCAN]["description"]),
    )

    for entry in accepts_list:
        raw_opt = str(entry.get("option") or entry.get("id") or entry.get("tier") or "").strip().lower()
        lam = _extract_lamports(entry, 0)
        pay_to_entry = str(entry.get("payTo") or entry.get("treasury") or treasury).strip() or treasury
        desc_entry = str(entry.get("description") or "").strip()
        usd_val = entry.get("usd") or entry.get("priceUsd") or entry.get("price_usd")
        is_opt_a = (
            raw_opt in ("option_a_pro_pass", "option_a", "pro_pass", "unlimited")
            or lam == OPTION_A_LAMPORTS
        )
        is_opt_b = (
            raw_opt in ("option_b_single_scan", "option_b", "single_scan", "single")
            or lam == OPTION_B_LAMPORTS
        )
        if is_opt_a:
            eff_lam = lam if lam > 0 else OPTION_A_LAMPORTS
            opt_a = X402Option(
                option=OPTION_A_PRO_PASS,
                lamports=eff_lam,
                sol=round(eff_lam / 1_000_000_000, 9),
                usd=float(usd_val if usd_val is not None else OPTION_A_USD),
                pay_to=pay_to_entry,
                scheme=str(entry.get("scheme") or X402_SCHEME),
                network=str(entry.get("network") or X402_NETWORK),
                unlimited=True,
                description=desc_entry or opt_a.description,
            )
        elif is_opt_b:
            eff_lam = lam if lam > 0 else OPTION_B_LAMPORTS
            opt_b = X402Option(
                option=OPTION_B_SINGLE_SCAN,
                lamports=eff_lam,
                sol=round(eff_lam / 1_000_000_000, 9),
                usd=float(usd_val if usd_val is not None else OPTION_B_USD),
                pay_to=pay_to_entry,
                scheme=str(entry.get("scheme") or X402_SCHEME),
                network=str(entry.get("network") or X402_NETWORK),
                unlimited=False,
                description=desc_entry or opt_b.description,
            )

    if not accepts_list:
        accepts_list = [opt_a.to_dict(), opt_b.to_dict()]

    free_limit = int(merged.get("freePingsLimit") or merged.get("free_pings_limit") or FREE_PINGS_LIMIT)
    hdr_used = _ci_header(headers, "x-free-pings-used")
    hdr_rem = _ci_header(headers, "x-free-pings-remaining")
    used_pings = int(hdr_used) if (hdr_used is not None and hdr_used.isdigit()) else int(
        merged.get("freePingsUsed") or fallback_used_pings
    )
    rem_pings = int(hdr_rem) if (hdr_rem is not None and hdr_rem.isdigit()) else int(
        merged.get("freePingsRemaining") if merged.get("freePingsRemaining") is not None else 0
    )

    return X402Challenge(
        x402_version=int(merged.get("x402Version") or X402_VERSION),
        treasury=treasury,
        treasury_verified=(treasury == expected_treasury),
        free_pings_limit=free_limit,
        free_pings_used=used_pings,
        free_pings_remaining=rem_pings,
        option_a=opt_a,
        option_b=opt_b,
        accepts=accepts_list,
        www_authenticate=www_auth,
        raw_header=decoded_hdr,
        raw_body=raw_body_parsed,
    )


PaymentSignerCallback = Callable[..., Any]


def build_mock_signature_88(option_id: str, seed_bytes: bytes) -> str:
    """Build an 88-char valid Base58 mock signature per STRICT_CONTRACT_SPEC.json (5MockA.../5MockB...)."""
    prefix = "5MockB" if normalize_x402_option(option_id) == OPTION_B_SINGLE_SCAN else "5MockA"
    digest = hashlib.sha512(seed_bytes).digest() + hashlib.sha256(seed_bytes + b":tail").digest()
    encoded = b58encode(digest)
    while len(encoded) < 88:
        encoded += b58encode(hashlib.sha256(encoded.encode("ascii")).digest())
    return (prefix + encoded)[:88]


class X402AutoPayer:
    """Manages Solana keypair / mock signer / custom callback for x402 HTTP 402 auto-upgrade."""

    def __init__(
        self,
        agent_id: str,
        solana_private_key: Optional[Union[str, bytes, List[int]]] = None,
        solana_rpc_url: Optional[str] = None,
        x402_option: Optional[str] = None,
        mock_signer: Optional[bool] = None,
        payment_signer: Optional[PaymentSignerCallback] = None,
        expected_treasury: str = TREASURY_WALLET,
    ) -> None:
        self.agent_id = agent_id
        self.expected_treasury = expected_treasury
        self.payment_signer = payment_signer

        env_key = os.environ.get("SOLANA_PRIVATE_KEY") or os.environ.get("X402_SOLANA_PRIVATE_KEY")
        eff_secret = solana_private_key if solana_private_key is not None else env_key
        self.key_material: Optional[SolanaKeyMaterial] = (
            parse_solana_private_key(eff_secret) if eff_secret else None
        )

        env_mock = (os.environ.get("X402_MOCK_SIGNER") or "").strip().lower()
        self.mock_signer: bool = (
            bool(mock_signer)
            if mock_signer is not None
            else env_mock in ("1", "true", "yes", "on")
        )
        mock_seed = hashlib.sha256(b"solana-rug-shield-x402-mock-signer-v1").digest()
        mock_pub = ed25519_pubkey_from_seed(mock_seed)
        self._mock_key_material = SolanaKeyMaterial(
            seed32=mock_seed,
            pubkey32=mock_pub,
            pubkey_b58=b58encode(mock_pub),
        )

        self.solana_rpc_url: str = (
            solana_rpc_url
            or os.environ.get("X402_SOLANA_RPC_URL")
            or os.environ.get("SOLANA_RPC_URL")
            or DEFAULT_SOLANA_RPC_URL
        )
        self._explicit_rpc_override = bool(
            solana_rpc_url
            or os.environ.get("X402_SOLANA_RPC_URL")
            or os.environ.get("SOLANA_RPC_URL")
        )

        env_opt = os.environ.get("X402_OPTION") or os.environ.get("RENTSHIELD_X402_OPTION")
        self.selected_option: str = normalize_x402_option(x402_option or env_opt)
        self._nonce: int = 0
        self.payments_executed: int = 0
        self.last_payment_signature: Optional[str] = None

    @property
    def can_auto_pay(self) -> bool:
        return bool(self.payment_signer is not None or self.mock_signer or self.key_material is not None)

    def get_payer_pubkey(self) -> Optional[str]:
        if self.key_material is not None:
            return self.key_material.pubkey_b58
        if self.mock_signer:
            return self._mock_key_material.pubkey_b58
        return None

    def _validate_challenge_safety(self, option_id: str, challenge: X402Challenge) -> X402Option:
        if not challenge.treasury_verified or challenge.treasury != self.expected_treasury:
            raise ValueError(
                f"Refusing x402 auto-payment: challenge treasury {challenge.treasury!r} "
                f"does not match locked treasury {self.expected_treasury!r}."
            )
        opt = challenge.get_option(option_id)
        if opt.pay_to != self.expected_treasury:
            raise ValueError(
                f"Refusing x402 auto-payment: option {opt.option} payTo {opt.pay_to!r} "
                f"does not match {self.expected_treasury!r}."
            )
        expected_lamports = int(X402_TIERS[opt.option]["lamports"])
        if opt.lamports != expected_lamports:
            raise ValueError(
                f"Refusing x402 auto-payment: option {opt.option} requested {opt.lamports} lamports, "
                f"expected exact {expected_lamports} lamports."
            )
        return opt

    def _rpc_call_sync(self, method: str, params: List[Any], timeout: float = 8.0) -> Dict[str, Any]:
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
        req = urllib.request.Request(
            self.solana_rpc_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if isinstance(data, dict) and data.get("error"):
            raise RuntimeError(f"Solana RPC {method} error: {data['error']}")
        return data

    def _sign_and_send_rpc_sync(
        self, km: SolanaKeyMaterial, pay_to: str, lamports: int, timeout: float = 8.0
    ) -> str:
        bh_resp = self._rpc_call_sync("getLatestBlockhash", [{"commitment": "confirmed"}], timeout=timeout)
        res_val = ((bh_resp.get("result") or {}).get("value")) or (bh_resp.get("result") or {})
        blockhash = str(res_val.get("blockhash") or "").strip()
        if not blockhash:
            raise RuntimeError("Solana RPC getLatestBlockhash returned empty blockhash.")
        wire_tx, sig_b58 = build_solana_transfer_transaction(
            seed32=km.seed32,
            pubkey32=km.pubkey32,
            to_pubkey_b58=pay_to,
            lamports=lamports,
            recent_blockhash_b58=blockhash,
        )
        tx_b64 = base64.b64encode(wire_tx).decode("ascii")
        send_resp = self._rpc_call_sync(
            "sendTransaction",
            [tx_b64, {"encoding": "base64", "skipPreflight": False, "preflightCommitment": "confirmed"}],
            timeout=timeout,
        )
        rpc_sig = send_resp.get("result")
        return str(rpc_sig).strip() if isinstance(rpc_sig, str) and rpc_sig.strip() else sig_b58

    def _normalize_signer_result(self, result: Any) -> Tuple[str, str]:
        if isinstance(result, str):
            payer = self.get_payer_pubkey() or "custom_signer_wallet"
            return result.strip(), payer
        if isinstance(result, Mapping):
            sig = str(result.get("signature") or "").strip()
            payer = str(result.get("payer") or self.get_payer_pubkey() or "custom_signer_wallet").strip()
            if not sig:
                raise ValueError("payment_signer callback dict missing 'signature'.")
            return sig, payer
        raise TypeError("payment_signer must return signature str or {'signature': ..., 'payer': ...} dict.")

    def _invoke_custom_signer_raw(self, opt: X402Option, challenge: X402Challenge) -> Any:
        assert self.payment_signer is not None
        try:
            sig_info = inspect.signature(self.payment_signer)
            param_count = len(sig_info.parameters)
        except Exception:
            param_count = 2
        if param_count == 1:
            return self.payment_signer(
                {
                    "option": opt.option,
                    "lamports": opt.lamports,
                    "sol": opt.sol,
                    "payTo": opt.pay_to,
                    "challenge": challenge,
                }
            )
        return self.payment_signer(opt, challenge)

    def _create_mock_payment(self, opt: X402Option) -> Tuple[str, str]:
        km = self.key_material or self._mock_key_material
        if self._explicit_rpc_override and (
            "127.0.0.1" in self.solana_rpc_url or "localhost" in self.solana_rpc_url
        ):
            try:
                sig = self._sign_and_send_rpc_sync(km, opt.pay_to, opt.lamports, timeout=0.5)
                return sig, km.pubkey_b58
            except Exception:
                pass
        self._nonce += 1
        pseudo_bh = b58encode(
            hashlib.sha256(
                f"x402-mock-bh:{self.agent_id}:{opt.option}:{self._nonce}:{time.time_ns()}".encode("utf-8")
            ).digest()
        )
        wire_tx, _ = build_solana_transfer_transaction(
            seed32=km.seed32,
            pubkey32=km.pubkey32,
            to_pubkey_b58=opt.pay_to,
            lamports=opt.lamports,
            recent_blockhash_b58=pseudo_bh,
        )
        sig_88 = build_mock_signature_88(opt.option, wire_tx)
        return sig_88, km.pubkey_b58

    def execute_payment_sync(
        self, challenge: X402Challenge, option_override: Optional[str] = None
    ) -> Dict[str, Any]:
        option_id = normalize_x402_option(option_override or self.selected_option)
        opt = self._validate_challenge_safety(option_id, challenge)

        if self.payment_signer is not None:
            raw_res = self._invoke_custom_signer_raw(opt, challenge)
            if inspect.isawaitable(raw_res):
                raise RuntimeError(
                    "Async payment_signer callback cannot be used with synchronous RugShieldClient; "
                    "use AsyncRugShieldClient instead."
                )
            signature, payer = self._normalize_signer_result(raw_res)
        elif self.mock_signer:
            signature, payer = self._create_mock_payment(opt)
        elif self.key_material is not None:
            signature = self._sign_and_send_rpc_sync(self.key_material, opt.pay_to, opt.lamports)
            payer = self.key_material.pubkey_b58
        else:
            raise X402PaymentRequired(challenge)

        self.payments_executed += 1
        self.last_payment_signature = signature
        header_b64 = encode_x_payment_header(
            signature=signature,
            payer=payer,
            option=opt.option,
            lamports=opt.lamports,
            pay_to=opt.pay_to,
        )
        return {
            "signature": signature,
            "payer": payer,
            "option": opt.option,
            "lamports": opt.lamports,
            "sol": opt.sol,
            "payTo": opt.pay_to,
            "x_payment_header": header_b64,
        }

    async def execute_payment_async(
        self, challenge: X402Challenge, option_override: Optional[str] = None
    ) -> Dict[str, Any]:
        import asyncio

        option_id = normalize_x402_option(option_override or self.selected_option)
        opt = self._validate_challenge_safety(option_id, challenge)

        if self.payment_signer is not None:
            raw_res = self._invoke_custom_signer_raw(opt, challenge)
            if inspect.isawaitable(raw_res):
                raw_res = await raw_res
            signature, payer = self._normalize_signer_result(raw_res)
        elif self.mock_signer:
            signature, payer = await asyncio.to_thread(self._create_mock_payment, opt)
        elif self.key_material is not None:
            signature = await asyncio.to_thread(
                self._sign_and_send_rpc_sync, self.key_material, opt.pay_to, opt.lamports
            )
            payer = self.key_material.pubkey_b58
        else:
            raise X402PaymentRequired(challenge)

        self.payments_executed += 1
        self.last_payment_signature = signature
        header_b64 = encode_x_payment_header(
            signature=signature,
            payer=payer,
            option=opt.option,
            lamports=opt.lamports,
            pay_to=opt.pay_to,
        )
        return {
            "signature": signature,
            "payer": payer,
            "option": opt.option,
            "lamports": opt.lamports,
            "sol": opt.sol,
            "payTo": opt.pay_to,
            "x_payment_header": header_b64,
        }
