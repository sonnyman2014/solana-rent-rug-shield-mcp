#!/usr/bin/env python3
"""
Solana x402 HTTP 402 Payment Required Middleware & Gatekeeper
=============================================================
Production-ready, framework-agnostic Solana x402 payment gatekeeper with
first-class `aiohttp.web` middleware integration matching `rent_shield_app/server.py`,
plus ASGI and WSGI wrappers and deterministic offline/E2E mock RPC verification.

Treasury: 89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1
- Free Tier : 10 free pings per client (`X-Agent-Id` / API key / client IP)
- Option A  : `option_a_pro_pass` -> 0.026 SOL (26,000,000 lamports, $1.99 Unlimited Pro Pass)
              Issues HMAC-signed `X-Pro-Pass-Token` granting unlimited subsequent 200 OK calls.
- Option B  : `option_b_single_scan` -> 0.0003 SOL (300,000 lamports, ~$0.02 instant single scan)
              Grants 1 verified request per unique Solana transaction signature (strict anti-replay).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

# ---------------------------------------------------------------------------
# Canonical Solana x402 Contract Constants
# ---------------------------------------------------------------------------

X402_VERSION: int = 1
X402_SCHEME: str = "exact"
SOLANA_NETWORK: str = "solana:mainnet-beta"
ACCEPTED_SOLANA_NETWORKS: frozenset[str] = frozenset(
    {
        "solana:mainnet-beta",
        "solana-mainnet",
        "solana:mainnet",
        "solana",
        "mainnet-beta",
    }
)

TREASURY_WALLET: str = "89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1"
SYSTEM_PROGRAM_ID: str = "11111111111111111111111111111111"
LAMPORTS_PER_SOL: int = 1_000_000_000

FREE_PINGS_LIMIT: int = 10

OPTION_A_ID: str = "option_a_pro_pass"
OPTION_A_NAME: str = "$1.99 Unlimited Pro Pass"
OPTION_A_SOL: str = "0.026"
OPTION_A_SOL_FLOAT: float = 0.026
OPTION_A_LAMPORTS: int = 26_000_000
OPTION_A_USD: float = 1.99

OPTION_B_ID: str = "option_b_single_scan"
OPTION_B_NAME: str = "Instant Single Scan"
OPTION_B_SOL: str = "0.0003"
OPTION_B_SOL_FLOAT: float = 0.0003
OPTION_B_LAMPORTS: int = 300_000
OPTION_B_USD: float = 0.02

PRO_PASS_TOKEN_PREFIX: str = "x402pp_v1"
DEFAULT_MOCK_PAYER: str = "AgentPayer111111111111111111111111111111111"

DEFAULT_SOLANA_RPC_URLS: Tuple[str, ...] = (
    os.environ.get("SOLANA_RPC_URL") or "https://api.mainnet-beta.solana.com",
    "https://solana-rpc.publicnode.com",
)

# Canonical API & MCP gateway paths served by rent_shield_app/server.py
RENTSHIELD_PROTECTED_PATHS: Tuple[str, ...] = (
    "/api/v1/shield-check",
    "/api/audit",
    "/api/audit-mint",
    "/api/scan-mint",
    "/api/scan-token",
    "/api/scan-wallet",
    "/api/v1/scan-wallet",
    "/api/simulate-tx",
    "/api/v1/simulate-tx",
    "/api/simulate-tx-drain",
    "/api/v1/simulate-solana-tx-drain",
    "/api/v1/audit-solana-token-10-layer",
    "/api/v1/scan-wallet-unclaimed-sol",
    "/api/mcp",
    "/mcp",
)

DEFAULT_EXEMPT_PATHS: frozenset[str] = frozenset(
    {
        "/",
        "/index.html",
        "/card.html",
        "/app.html",
        "/moon_sphere.html",
        "/privacy",
        "/privacy.html",
        "/terms",
        "/terms.html",
        "/health",
        "/api/health",
        "/manifest.json",
        "/robots.txt",
        "/sitemap.xml",
        "/security.txt",
        "/.well-known/security.txt",
        "/favicon.ico",
        "/favicon.png",
        "/apple-touch-icon.png",
        "/sw.js",
    }
)

STATIC_EXEMPT_EXTENSIONS: Tuple[str, ...] = (
    ".html",
    ".png",
    ".svg",
    ".ico",
    ".js",
    ".css",
    ".zip",
    ".mobileconfig",
    ".xml",
    ".txt",
)

CORS_ALLOW_HEADERS: str = (
    "Content-Type, Accept, Authorization, X-API-Key, X-Requested-With, "
    "X-Agent-Id, X-Payment, Payment-Signature, X-Solana-Tx-Signature, "
    "X-Pro-Pass-Token, X-Payment-Option"
)

CORS_EXPOSE_HEADERS: str = (
    "WWW-Authenticate, Payment-Required, X-Payment-Required, X-402-Treasury, "
    "X-Free-Pings-Limit, X-Free-Pings-Used, X-Free-Pings-Remaining, "
    "X-Pro-Pass-Token, X-Pro-Pass-Active, X-Payment-Verified, "
    "X-Payment-Option, X-Payment-Tx-Signature, Payment-Response, "
    "X-Payment-Response, X-Payment-Error"
)


# ---------------------------------------------------------------------------
# JSON / Base64 Helpers & Atomic Persistence
# ---------------------------------------------------------------------------


def encode_base64_json(payload: Mapping[str, Any]) -> str:
    """Encode a mapping as compact UTF-8 JSON wrapped in standard Base64."""
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def decode_base64_json(encoded: str) -> Dict[str, Any]:
    """Decode standard Base64, URL-safe Base64 (with optional missing padding), or raw JSON."""
    text = (encoded or "").strip()
    if not text:
        raise ValueError("Empty payment payload")
    if text.startswith("{"):
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise ValueError("Decoded JSON payment payload must be an object")
        return parsed

    normalized = text.replace("-", "+").replace("_", "/")
    rem = len(normalized) % 4
    if rem:
        normalized += "=" * (4 - rem)
    raw = base64.b64decode(normalized.encode("ascii"), validate=False)
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("Decoded base64 payment payload must be a JSON object")
    return parsed


def _encode_b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode_b64url_nopad(text: str) -> bytes:
    padded = text + ("=" * ((4 - (len(text) % 4)) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _atomic_load_json(path: Optional[str], default: Any) -> Any:
    if not path or not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return default


def _atomic_save_json(path: Optional[str], data: Any) -> None:
    if not path:
        return
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp_path = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    os.replace(tmp_path, path)


def _get_header_case_insensitive(headers: Mapping[str, Any], name: str) -> str:
    direct = headers.get(name)
    if direct is not None:
        return str(direct).strip()
    lower = name.lower()
    for k, v in headers.items():
        if str(k).lower() == lower and v is not None:
            return str(v).strip()
    return ""


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParsedPaymentCredentials:
    """Normalized incoming payment credentials extracted from HTTP headers/query/body."""

    has_credentials: bool = False
    pro_pass_token: str = ""
    signature: str = ""
    payer: str = ""
    option: str = ""
    claimed_lamports: Optional[int] = None
    pay_to: str = ""
    network: str = ""
    scheme: str = ""
    x402_version: Optional[int] = None
    source_header: str = ""
    parse_error: str = ""


@dataclass(frozen=True)
class PaymentVerificationResult:
    """Outcome of Solana transaction or Pro Pass verification."""

    verified: bool
    option: str = ""
    signature: str = ""
    payer: str = ""
    treasury: str = TREASURY_WALLET
    paid_lamports: int = 0
    required_lamports: int = 0
    error_code: str = ""
    reason: str = ""
    pro_pass_token: str = ""
    slot: Optional[int] = None


@dataclass
class GatekeeperDecision:
    """Framework-agnostic HTTP gatekeeping decision produced by X402SolanaGatekeeper."""

    allowed: bool
    status_code: int = 200
    client_id: str = ""
    auth_mode: str = "exempt"  # exempt | free_ping | option_b_single_scan | option_a_pro_pass | pro_pass_token | rejected
    payment_verified: bool = False
    option: str = ""
    signature: str = ""
    payer: str = ""
    paid_lamports: int = 0
    pro_pass_token: str = ""
    free_pings_limit: int = FREE_PINGS_LIMIT
    free_pings_used: int = 0
    free_pings_remaining: int = FREE_PINGS_LIMIT
    error_code: str = ""
    error_message: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Challenge & Header Builders
# ---------------------------------------------------------------------------


def build_www_authenticate_header(
    *,
    network: str = SOLANA_NETWORK,
    treasury: str = TREASURY_WALLET,
    option_a_sol: str = OPTION_A_SOL,
    option_b_sol: str = OPTION_B_SOL,
) -> str:
    return (
        f'x402 network="{network}", '
        f'treasury="{treasury}", '
        f'option_a_sol="{option_a_sol}", '
        f'option_b_sol="{option_b_sol}"'
    )


def build_x402_challenge(
    *,
    resource: str = "/api/v1/shield-check",
    treasury: str = TREASURY_WALLET,
    network: str = SOLANA_NETWORK,
    free_pings_limit: int = FREE_PINGS_LIMIT,
    free_pings_used: int = FREE_PINGS_LIMIT,
    free_pings_remaining: int = 0,
    error_code: str = "PAYMENT_REQUIRED",
    error_message: str = "",
) -> Dict[str, Any]:
    msg = error_message or (
        f"Payment Required: {free_pings_limit} free pings exhausted. "
        f"Upgrade via Solana x402 Option A ({OPTION_A_SOL} SOL / $1.99 Unlimited Pro Pass) "
        f"or Option B ({OPTION_B_SOL} SOL / ~$0.02 single scan) to {treasury}."
    )
    accepts = [
        {
            "scheme": X402_SCHEME,
            "network": network,
            "networkId": SOLANA_NETWORK,
            "option": OPTION_A_ID,
            "id": OPTION_A_ID,
            "maxAmountRequired": str(OPTION_A_LAMPORTS),
            "lamports": OPTION_A_LAMPORTS,
            "amountSol": OPTION_A_SOL_FLOAT,
            "sol": OPTION_A_SOL_FLOAT,
            "solStr": OPTION_A_SOL,
            "priceUsd": OPTION_A_USD,
            "payTo": treasury,
            "treasury": treasury,
            "asset": "SOL",
            "resource": resource,
            "description": f"{OPTION_A_NAME} ({OPTION_A_SOL} SOL) issuing X-Pro-Pass-Token for unlimited 200 OK calls",
            "mimeType": "application/json",
            "maxTimeoutSeconds": 300,
            "extra": {
                "option": OPTION_A_ID,
                "name": OPTION_A_NAME,
                "lamports": OPTION_A_LAMPORTS,
                "sol": OPTION_A_SOL,
                "priceUsd": OPTION_A_USD,
                "unlimited": True,
                "issuesHeader": "X-Pro-Pass-Token",
            },
        },
        {
            "scheme": X402_SCHEME,
            "network": network,
            "networkId": SOLANA_NETWORK,
            "option": OPTION_B_ID,
            "id": OPTION_B_ID,
            "maxAmountRequired": str(OPTION_B_LAMPORTS),
            "lamports": OPTION_B_LAMPORTS,
            "amountSol": OPTION_B_SOL_FLOAT,
            "sol": OPTION_B_SOL_FLOAT,
            "solStr": OPTION_B_SOL,
            "priceUsd": OPTION_B_USD,
            "payTo": treasury,
            "treasury": treasury,
            "asset": "SOL",
            "resource": resource,
            "description": f"{OPTION_B_NAME} ({OPTION_B_SOL} SOL / ~$0.02) granting 1 verified scan",
            "mimeType": "application/json",
            "maxTimeoutSeconds": 300,
            "extra": {
                "option": OPTION_B_ID,
                "name": OPTION_B_NAME,
                "lamports": OPTION_B_LAMPORTS,
                "sol": OPTION_B_SOL,
                "priceUsd": OPTION_B_USD,
                "unlimited": False,
                "requestsGranted": 1,
            },
        },
    ]
    return {
        "ok": False,
        "status": 402,
        "error": msg,
        "error_code": error_code,
        "code": error_code,
        "verified_onchain": False,
        "x402Version": X402_VERSION,
        "scheme": X402_SCHEME,
        "network": network,
        "treasury": treasury,
        "freePingsLimit": free_pings_limit,
        "freePingsUsed": free_pings_used,
        "freePingsRemaining": free_pings_remaining,
        "options": {
            OPTION_A_ID: {
                "id": OPTION_A_ID,
                "option": OPTION_A_ID,
                "name": OPTION_A_NAME,
                "sol": OPTION_A_SOL,
                "amountSol": OPTION_A_SOL_FLOAT,
                "lamports": OPTION_A_LAMPORTS,
                "maxAmountRequired": str(OPTION_A_LAMPORTS),
                "priceUsd": OPTION_A_USD,
                "payTo": treasury,
                "treasury": treasury,
                "network": network,
                "unlimited": True,
                "issuesHeader": "X-Pro-Pass-Token",
            },
            OPTION_B_ID: {
                "id": OPTION_B_ID,
                "option": OPTION_B_ID,
                "name": OPTION_B_NAME,
                "sol": OPTION_B_SOL,
                "amountSol": OPTION_B_SOL_FLOAT,
                "lamports": OPTION_B_LAMPORTS,
                "maxAmountRequired": str(OPTION_B_LAMPORTS),
                "priceUsd": OPTION_B_USD,
                "payTo": treasury,
                "treasury": treasury,
                "network": network,
                "unlimited": False,
                "requestsGranted": 1,
            },
        },
        "accepts": accepts,
    }


def parse_payment_headers(
    headers: Mapping[str, Any],
    *,
    query: Optional[Mapping[str, Any]] = None,
    body: Optional[Mapping[str, Any]] = None,
) -> ParsedPaymentCredentials:
    """
    Extract payment credentials from HTTP headers (and optional query/body fallbacks):
    - `X-Pro-Pass-Token` (or `Authorization: ProPass <tok>` / `Bearer x402pp_v1...`)
    - `X-Payment` (base64 JSON `{x402Version, scheme, network, payload:{signature, payer, option, lamports, payTo}}`)
    - `Payment-Signature` (base64 JSON x402 payload or raw tx signature)
    - `X-Solana-Tx-Signature` (raw base58 Solana transaction signature)
    """
    query = query or {}
    body = body if isinstance(body, Mapping) else {}

    # 1. Check Pro Pass Token first
    pro_token = _get_header_case_insensitive(headers, "X-Pro-Pass-Token")
    source_hdr = "X-Pro-Pass-Token" if pro_token else ""
    if not pro_token:
        auth_hdr = _get_header_case_insensitive(headers, "Authorization")
        if auth_hdr.lower().startswith("propass "):
            pro_token = auth_hdr[8:].strip()
            source_hdr = "Authorization"
        elif auth_hdr.lower().startswith("bearer ") and auth_hdr[7:].strip().startswith(f"{PRO_PASS_TOKEN_PREFIX}."):
            pro_token = auth_hdr[7:].strip()
            source_hdr = "Authorization"
    if not pro_token:
        q_tok = str(query.get("pro_pass_token") or body.get("pro_pass_token") or "").strip()
        if q_tok:
            pro_token = q_tok
            source_hdr = "pro_pass_token"

    if pro_token:
        return ParsedPaymentCredentials(
            has_credentials=True,
            pro_pass_token=pro_token,
            option=OPTION_A_ID,
            source_header=source_hdr,
        )

    # 2. Check structured `X-Payment` or `Payment-Signature` headers
    for hdr_name in ("X-Payment", "Payment-Signature"):
        raw_val = _get_header_case_insensitive(headers, hdr_name)
        if not raw_val:
            continue
        try:
            decoded = decode_base64_json(raw_val)
        except Exception as exc:
            # Allow `Payment-Signature` to carry a direct base58 signature if not JSON/base64-JSON
            if hdr_name == "Payment-Signature" and not raw_val.startswith("{") and len(raw_val) >= 32 and " " not in raw_val:
                tx_opt = _get_header_case_insensitive(headers, "X-Payment-Option")
                return ParsedPaymentCredentials(
                    has_credentials=True,
                    signature=raw_val,
                    option=tx_opt,
                    source_header=hdr_name,
                )
            return ParsedPaymentCredentials(
                has_credentials=True,
                source_header=hdr_name,
                parse_error=f"Malformed {hdr_name} base64 JSON payload: {exc}",
            )

        payload_obj = decoded.get("payload")
        if not isinstance(payload_obj, Mapping):
            payload_obj = decoded

        sig = str(
            payload_obj.get("signature")
            or payload_obj.get("txSignature")
            or payload_obj.get("tx_signature")
            or decoded.get("signature")
            or ""
        ).strip()
        payer = str(
            payload_obj.get("payer")
            or payload_obj.get("wallet")
            or payload_obj.get("from")
            or decoded.get("payer")
            or ""
        ).strip()
        option = str(
            payload_obj.get("option")
            or payload_obj.get("optionId")
            or payload_obj.get("tier")
            or decoded.get("option")
            or _get_header_case_insensitive(headers, "X-Payment-Option")
            or ""
        ).strip()
        pay_to = str(
            payload_obj.get("payTo")
            or payload_obj.get("treasury")
            or payload_obj.get("recipient")
            or decoded.get("payTo")
            or decoded.get("treasury")
            or ""
        ).strip()
        network = str(decoded.get("network") or payload_obj.get("network") or "").strip()
        scheme = str(decoded.get("scheme") or payload_obj.get("scheme") or "").strip()

        raw_ver = decoded.get("x402Version")
        ver_int: Optional[int] = None
        if raw_ver is not None:
            try:
                ver_int = int(raw_ver)
            except (TypeError, ValueError):
                return ParsedPaymentCredentials(
                    has_credentials=True,
                    source_header=hdr_name,
                    parse_error=f"Invalid x402Version in {hdr_name}: {raw_ver!r}",
                )

        raw_lamports = (
            payload_obj.get("lamports")
            if payload_obj.get("lamports") is not None
            else (payload_obj.get("amount") if payload_obj.get("amount") is not None else decoded.get("lamports"))
        )
        lamports_int: Optional[int] = None
        if raw_lamports is not None:
            try:
                lamports_int = int(raw_lamports)
            except (TypeError, ValueError):
                return ParsedPaymentCredentials(
                    has_credentials=True,
                    source_header=hdr_name,
                    parse_error=f"Invalid lamports value in {hdr_name}: {raw_lamports!r}",
                )

        if not sig:
            return ParsedPaymentCredentials(
                has_credentials=True,
                source_header=hdr_name,
                parse_error=f"Missing Solana transaction signature in {hdr_name} payload",
            )

        return ParsedPaymentCredentials(
            has_credentials=True,
            signature=sig,
            payer=payer,
            option=option,
            claimed_lamports=lamports_int,
            pay_to=pay_to,
            network=network,
            scheme=scheme,
            x402_version=ver_int,
            source_header=hdr_name,
        )

    # 3. Check `X-Solana-Tx-Signature` (and optional `payment_signature` query/body fallback)
    raw_sig = _get_header_case_insensitive(headers, "X-Solana-Tx-Signature")
    sig_source = "X-Solana-Tx-Signature" if raw_sig else ""
    if not raw_sig:
        fallback_sig = str(query.get("payment_signature") or body.get("payment_signature") or "").strip()
        if fallback_sig:
            raw_sig = fallback_sig
            sig_source = "payment_signature"

    if raw_sig:
        return ParsedPaymentCredentials(
            has_credentials=True,
            signature=raw_sig,
            payer=_get_header_case_insensitive(headers, "X-Payer-Wallet") or str(body.get("wallet") or "").strip(),
            option=_get_header_case_insensitive(headers, "X-Payment-Option") or str(body.get("payment_option") or "").strip(),
            source_header=sig_source,
        )

    return ParsedPaymentCredentials(has_credentials=False)


# ---------------------------------------------------------------------------
# Stateful Components: Anti-Replay Ledger, Pro-Pass Tokens & Free Ping Quota
# ---------------------------------------------------------------------------


class SignatureReplayLedger:
    """Thread-safe anti-replay ledger ensuring each Solana tx signature is redeemed at most once."""

    def __init__(self, store_path: Optional[str] = None) -> None:
        self.store_path = store_path
        self._lock = threading.RLock()
        loaded = _atomic_load_json(store_path, {})
        self._used: Dict[str, Dict[str, Any]] = loaded if isinstance(loaded, dict) else {}

    def is_used(self, signature: str) -> bool:
        sig = (signature or "").strip()
        with self._lock:
            return sig in self._used

    def get_record(self, signature: str) -> Optional[Dict[str, Any]]:
        sig = (signature or "").strip()
        with self._lock:
            rec = self._used.get(sig)
            return dict(rec) if isinstance(rec, dict) else None

    def try_consume(self, signature: str, metadata: Mapping[str, Any]) -> bool:
        """Atomically record signature if unused; returns False if already consumed."""
        sig = (signature or "").strip()
        if not sig:
            return False
        with self._lock:
            if sig in self._used:
                return False
            entry = dict(metadata)
            entry.setdefault("redeemed_at", int(time.time()))
            self._used[sig] = entry
            _atomic_save_json(self.store_path, self._used)
            return True

    def count(self) -> int:
        with self._lock:
            return len(self._used)


class ProPassTokenManager:
    """
    Issues and verifies HMAC-SHA256 signed `X-Pro-Pass-Token` credentials for Option A
    (0.026 SOL / $1.99 Unlimited Pro Pass), with optional persistent JSON backing store.
    """

    def __init__(
        self,
        secret_key: Optional[str] = None,
        *,
        store_path: Optional[str] = None,
        treasury: str = TREASURY_WALLET,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        env_secret = os.environ.get("X402_PRO_PASS_SECRET")
        resolved_secret = secret_key or env_secret or secrets.token_hex(32)
        self._secret_bytes = resolved_secret.encode("utf-8")
        self.store_path = store_path
        self.treasury = treasury
        self.ttl_seconds = ttl_seconds
        self._lock = threading.RLock()
        loaded = _atomic_load_json(store_path, {"tokens": {}})
        self._store: Dict[str, Any] = loaded if isinstance(loaded, dict) and isinstance(loaded.get("tokens"), dict) else {"tokens": {}}

    def _sign_segment(self, payload_segment: str) -> str:
        msg = f"{PRO_PASS_TOKEN_PREFIX}.{payload_segment}".encode("ascii")
        return hmac.new(self._secret_bytes, msg, hashlib.sha256).hexdigest()

    def issue_token(
        self,
        *,
        signature: str,
        payer: str = "",
        client_id: str = "",
        paid_lamports: int = OPTION_A_LAMPORTS,
    ) -> str:
        now = int(time.time())
        jti = secrets.token_hex(8)
        exp = (now + int(self.ttl_seconds)) if self.ttl_seconds is not None else None
        claims = {
            "v": 1,
            "jti": jti,
            "tier": OPTION_A_ID,
            "sub": payer or client_id or "solana-agent",
            "sig": signature,
            "lamports": int(paid_lamports),
            "treasury": self.treasury,
            "iat": now,
            "exp": exp,
        }
        payload_seg = _encode_b64url_nopad(
            json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        mac_hex = self._sign_segment(payload_seg)
        token = f"{PRO_PASS_TOKEN_PREFIX}.{payload_seg}.{mac_hex}"

        with self._lock:
            self._store["tokens"][jti] = {
                "jti": jti,
                "payer": claims["sub"],
                "tx_signature": signature,
                "paid_lamports": int(paid_lamports),
                "issued_at": now,
                "expires_at": exp,
                "revoked": False,
            }
            _atomic_save_json(self.store_path, self._store)

        return token

    def revoke_jti(self, jti: str) -> bool:
        with self._lock:
            rec = self._store["tokens"].get(jti)
            if isinstance(rec, dict):
                rec["revoked"] = True
                _atomic_save_json(self.store_path, self._store)
                return True
            return False

    def verify_token(self, token: str) -> PaymentVerificationResult:
        raw = (token or "").strip()
        parts = raw.split(".")
        if len(parts) != 3 or parts[0] != PRO_PASS_TOKEN_PREFIX:
            return PaymentVerificationResult(
                verified=False,
                option=OPTION_A_ID,
                treasury=self.treasury,
                required_lamports=OPTION_A_LAMPORTS,
                error_code="INVALID_PRO_PASS_TOKEN",
                reason="Malformed X-Pro-Pass-Token format",
            )

        _, payload_seg, provided_mac = parts
        expected_mac = self._sign_segment(payload_seg)
        if not hmac.compare_digest(expected_mac, provided_mac):
            return PaymentVerificationResult(
                verified=False,
                option=OPTION_A_ID,
                treasury=self.treasury,
                required_lamports=OPTION_A_LAMPORTS,
                error_code="INVALID_PRO_PASS_TOKEN",
                reason="Invalid X-Pro-Pass-Token HMAC signature",
            )

        try:
            claims = json.loads(_decode_b64url_nopad(payload_seg).decode("utf-8"))
        except Exception:
            return PaymentVerificationResult(
                verified=False,
                option=OPTION_A_ID,
                treasury=self.treasury,
                required_lamports=OPTION_A_LAMPORTS,
                error_code="INVALID_PRO_PASS_TOKEN",
                reason="Corrupted X-Pro-Pass-Token claims payload",
            )

        if not isinstance(claims, dict) or claims.get("tier") != OPTION_A_ID:
            return PaymentVerificationResult(
                verified=False,
                option=OPTION_A_ID,
                treasury=self.treasury,
                required_lamports=OPTION_A_LAMPORTS,
                error_code="INVALID_PRO_PASS_TOKEN",
                reason="Unsupported X-Pro-Pass-Token tier",
            )

        if claims.get("treasury") != self.treasury:
            return PaymentVerificationResult(
                verified=False,
                option=OPTION_A_ID,
                treasury=self.treasury,
                required_lamports=OPTION_A_LAMPORTS,
                error_code="INVALID_PRO_PASS_TOKEN",
                reason="X-Pro-Pass-Token treasury mismatch",
            )

        paid_lamports = int(claims.get("lamports") or 0)
        if paid_lamports < OPTION_A_LAMPORTS:
            return PaymentVerificationResult(
                verified=False,
                option=OPTION_A_ID,
                treasury=self.treasury,
                paid_lamports=paid_lamports,
                required_lamports=OPTION_A_LAMPORTS,
                error_code="INVALID_PRO_PASS_TOKEN",
                reason="X-Pro-Pass-Token lamports below Option A threshold",
            )

        exp = claims.get("exp")
        if exp is not None and int(time.time()) > int(exp):
            return PaymentVerificationResult(
                verified=False,
                option=OPTION_A_ID,
                treasury=self.treasury,
                paid_lamports=paid_lamports,
                required_lamports=OPTION_A_LAMPORTS,
                error_code="EXPIRED_PRO_PASS_TOKEN",
                reason="X-Pro-Pass-Token has expired",
            )

        jti = str(claims.get("jti") or "")
        if jti:
            with self._lock:
                stored = self._store["tokens"].get(jti)
                if isinstance(stored, dict) and stored.get("revoked") is True:
                    return PaymentVerificationResult(
                        verified=False,
                        option=OPTION_A_ID,
                        treasury=self.treasury,
                        paid_lamports=paid_lamports,
                        required_lamports=OPTION_A_LAMPORTS,
                        error_code="REVOKED_PRO_PASS_TOKEN",
                        reason="X-Pro-Pass-Token has been revoked",
                    )

        return PaymentVerificationResult(
            verified=True,
            option=OPTION_A_ID,
            signature=str(claims.get("sig") or ""),
            payer=str(claims.get("sub") or ""),
            treasury=self.treasury,
            paid_lamports=paid_lamports,
            required_lamports=OPTION_A_LAMPORTS,
            pro_pass_token=raw,
        )


class FreePingTracker:
    """Tracks the 10 free pings per client (`X-Agent-Id`, API key, or client IP)."""

    def __init__(self, limit: int = FREE_PINGS_LIMIT, *, store_path: Optional[str] = None) -> None:
        self.limit = max(0, int(limit))
        self.store_path = store_path
        self._lock = threading.RLock()
        loaded = _atomic_load_json(store_path, {})
        self._counts: Dict[str, int] = (
            {str(k): int(v) for k, v in loaded.items() if isinstance(v, (int, float))}
            if isinstance(loaded, dict)
            else {}
        )

    def get_usage(self, client_id: str) -> Tuple[int, int]:
        cid = client_id or "ip:127.0.0.1"
        with self._lock:
            used = int(self._counts.get(cid, 0))
            remaining = max(0, self.limit - used)
            return used, remaining

    def try_consume_ping(self, client_id: str) -> Tuple[bool, int, int]:
        """
        Attempt to consume 1 free ping for `client_id`.
        Returns `(allowed, used_count, remaining_count)`.
        """
        cid = client_id or "ip:127.0.0.1"
        with self._lock:
            used = int(self._counts.get(cid, 0))
            if used >= self.limit:
                return False, used, 0
            used += 1
            self._counts[cid] = used
            remaining = max(0, self.limit - used)
            _atomic_save_json(self.store_path, self._counts)
            return True, used, remaining

    def reset(self, client_id: Optional[str] = None) -> None:
        with self._lock:
            if client_id is None:
                self._counts.clear()
            else:
                self._counts.pop(client_id, None)
            _atomic_save_json(self.store_path, self._counts)


# ---------------------------------------------------------------------------
# Pluggable Solana JSON-RPC Transaction Verifier + Deterministic Offline Mock
# ---------------------------------------------------------------------------


class SolanaRpcVerifier:
    """
    Verifies on-chain Solana `x402` SOL transfers via JSON-RPC `getTransaction`:
    1. Confirms `result` exists and `meta.err is None`.
    2. Confirms `accountKeys` (including v0 `loadedAddresses`) contains `treasury`
       (`89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1`).
    3. Computes exact treasury balance delta `postBalances[idx] - preBalances[idx]`
       and verifies `delta >= required_lamports` (`26,000,000` for Option A or
       `300,000` for Option B).
    """

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        *,
        failover_urls: Optional[Sequence[str]] = None,
        treasury: str = TREASURY_WALLET,
        commitment: str = "confirmed",
        timeout_seconds: float = 6.0,
        rpc_transport: Optional[Callable[[str, Dict[str, Any], float], Dict[str, Any]]] = None,
    ) -> None:
        primary = rpc_url or os.environ.get("SOLANA_RPC_URL") or DEFAULT_SOLANA_RPC_URLS[0]
        urls = [primary]
        for extra in failover_urls or DEFAULT_SOLANA_RPC_URLS[1:]:
            if extra and extra not in urls:
                urls.append(extra)
        self.rpc_urls: Tuple[str, ...] = tuple(urls)
        self.treasury = treasury
        self.commitment = commitment
        self.timeout_seconds = float(timeout_seconds)
        self._rpc_transport = rpc_transport or self._default_http_rpc_transport

    @staticmethod
    def _default_http_rpc_transport(url: str, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]:
        raw = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=raw,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "RentAndRugShield-x402-Verifier/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(body)
            return parsed if isinstance(parsed, dict) else {}

    def fetch_transaction_sync(
        self,
        signature: str,
        *,
        claim_hint: Optional[Mapping[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        rpc_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [
                signature,
                {
                    "encoding": "jsonParsed",
                    "commitment": self.commitment,
                    "maxSupportedTransactionVersion": 0,
                },
            ],
        }
        last_err: Optional[Exception] = None
        for url in self.rpc_urls:
            try:
                response = self._rpc_transport(url, rpc_payload, self.timeout_seconds)
                if isinstance(response, dict):
                    if "error" in response and response["error"]:
                        continue
                    res = response.get("result")
                    if isinstance(res, dict):
                        return res
                    if res is None and "result" in response:
                        return None
            except Exception as exc:
                last_err = exc
                continue
        if last_err is not None:
            raise RuntimeError(f"Solana RPC getTransaction failed: {last_err}") from last_err
        return None

    async def fetch_transaction_async(
        self,
        signature: str,
        *,
        claim_hint: Optional[Mapping[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        return await asyncio.to_thread(self.fetch_transaction_sync, signature, claim_hint=claim_hint)

    def verify_transaction_data(
        self,
        signature: str,
        tx_result: Optional[Mapping[str, Any]],
        *,
        requested_option: str = "",
        expected_treasury: Optional[str] = None,
    ) -> PaymentVerificationResult:
        target_treasury = expected_treasury or self.treasury
        norm_opt = (requested_option or "").strip().lower()
        if norm_opt in ("option_a", "pro_pass", "pro", OPTION_A_ID.lower()):
            req_option = OPTION_A_ID
            min_required = OPTION_A_LAMPORTS
        elif norm_opt in ("option_b", "single_scan", "single", OPTION_B_ID.lower()):
            req_option = OPTION_B_ID
            min_required = OPTION_B_LAMPORTS
        elif norm_opt == "":
            req_option = ""
            min_required = OPTION_B_LAMPORTS
        else:
            return PaymentVerificationResult(
                verified=False,
                signature=signature,
                treasury=target_treasury,
                required_lamports=OPTION_B_LAMPORTS,
                error_code="INVALID_PAYMENT_OPTION",
                reason=f"Unsupported x402 payment option: {requested_option!r}",
            )

        if not isinstance(tx_result, Mapping):
            return PaymentVerificationResult(
                verified=False,
                option=req_option,
                signature=signature,
                treasury=target_treasury,
                required_lamports=min_required,
                error_code="TX_NOT_FOUND",
                reason=f"Transaction {signature} not found or not confirmed on Solana",
            )

        meta = tx_result.get("meta")
        if not isinstance(meta, Mapping):
            return PaymentVerificationResult(
                verified=False,
                option=req_option,
                signature=signature,
                treasury=target_treasury,
                required_lamports=min_required,
                error_code="INVALID_TX_META",
                reason="Transaction metadata missing from Solana RPC response",
            )

        if meta.get("err") is not None:
            return PaymentVerificationResult(
                verified=False,
                option=req_option,
                signature=signature,
                treasury=target_treasury,
                required_lamports=min_required,
                error_code="TX_FAILED_ONCHAIN",
                reason=f"Transaction failed on-chain (meta.err={meta.get('err')!r})",
            )

        tx_obj = tx_result.get("transaction")
        msg_obj = tx_obj.get("message") if isinstance(tx_obj, Mapping) else {}
        if not isinstance(msg_obj, Mapping):
            msg_obj = {}

        raw_account_keys: List[Any] = list(msg_obj.get("accountKeys") or [])
        loaded = meta.get("loadedAddresses")
        if isinstance(loaded, Mapping):
            raw_account_keys.extend(loaded.get("writable") or [])
            raw_account_keys.extend(loaded.get("readonly") or [])

        normalized_keys: List[Tuple[str, bool]] = []
        for idx, entry in enumerate(raw_account_keys):
            if isinstance(entry, Mapping):
                pk = str(entry.get("pubkey") or "").strip()
                is_signer = bool(entry.get("signer", idx == 0))
            else:
                pk = str(entry or "").strip()
                is_signer = idx == 0
            normalized_keys.append((pk, is_signer))

        treasury_indices = [idx for idx, (pk, _) in enumerate(normalized_keys) if pk == target_treasury]
        if not treasury_indices:
            return PaymentVerificationResult(
                verified=False,
                option=req_option,
                signature=signature,
                treasury=target_treasury,
                required_lamports=min_required,
                error_code="WRONG_RECIPIENT",
                reason=f"Treasury {target_treasury} not present in transaction accountKeys",
            )

        pre_balances = list(meta.get("preBalances") or [])
        post_balances = list(meta.get("postBalances") or [])
        treasury_delta = 0
        for idx in treasury_indices:
            if idx < len(pre_balances) and idx < len(post_balances):
                treasury_delta += int(post_balances[idx]) - int(pre_balances[idx])

        payer_pubkey = ""
        for pk, is_signer in normalized_keys:
            if is_signer and pk and pk != target_treasury:
                payer_pubkey = pk
                break
        if not payer_pubkey and normalized_keys:
            payer_pubkey = normalized_keys[0][0]

        if treasury_delta <= 0:
            return PaymentVerificationResult(
                verified=False,
                option=req_option,
                signature=signature,
                payer=payer_pubkey,
                treasury=target_treasury,
                paid_lamports=max(0, treasury_delta),
                required_lamports=min_required,
                error_code="WRONG_RECIPIENT",
                reason=(
                    f"No positive lamport transfer received by treasury {target_treasury} "
                    f"(delta={treasury_delta} lamports)"
                ),
            )

        if req_option == OPTION_A_ID:
            if treasury_delta < OPTION_A_LAMPORTS:
                return PaymentVerificationResult(
                    verified=False,
                    option=OPTION_A_ID,
                    signature=signature,
                    payer=payer_pubkey,
                    treasury=target_treasury,
                    paid_lamports=treasury_delta,
                    required_lamports=OPTION_A_LAMPORTS,
                    error_code="UNDERPAYMENT",
                    reason=(
                        f"Underpayment for Option A Pro Pass: received {treasury_delta} lamports "
                        f"({treasury_delta / LAMPORTS_PER_SOL:.6f} SOL), required >= {OPTION_A_LAMPORTS} lamports ({OPTION_A_SOL} SOL)"
                    ),
                )
            resolved_option = OPTION_A_ID
            resolved_required = OPTION_A_LAMPORTS
        elif req_option == OPTION_B_ID:
            if treasury_delta < OPTION_B_LAMPORTS:
                return PaymentVerificationResult(
                    verified=False,
                    option=OPTION_B_ID,
                    signature=signature,
                    payer=payer_pubkey,
                    treasury=target_treasury,
                    paid_lamports=treasury_delta,
                    required_lamports=OPTION_B_LAMPORTS,
                    error_code="UNDERPAYMENT",
                    reason=(
                        f"Underpayment for Option B Single Scan: received {treasury_delta} lamports "
                        f"({treasury_delta / LAMPORTS_PER_SOL:.6f} SOL), required >= {OPTION_B_LAMPORTS} lamports ({OPTION_B_SOL} SOL)"
                    ),
                )
            resolved_option = OPTION_B_ID
            resolved_required = OPTION_B_LAMPORTS
        else:
            if treasury_delta >= OPTION_A_LAMPORTS:
                resolved_option = OPTION_A_ID
                resolved_required = OPTION_A_LAMPORTS
            elif treasury_delta >= OPTION_B_LAMPORTS:
                resolved_option = OPTION_B_ID
                resolved_required = OPTION_B_LAMPORTS
            else:
                return PaymentVerificationResult(
                    verified=False,
                    option=OPTION_B_ID,
                    signature=signature,
                    payer=payer_pubkey,
                    treasury=target_treasury,
                    paid_lamports=treasury_delta,
                    required_lamports=OPTION_B_LAMPORTS,
                    error_code="UNDERPAYMENT",
                    reason=(
                        f"Underpayment: received {treasury_delta} lamports "
                        f"({treasury_delta / LAMPORTS_PER_SOL:.6f} SOL), minimum required is "
                        f"{OPTION_B_LAMPORTS} lamports ({OPTION_B_SOL} SOL)"
                    ),
                )

        slot_val = int(tx_result["slot"]) if isinstance(tx_result.get("slot"), int) else None
        return PaymentVerificationResult(
            verified=True,
            option=resolved_option,
            signature=signature,
            payer=payer_pubkey,
            treasury=target_treasury,
            paid_lamports=treasury_delta,
            required_lamports=resolved_required,
            slot=slot_val,
        )

    def verify_signature_sync(
        self,
        signature: str,
        *,
        requested_option: str = "",
        claim_hint: Optional[Mapping[str, Any]] = None,
    ) -> PaymentVerificationResult:
        try:
            tx_data = self.fetch_transaction_sync(signature, claim_hint=claim_hint)
        except Exception as exc:
            return PaymentVerificationResult(
                verified=False,
                option=requested_option,
                signature=signature,
                treasury=self.treasury,
                required_lamports=OPTION_A_LAMPORTS if requested_option == OPTION_A_ID else OPTION_B_LAMPORTS,
                error_code="RPC_VERIFICATION_ERROR",
                reason=str(exc),
            )
        return self.verify_transaction_data(
            signature,
            tx_data,
            requested_option=requested_option,
            expected_treasury=self.treasury,
        )

    async def verify_signature_async(
        self,
        signature: str,
        *,
        requested_option: str = "",
        claim_hint: Optional[Mapping[str, Any]] = None,
    ) -> PaymentVerificationResult:
        try:
            tx_data = await self.fetch_transaction_async(signature, claim_hint=claim_hint)
        except Exception as exc:
            return PaymentVerificationResult(
                verified=False,
                option=requested_option,
                signature=signature,
                treasury=self.treasury,
                required_lamports=OPTION_A_LAMPORTS if requested_option == OPTION_A_ID else OPTION_B_LAMPORTS,
                error_code="RPC_VERIFICATION_ERROR",
                reason=str(exc),
            )
        return self.verify_transaction_data(
            signature,
            tx_data,
            requested_option=requested_option,
            expected_treasury=self.treasury,
        )


class MockSolanaRpcVerifier(SolanaRpcVerifier):
    """
    Deterministic in-memory Solana `getTransaction` verifier for 100% offline unit
    and cross-squad E2E testing. Executes the exact same `verify_transaction_data`
    checks (`meta.err`, `accountKeys`, `postBalances - preBalances`) as production!
    """

    def __init__(
        self,
        *,
        treasury: str = TREASURY_WALLET,
        transactions: Optional[Mapping[str, Mapping[str, Any]]] = None,
        auto_accept_from_claim: bool = False,
        dynamic_resolver: Optional[Callable[[str, Optional[Mapping[str, Any]]], Optional[Dict[str, Any]]]] = None,
    ) -> None:
        super().__init__(rpc_url="mock://solana-mainnet-beta", treasury=treasury)
        self._lock = threading.RLock()
        self._transactions: Dict[str, Dict[str, Any]] = {
            str(k): dict(v) for k, v in (transactions or {}).items()
        }
        self.auto_accept_from_claim = bool(auto_accept_from_claim)
        self.dynamic_resolver = dynamic_resolver
        self.calls: List[str] = []

    @classmethod
    def for_e2e_harness(cls, treasury: str = TREASURY_WALLET) -> "MockSolanaRpcVerifier":
        """Factory pre-configured for E2E mock-signer testing while preserving full balance/replay checks."""
        return cls(treasury=treasury, auto_accept_from_claim=True)

    @staticmethod
    def build_rpc_transaction(
        signature: str,
        *,
        payer: str = DEFAULT_MOCK_PAYER,
        pay_to: str = TREASURY_WALLET,
        lamports: int = OPTION_B_LAMPORTS,
        fee_lamports: int = 5_000,
        payer_pre_balance: int = 2_000_000_000,
        recipient_pre_balance: int = 100_000_000,
        err: Any = None,
        slot: int = 325_000_001,
        block_time: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Construct a realistic Solana `getTransaction` (`jsonParsed`) result object."""
        btime = block_time if block_time is not None else int(time.time())
        effective_transfer = int(lamports) if err is None else 0
        payer_post = max(0, int(payer_pre_balance) - effective_transfer - int(fee_lamports))
        recipient_post = int(recipient_pre_balance) + effective_transfer
        return {
            "slot": slot,
            "blockTime": btime,
            "version": 0,
            "meta": {
                "err": err,
                "status": {"Ok": None} if err is None else {"Err": err},
                "fee": int(fee_lamports),
                "preBalances": [int(payer_pre_balance), int(recipient_pre_balance), 1],
                "postBalances": [payer_post, recipient_post, 1],
                "innerInstructions": [],
                "logMessages": [
                    f"Program {SYSTEM_PROGRAM_ID} invoke [1]",
                    f"Program {SYSTEM_PROGRAM_ID} success" if err is None else f"Program {SYSTEM_PROGRAM_ID} failed",
                ],
            },
            "transaction": {
                "signatures": [signature],
                "message": {
                    "accountKeys": [
                        {"pubkey": payer, "signer": True, "writable": True, "source": "transaction"},
                        {"pubkey": pay_to, "signer": False, "writable": True, "source": "transaction"},
                        {"pubkey": SYSTEM_PROGRAM_ID, "signer": False, "writable": False, "source": "transaction"},
                    ],
                    "recentBlockhash": "11111111111111111111111111111111",
                    "instructions": [
                        {
                            "program": "system",
                            "programId": SYSTEM_PROGRAM_ID,
                            "parsed": {
                                "type": "transfer",
                                "info": {
                                    "source": payer,
                                    "destination": pay_to,
                                    "lamports": int(lamports),
                                },
                            },
                        }
                    ],
                },
            },
        }

    def register_tx(
        self,
        signature: str,
        *,
        payer: str = DEFAULT_MOCK_PAYER,
        pay_to: str = TREASURY_WALLET,
        lamports: int = OPTION_B_LAMPORTS,
        err: Any = None,
        slot: int = 325_000_001,
        raw_rpc_result: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        tx_obj = (
            dict(raw_rpc_result)
            if raw_rpc_result is not None
            else self.build_rpc_transaction(
                signature,
                payer=payer,
                pay_to=pay_to,
                lamports=lamports,
                err=err,
                slot=slot,
            )
        )
        with self._lock:
            self._transactions[signature] = tx_obj
        return tx_obj

    register_transaction = register_tx
    add_tx = register_tx

    def register_option_a_tx(
        self,
        signature: str,
        *,
        payer: str = DEFAULT_MOCK_PAYER,
        pay_to: str = TREASURY_WALLET,
        lamports: int = OPTION_A_LAMPORTS,
    ) -> Dict[str, Any]:
        return self.register_tx(signature, payer=payer, pay_to=pay_to, lamports=lamports)

    def register_option_b_tx(
        self,
        signature: str,
        *,
        payer: str = DEFAULT_MOCK_PAYER,
        pay_to: str = TREASURY_WALLET,
        lamports: int = OPTION_B_LAMPORTS,
    ) -> Dict[str, Any]:
        return self.register_tx(signature, payer=payer, pay_to=pay_to, lamports=lamports)

    def register_failed_tx(
        self,
        signature: str,
        *,
        err: Any = None,
        payer: str = DEFAULT_MOCK_PAYER,
        pay_to: str = TREASURY_WALLET,
        lamports: int = OPTION_B_LAMPORTS,
    ) -> Dict[str, Any]:
        failure = err if err is not None else {"InstructionError": [0, {"Custom": 1}]}
        return self.register_tx(signature, payer=payer, pay_to=pay_to, lamports=lamports, err=failure)

    def fetch_transaction_sync(
        self,
        signature: str,
        *,
        claim_hint: Optional[Mapping[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        sig = (signature or "").strip()
        with self._lock:
            self.calls.append(sig)
            if sig in self._transactions:
                return dict(self._transactions[sig])

        if self.dynamic_resolver is not None:
            resolved = self.dynamic_resolver(sig, claim_hint)
            if resolved is not None:
                return resolved

        if self.auto_accept_from_claim and sig:
            hint = claim_hint or {}
            pay_to = str(hint.get("pay_to") or self.treasury)
            payer = str(hint.get("payer") or DEFAULT_MOCK_PAYER)
            opt = str(hint.get("option") or "").lower()
            claimed_lamports = hint.get("claimed_lamports")
            if claimed_lamports is not None:
                lamports = int(claimed_lamports)
            elif (
                opt in (OPTION_A_ID, "option_a", "pro_pass", "pro")
                or sig.startswith("5MockA")
                or "option_a" in sig.lower()
                or "pro" in sig.lower()
            ):
                lamports = OPTION_A_LAMPORTS
            else:
                lamports = OPTION_B_LAMPORTS
            return self.build_rpc_transaction(sig, payer=payer, pay_to=pay_to, lamports=lamports)

        return None

    async def fetch_transaction_async(
        self,
        signature: str,
        *,
        claim_hint: Optional[Mapping[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        return self.fetch_transaction_sync(signature, claim_hint=claim_hint)


# ---------------------------------------------------------------------------
# Framework-Agnostic Core Gatekeeper: X402SolanaGatekeeper
# ---------------------------------------------------------------------------


class X402SolanaGatekeeper:
    """
    Core framework-agnostic Solana `x402` gatekeeper enforcing:
    - 10 free pings per client (`X-Agent-Id`, `X-API-Key`, or client IP)
    - HTTP 402 Payment Required challenge on 11th+ unpaid ping
    - Option A (`0.026 SOL` = `26,000,000` lamports): issues HMAC `X-Pro-Pass-Token`
      granting unlimited subsequent 200 OK calls
    - Option B (`0.0003 SOL` = `300,000` lamports): grants 1 request per verified tx
      signature with strict anti-replay enforcement
    """

    def __init__(
        self,
        *,
        treasury: str = TREASURY_WALLET,
        network: str = SOLANA_NETWORK,
        free_pings_limit: int = FREE_PINGS_LIMIT,
        rpc_verifier: Optional[SolanaRpcVerifier] = None,
        pro_pass_secret: Optional[str] = None,
        pro_pass_manager: Optional[ProPassTokenManager] = None,
        replay_ledger: Optional[SignatureReplayLedger] = None,
        ping_tracker: Optional[FreePingTracker] = None,
        pro_pass_store_path: Optional[str] = None,
        signature_ledger_path: Optional[str] = None,
        free_pings_store_path: Optional[str] = None,
        protected_paths: Optional[Iterable[str]] = None,
        protected_prefixes: Optional[Iterable[str]] = None,
        exempt_paths: Optional[Iterable[str]] = None,
    ) -> None:
        self.treasury = treasury
        self.network = network
        self.free_pings_limit = int(free_pings_limit)
        self.rpc_verifier = rpc_verifier or SolanaRpcVerifier(treasury=treasury)
        self.pro_pass_manager = pro_pass_manager or ProPassTokenManager(
            secret_key=pro_pass_secret,
            store_path=pro_pass_store_path,
            treasury=treasury,
        )
        self.replay_ledger = replay_ledger or SignatureReplayLedger(store_path=signature_ledger_path)
        self.ping_tracker = ping_tracker or FreePingTracker(
            limit=self.free_pings_limit,
            store_path=free_pings_store_path,
        )
        self.protected_paths: Optional[Set[str]] = (
            {self._normalize_path(p) for p in protected_paths} if protected_paths is not None else None
        )
        self.protected_prefixes: Tuple[str, ...] = (
            tuple(self._normalize_path(p) for p in protected_prefixes) if protected_prefixes is not None else ()
        )
        self.exempt_paths: Set[str] = (
            {self._normalize_path(p) for p in exempt_paths}
            if exempt_paths is not None
            else set(DEFAULT_EXEMPT_PATHS)
        )
        self._verify_lock = threading.RLock()

    @staticmethod
    def _normalize_path(path: str) -> str:
        clean = urllib.parse.unquote((path or "/").split("?", 1)[0]).strip()
        if not clean.startswith("/"):
            clean = "/" + clean
        if len(clean) > 1 and clean.endswith("/"):
            clean = clean.rstrip("/")
        return clean

    def is_path_protected(self, method: str, path: str) -> bool:
        if (method or "GET").upper() == "OPTIONS":
            return False
        norm = self._normalize_path(path)
        if norm in self.exempt_paths:
            return False
        lower = norm.lower()
        if lower.startswith("/static/") or lower.startswith("/download/") or lower.startswith("/api/pixel/"):
            return False
        if any(lower.endswith(ext) for ext in STATIC_EXEMPT_EXTENSIONS):
            return False
        if self.protected_paths is not None or self.protected_prefixes:
            in_exact = self.protected_paths is not None and norm in self.protected_paths
            in_prefix = any(norm == pref or norm.startswith(pref + "/") for pref in self.protected_prefixes)
            return bool(in_exact or in_prefix)
        return True

    @staticmethod
    def resolve_client_id(headers: Mapping[str, Any], remote_addr: str = "") -> str:
        agent_id = _get_header_case_insensitive(headers, "X-Agent-Id")
        if agent_id:
            return f"agent:{agent_id}"

        api_key = _get_header_case_insensitive(headers, "X-API-Key")
        if api_key:
            return f"apikey:{api_key}"

        auth_hdr = _get_header_case_insensitive(headers, "Authorization")
        if auth_hdr.lower().startswith("bearer "):
            tok = auth_hdr[7:].strip()
            if tok and not tok.startswith(f"{PRO_PASS_TOKEN_PREFIX}."):
                return f"apikey:{tok}"

        for ip_hdr in ("CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"):
            val = _get_header_case_insensitive(headers, ip_hdr)
            if val:
                ip = val.split(",")[0].strip()
                if ip:
                    return f"ip:{ip}"

        eff_remote = (remote_addr or "127.0.0.1").split(",")[0].strip() or "127.0.0.1"
        return f"ip:{eff_remote}"

    def _build_402_decision(
        self,
        *,
        path: str,
        client_id: str,
        used: int,
        remaining: int,
        error_code: str = "PAYMENT_REQUIRED",
        error_message: str = "",
    ) -> GatekeeperDecision:
        challenge = build_x402_challenge(
            resource=path,
            treasury=self.treasury,
            network=self.network,
            free_pings_limit=self.free_pings_limit,
            free_pings_used=used,
            free_pings_remaining=remaining,
            error_code=error_code,
            error_message=error_message,
        )
        b64_challenge = encode_base64_json(challenge)
        www_auth = build_www_authenticate_header(
            network=self.network,
            treasury=self.treasury,
            option_a_sol=OPTION_A_SOL,
            option_b_sol=OPTION_B_SOL,
        )
        headers = {
            "WWW-Authenticate": www_auth,
            "Payment-Required": b64_challenge,
            "X-Payment-Required": b64_challenge,
            "X-402-Treasury": self.treasury,
            "X-Free-Pings-Limit": str(self.free_pings_limit),
            "X-Free-Pings-Used": str(used),
            "X-Free-Pings-Remaining": str(remaining),
            "Cache-Control": "no-store",
            "Access-Control-Expose-Headers": CORS_EXPOSE_HEADERS,
        }
        if error_code and error_code != "PAYMENT_REQUIRED":
            headers["X-Payment-Error"] = error_code

        return GatekeeperDecision(
            allowed=False,
            status_code=402,
            client_id=client_id,
            auth_mode="rejected",
            payment_verified=False,
            free_pings_limit=self.free_pings_limit,
            free_pings_used=used,
            free_pings_remaining=remaining,
            error_code=error_code,
            error_message=challenge["error"],
            response_headers=headers,
            response_body=challenge,
        )

    def _build_paid_200_decision(
        self,
        *,
        client_id: str,
        auth_mode: str,
        verification: PaymentVerificationResult,
        used: int,
        remaining: int,
        issued_pro_pass_token: str = "",
    ) -> GatekeeperDecision:
        active_token = issued_pro_pass_token or verification.pro_pass_token
        receipt_payload: Dict[str, Any] = {
            "x402Version": X402_VERSION,
            "success": True,
            "network": self.network,
            "treasury": self.treasury,
            "option": verification.option,
            "transaction": verification.signature,
            "payer": verification.payer,
            "lamports": verification.paid_lamports,
        }
        if active_token:
            receipt_payload["proPassToken"] = active_token
        receipt_b64 = encode_base64_json(receipt_payload)

        resp_headers: Dict[str, str] = {
            "X-402-Treasury": self.treasury,
            "X-Payment-Verified": "true",
            "X-Payment-Option": verification.option,
            "Payment-Response": receipt_b64,
            "X-Payment-Response": receipt_b64,
            "X-Free-Pings-Limit": str(self.free_pings_limit),
            "X-Free-Pings-Used": str(used),
            "X-Free-Pings-Remaining": str(remaining),
            "Access-Control-Expose-Headers": CORS_EXPOSE_HEADERS,
        }
        if verification.signature:
            resp_headers["X-Payment-Tx-Signature"] = verification.signature
        if active_token:
            resp_headers["X-Pro-Pass-Token"] = active_token
            resp_headers["X-Pro-Pass-Active"] = "true"

        return GatekeeperDecision(
            allowed=True,
            status_code=200,
            client_id=client_id,
            auth_mode=auth_mode,
            payment_verified=True,
            option=verification.option,
            signature=verification.signature,
            payer=verification.payer,
            paid_lamports=verification.paid_lamports,
            pro_pass_token=active_token,
            free_pings_limit=self.free_pings_limit,
            free_pings_used=used,
            free_pings_remaining=remaining,
            response_headers=resp_headers,
        )

    def _precheck_credentials(
        self,
        creds: ParsedPaymentCredentials,
        *,
        path: str,
        client_id: str,
        used: int,
        remaining: int,
    ) -> Optional[GatekeeperDecision]:
        if creds.parse_error:
            return self._build_402_decision(
                path=path,
                client_id=client_id,
                used=used,
                remaining=remaining,
                error_code="INVALID_PAYMENT_HEADER",
                error_message=creds.parse_error,
            )

        if creds.pro_pass_token:
            tok_res = self.pro_pass_manager.verify_token(creds.pro_pass_token)
            if not tok_res.verified:
                return self._build_402_decision(
                    path=path,
                    client_id=client_id,
                    used=used,
                    remaining=remaining,
                    error_code=tok_res.error_code or "INVALID_PRO_PASS_TOKEN",
                    error_message=tok_res.reason,
                )
            return self._build_paid_200_decision(
                client_id=client_id,
                auth_mode="pro_pass_token",
                verification=tok_res,
                used=used,
                remaining=remaining,
            )

        if creds.x402_version is not None and creds.x402_version != X402_VERSION:
            return self._build_402_decision(
                path=path,
                client_id=client_id,
                used=used,
                remaining=remaining,
                error_code="UNSUPPORTED_X402_VERSION",
                error_message=f"Unsupported x402Version {creds.x402_version}; expected {X402_VERSION}",
            )

        if creds.network and creds.network.lower() not in ACCEPTED_SOLANA_NETWORKS:
            return self._build_402_decision(
                path=path,
                client_id=client_id,
                used=used,
                remaining=remaining,
                error_code="UNSUPPORTED_NETWORK",
                error_message=f"Unsupported x402 network {creds.network!r}; expected {self.network}",
            )

        if creds.pay_to and creds.pay_to != self.treasury:
            return self._build_402_decision(
                path=path,
                client_id=client_id,
                used=used,
                remaining=remaining,
                error_code="WRONG_RECIPIENT",
                error_message=f"Invalid payment recipient {creds.pay_to}; expected treasury {self.treasury}",
            )

        if self.replay_ledger.is_used(creds.signature):
            return self._build_402_decision(
                path=path,
                client_id=client_id,
                used=used,
                remaining=remaining,
                error_code="TX_SIGNATURE_REPLAYED",
                error_message=f"Transaction signature {creds.signature} has already been redeemed (anti-replay lock)",
            )

        return None

    def _finalize_verified_tx(
        self,
        creds: ParsedPaymentCredentials,
        verification: PaymentVerificationResult,
        *,
        path: str,
        client_id: str,
        used: int,
        remaining: int,
    ) -> GatekeeperDecision:
        if not verification.verified:
            return self._build_402_decision(
                path=path,
                client_id=client_id,
                used=used,
                remaining=remaining,
                error_code=verification.error_code or "PAYMENT_VERIFICATION_FAILED",
                error_message=verification.reason or "Solana transaction verification failed",
            )

        with self._verify_lock:
            consumed = self.replay_ledger.try_consume(
                creds.signature,
                {
                    "option": verification.option,
                    "payer": verification.payer or creds.payer,
                    "client_id": client_id,
                    "paid_lamports": verification.paid_lamports,
                    "treasury": self.treasury,
                    "path": path,
                },
            )
            if not consumed:
                return self._build_402_decision(
                    path=path,
                    client_id=client_id,
                    used=used,
                    remaining=remaining,
                    error_code="TX_SIGNATURE_REPLAYED",
                    error_message=f"Transaction signature {creds.signature} has already been redeemed (anti-replay lock)",
                )

            issued_token = ""
            if verification.option == OPTION_A_ID:
                issued_token = self.pro_pass_manager.issue_token(
                    signature=creds.signature,
                    payer=verification.payer or creds.payer,
                    client_id=client_id,
                    paid_lamports=verification.paid_lamports,
                )

        return self._build_paid_200_decision(
            client_id=client_id,
            auth_mode=verification.option,
            verification=verification,
            used=used,
            remaining=remaining,
            issued_pro_pass_token=issued_token,
        )

    def _evaluate_free_ping(self, *, path: str, client_id: str) -> GatekeeperDecision:
        allowed, used, remaining = self.ping_tracker.try_consume_ping(client_id)
        if allowed:
            return GatekeeperDecision(
                allowed=True,
                status_code=200,
                client_id=client_id,
                auth_mode="free_ping",
                payment_verified=False,
                free_pings_limit=self.free_pings_limit,
                free_pings_used=used,
                free_pings_remaining=remaining,
                response_headers={
                    "X-402-Treasury": self.treasury,
                    "X-Free-Pings-Limit": str(self.free_pings_limit),
                    "X-Free-Pings-Used": str(used),
                    "X-Free-Pings-Remaining": str(remaining),
                    "Access-Control-Expose-Headers": CORS_EXPOSE_HEADERS,
                },
            )
        return self._build_402_decision(
            path=path,
            client_id=client_id,
            used=used,
            remaining=remaining,
            error_code="PAYMENT_REQUIRED",
        )

    def evaluate_request_sync(
        self,
        *,
        method: str = "GET",
        path: str = "/",
        headers: Optional[Mapping[str, Any]] = None,
        remote_addr: str = "127.0.0.1",
        query: Optional[Mapping[str, Any]] = None,
        body: Optional[Mapping[str, Any]] = None,
    ) -> GatekeeperDecision:
        hdrs = headers or {}
        if not self.is_path_protected(method, path):
            return GatekeeperDecision(allowed=True, status_code=200, auth_mode="exempt")

        client_id = self.resolve_client_id(hdrs, remote_addr)
        used, remaining = self.ping_tracker.get_usage(client_id)
        creds = parse_payment_headers(hdrs, query=query, body=body)

        if creds.has_credentials:
            early = self._precheck_credentials(creds, path=path, client_id=client_id, used=used, remaining=remaining)
            if early is not None:
                return early
            claim_hint = {
                "payer": creds.payer,
                "option": creds.option,
                "claimed_lamports": creds.claimed_lamports,
                "pay_to": creds.pay_to,
            }
            verification = self.rpc_verifier.verify_signature_sync(
                creds.signature,
                requested_option=creds.option,
                claim_hint=claim_hint,
            )
            return self._finalize_verified_tx(
                creds,
                verification,
                path=path,
                client_id=client_id,
                used=used,
                remaining=remaining,
            )

        return self._evaluate_free_ping(path=path, client_id=client_id)

    async def evaluate_request_async(
        self,
        *,
        method: str = "GET",
        path: str = "/",
        headers: Optional[Mapping[str, Any]] = None,
        remote_addr: str = "127.0.0.1",
        query: Optional[Mapping[str, Any]] = None,
        body: Optional[Mapping[str, Any]] = None,
    ) -> GatekeeperDecision:
        hdrs = headers or {}
        if not self.is_path_protected(method, path):
            return GatekeeperDecision(allowed=True, status_code=200, auth_mode="exempt")

        client_id = self.resolve_client_id(hdrs, remote_addr)
        used, remaining = self.ping_tracker.get_usage(client_id)
        creds = parse_payment_headers(hdrs, query=query, body=body)

        if creds.has_credentials:
            early = self._precheck_credentials(creds, path=path, client_id=client_id, used=used, remaining=remaining)
            if early is not None:
                return early
            claim_hint = {
                "payer": creds.payer,
                "option": creds.option,
                "claimed_lamports": creds.claimed_lamports,
                "pay_to": creds.pay_to,
            }
            verification = await self.rpc_verifier.verify_signature_async(
                creds.signature,
                requested_option=creds.option,
                claim_hint=claim_hint,
            )
            return self._finalize_verified_tx(
                creds,
                verification,
                path=path,
                client_id=client_id,
                used=used,
                remaining=remaining,
            )

        return self._evaluate_free_ping(path=path, client_id=client_id)


# ---------------------------------------------------------------------------
# aiohttp.web Middleware Integration (Matches rent_shield_app/server.py)
# ---------------------------------------------------------------------------


def create_x402_aiohttp_middleware(
    gatekeeper: Optional[X402SolanaGatekeeper] = None,
    *,
    inspect_json_body: bool = True,
    **gatekeeper_kwargs: Any,
) -> Callable[..., Awaitable[Any]]:
    """
    Build an `@aiohttp.web.middleware` coroutine matching `rent_shield_app/server.py`'s
    `create_app()` architecture (`web.Application(middlewares=[...])`).
    """
    from aiohttp import web

    gk = gatekeeper or X402SolanaGatekeeper(**gatekeeper_kwargs)

    @web.middleware
    async def x402_solana_aiohttp_middleware(
        request: web.Request,
        handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
    ) -> web.StreamResponse:
        if request.method == "OPTIONS":
            resp = await handler(request)
            resp.headers.setdefault("Access-Control-Allow-Origin", "*")
            resp.headers.setdefault("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            resp.headers.setdefault("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS)
            resp.headers.setdefault("Access-Control-Expose-Headers", CORS_EXPOSE_HEADERS)
            return resp

        if not gk.is_path_protected(request.method, request.path):
            return await handler(request)

        body_dict: Optional[Dict[str, Any]] = None
        if inspect_json_body and request.method in ("POST", "PUT", "PATCH") and request.can_read_body:
            ctype = (request.content_type or "").lower()
            if "json" in ctype:
                try:
                    raw_bytes = await request.read()
                    if raw_bytes:
                        parsed_body = json.loads(raw_bytes.decode("utf-8", errors="replace"))
                        if isinstance(parsed_body, dict):
                            body_dict = parsed_body
                except Exception:
                    body_dict = None

        decision = await gk.evaluate_request_async(
            method=request.method,
            path=request.path,
            headers=request.headers,
            remote_addr=str(request.remote or "127.0.0.1"),
            query=request.query,
            body=body_dict,
        )

        if not decision.allowed:
            resp_402 = web.json_response(
                decision.response_body,
                status=decision.status_code,
                headers=decision.response_headers,
            )
            resp_402.headers.setdefault("Access-Control-Allow-Origin", "*")
            resp_402.headers.setdefault("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            resp_402.headers.setdefault("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS)
            return resp_402

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            request["x402_decision"] = decision
            request["x402_verified"] = decision.payment_verified
            request["x402_paid"] = decision.payment_verified
            request["x402_authorized"] = decision.allowed
            request["x402_option"] = decision.option
            request["x402_payer"] = decision.payer
            request["x402_pro_pass_token"] = decision.pro_pass_token

        response = await handler(request)
        for hdr_k, hdr_v in decision.response_headers.items():
            response.headers[hdr_k] = hdr_v
        response.headers.setdefault("Access-Control-Allow-Origin", "*")
        response.headers.setdefault("Access-Control-Expose-Headers", CORS_EXPOSE_HEADERS)
        return response

    x402_solana_aiohttp_middleware.gatekeeper = gk  # type: ignore[attr-defined]
    return x402_solana_aiohttp_middleware


create_x402_middleware = create_x402_aiohttp_middleware


def attach_x402_to_aiohttp_app(
    app: Any,
    gatekeeper: Optional[X402SolanaGatekeeper] = None,
    *,
    use_rentshield_route_preset: bool = True,
    **gatekeeper_kwargs: Any,
) -> X402SolanaGatekeeper:
    """
    Idempotently wire Solana `x402` middleware into an existing `aiohttp.web.Application`
    (such as `rent_shield_app/server.py`'s `create_app()`).
    """
    existing = app.get("x402_gatekeeper")
    if isinstance(existing, X402SolanaGatekeeper):
        return existing

    if gatekeeper is None:
        if use_rentshield_route_preset and "protected_paths" not in gatekeeper_kwargs:
            gatekeeper_kwargs["protected_paths"] = RENTSHIELD_PROTECTED_PATHS
        gatekeeper = X402SolanaGatekeeper(**gatekeeper_kwargs)

    mw = create_x402_aiohttp_middleware(gatekeeper)
    app.middlewares.append(mw)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        app["x402_gatekeeper"] = gatekeeper
        app["x402_middleware"] = mw
    return gatekeeper


# ---------------------------------------------------------------------------
# Framework-Agnostic ASGI & WSGI Middleware Helpers
# ---------------------------------------------------------------------------


class X402AsgiMiddleware:
    """ASGI 3.0 middleware wrapper (FastAPI / Starlette / Uvicorn / Quart)."""

    def __init__(self, app: Callable[..., Awaitable[Any]], gatekeeper: Optional[X402SolanaGatekeeper] = None, **kwargs: Any) -> None:
        self.app = app
        self.gatekeeper = gatekeeper or X402SolanaGatekeeper(**kwargs)

    async def __call__(self, scope: Dict[str, Any], receive: Callable[..., Awaitable[Any]], send: Callable[..., Awaitable[Any]]) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method") or "GET").upper()
        path = str(scope.get("path") or "/")
        raw_headers = scope.get("headers") or []
        headers_dict: Dict[str, str] = {}
        for k_bytes, v_bytes in raw_headers:
            k_str = k_bytes.decode("latin-1") if isinstance(k_bytes, (bytes, bytearray)) else str(k_bytes)
            v_str = v_bytes.decode("latin-1") if isinstance(v_bytes, (bytes, bytearray)) else str(v_bytes)
            headers_dict[k_str] = v_str

        client_tuple = scope.get("client")
        remote_ip = str(client_tuple[0]) if isinstance(client_tuple, (list, tuple)) and client_tuple else "127.0.0.1"
        qs_bytes = scope.get("query_string") or b""
        qs_str = qs_bytes.decode("latin-1") if isinstance(qs_bytes, (bytes, bytearray)) else str(qs_bytes)
        query_dict = {k: v[-1] for k, v in urllib.parse.parse_qs(qs_str).items() if v}

        decision = await self.gatekeeper.evaluate_request_async(
            method=method,
            path=path,
            headers=headers_dict,
            remote_addr=remote_ip,
            query=query_dict,
        )

        if not decision.allowed:
            payload_bytes = json.dumps(decision.response_body).encode("utf-8")
            asgi_headers = [(b"content-type", b"application/json; charset=utf-8")]
            for hk, hv in decision.response_headers.items():
                asgi_headers.append((hk.lower().encode("latin-1"), hv.encode("latin-1")))
            asgi_headers.append((b"content-length", str(len(payload_bytes)).encode("ascii")))
            await send({"type": "http.response.start", "status": decision.status_code, "headers": asgi_headers})
            await send({"type": "http.response.body", "body": payload_bytes})
            return

        state = scope.setdefault("state", {})
        if isinstance(state, dict):
            state["x402_decision"] = decision
            state["x402_verified"] = decision.payment_verified

        async def send_with_x402_headers(message: Dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                out_headers = list(message.get("headers") or [])
                for hk, hv in decision.response_headers.items():
                    out_headers.append((hk.lower().encode("latin-1"), hv.encode("latin-1")))
                message = {**message, "headers": out_headers}
            await send(message)

        await self.app(scope, receive, send_with_x402_headers)


def create_x402_asgi_middleware(
    app: Callable[..., Awaitable[Any]],
    gatekeeper: Optional[X402SolanaGatekeeper] = None,
    **kwargs: Any,
) -> X402AsgiMiddleware:
    return X402AsgiMiddleware(app, gatekeeper=gatekeeper, **kwargs)


class X402WsgiMiddleware:
    """WSGI (PEP 3333) middleware wrapper (Flask / Gunicorn / Django WSGI)."""

    def __init__(self, app: Callable[..., Iterable[bytes]], gatekeeper: Optional[X402SolanaGatekeeper] = None, **kwargs: Any) -> None:
        self.app = app
        self.gatekeeper = gatekeeper or X402SolanaGatekeeper(**kwargs)

    def __call__(self, environ: Dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        method = str(environ.get("REQUEST_METHOD") or "GET").upper()
        path = str(environ.get("PATH_INFO") or "/")
        remote_ip = str(environ.get("REMOTE_ADDR") or "127.0.0.1")
        qs_str = str(environ.get("QUERY_STRING") or "")
        query_dict = {k: v[-1] for k, v in urllib.parse.parse_qs(qs_str).items() if v}

        headers_dict: Dict[str, str] = {}
        for ek, ev in environ.items():
            if ek.startswith("HTTP_") and ev is not None:
                h_name = ek[5:].replace("_", "-")
                headers_dict[h_name] = str(ev)
        if environ.get("CONTENT_TYPE"):
            headers_dict["Content-Type"] = str(environ["CONTENT_TYPE"])

        decision = self.gatekeeper.evaluate_request_sync(
            method=method,
            path=path,
            headers=headers_dict,
            remote_addr=remote_ip,
            query=query_dict,
        )

        if not decision.allowed:
            body_bytes = json.dumps(decision.response_body).encode("utf-8")
            wsgi_headers: List[Tuple[str, str]] = [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Content-Length", str(len(body_bytes))),
            ]
            for hk, hv in decision.response_headers.items():
                wsgi_headers.append((hk, hv))
            start_response("402 Payment Required", wsgi_headers)
            return [body_bytes]

        environ["x402.decision"] = decision
        environ["x402.verified"] = decision.payment_verified

        def wrapped_start_response(status: str, response_headers: List[Tuple[str, str]], exc_info: Any = None) -> Any:
            merged = list(response_headers)
            existing_lower = {k.lower() for k, _ in merged}
            for hk, hv in decision.response_headers.items():
                if hk.lower() not in existing_lower:
                    merged.append((hk, hv))
            return start_response(status, merged, exc_info)

        return self.app(environ, wrapped_start_response)


def create_x402_wsgi_middleware(
    app: Callable[..., Iterable[bytes]],
    gatekeeper: Optional[X402SolanaGatekeeper] = None,
    **kwargs: Any,
) -> X402WsgiMiddleware:
    return X402WsgiMiddleware(app, gatekeeper=gatekeeper, **kwargs)


__all__ = [
    "ACCEPTED_SOLANA_NETWORKS",
    "CORS_ALLOW_HEADERS",
    "CORS_EXPOSE_HEADERS",
    "DEFAULT_MOCK_PAYER",
    "FREE_PINGS_LIMIT",
    "FreePingTracker",
    "GatekeeperDecision",
    "LAMPORTS_PER_SOL",
    "MockSolanaRpcVerifier",
    "OPTION_A_ID",
    "OPTION_A_LAMPORTS",
    "OPTION_A_NAME",
    "OPTION_A_SOL",
    "OPTION_A_SOL_FLOAT",
    "OPTION_A_USD",
    "OPTION_B_ID",
    "OPTION_B_LAMPORTS",
    "OPTION_B_NAME",
    "OPTION_B_SOL",
    "OPTION_B_SOL_FLOAT",
    "OPTION_B_USD",
    "PRO_PASS_TOKEN_PREFIX",
    "ParsedPaymentCredentials",
    "PaymentVerificationResult",
    "ProPassTokenManager",
    "RENTSHIELD_PROTECTED_PATHS",
    "SOLANA_NETWORK",
    "SignatureReplayLedger",
    "SolanaRpcVerifier",
    "TREASURY_WALLET",
    "X402AsgiMiddleware",
    "X402SolanaGatekeeper",
    "X402WsgiMiddleware",
    "X402_SCHEME",
    "X402_VERSION",
    "attach_x402_to_aiohttp_app",
    "build_www_authenticate_header",
    "build_x402_challenge",
    "create_x402_aiohttp_middleware",
    "create_x402_asgi_middleware",
    "create_x402_wsgi_middleware",
    "decode_base64_json",
    "encode_base64_json",
    "parse_payment_headers",
]
