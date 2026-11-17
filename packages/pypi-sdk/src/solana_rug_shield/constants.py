"""Core protocol constants and endpoint route defaults for solana-rug-shield."""

from __future__ import annotations

from typing import Dict, Tuple

PACKAGE_NAME: str = "solana-rug-shield"
PACKAGE_VERSION: str = "1.0.0"

DEFAULT_API_URL: str = "https://rentandrugshield.com"
DEFAULT_SOLANA_RPC_URL: str = "https://api.mainnet-beta.solana.com"

TREASURY_WALLET: str = "89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1"
X402_TREASURY: str = TREASURY_WALLET
FREE_PINGS_LIMIT: int = 10

OPTION_A_PRO_PASS: str = "option_a_pro_pass"
OPTION_B_SINGLE_SCAN: str = "option_b_single_scan"

OPTION_A_LAMPORTS: int = 26_000_000
OPTION_A_SOL: float = 0.026
OPTION_A_USD: float = 1.99

OPTION_B_LAMPORTS: int = 300_000
OPTION_B_SOL: float = 0.0003
OPTION_B_USD: float = 0.02

X402_VERSION: int = 1
X402_SCHEME: str = "exact"
X402_NETWORK: str = "solana-mainnet"
X402_ACCEPTED_NETWORKS: Tuple[str, ...] = (
    "solana-mainnet",
    "solana:mainnet-beta",
    "solana",
    "mainnet-beta",
)

X402_TIERS: Dict[str, Dict[str, object]] = {
    OPTION_A_PRO_PASS: {
        "option": OPTION_A_PRO_PASS,
        "id": OPTION_A_PRO_PASS,
        "sol": OPTION_A_SOL,
        "lamports": OPTION_A_LAMPORTS,
        "usd": OPTION_A_USD,
        "unlimited": True,
        "payTo": TREASURY_WALLET,
        "scheme": X402_SCHEME,
        "network": X402_NETWORK,
        "description": "$1.99 Unlimited Pro Pass (0.026 SOL / 26000000 lamports) with cached X-Pro-Pass-Token",
    },
    OPTION_B_SINGLE_SCAN: {
        "option": OPTION_B_SINGLE_SCAN,
        "id": OPTION_B_SINGLE_SCAN,
        "sol": OPTION_B_SOL,
        "lamports": OPTION_B_LAMPORTS,
        "usd": OPTION_B_USD,
        "unlimited": False,
        "payTo": TREASURY_WALLET,
        "scheme": X402_SCHEME,
        "network": X402_NETWORK,
        "description": "$0.02 Instant Single Scan (0.0003 SOL / 300000 lamports) for 1 verified request",
    },
}

# Upstream route cascades locked in STRICT_CONTRACT_SPEC.json
DEFAULT_AUDIT_ROUTES: Tuple[str, ...] = (
    "/api/v1/shield-check",
    "/api/scan-token",
    "/api/audit-mint",
    "/api/scan-mint",
    "/api/audit",
)

DEFAULT_SIMULATE_ROUTES: Tuple[str, ...] = (
    "/api/v1/simulate-tx",
    "/api/simulate-tx",
    "/api/simulate-drain",
)

DEFAULT_SCAN_WALLET_ROUTES: Tuple[str, ...] = (
    "/api/scan-wallet",
    "/api/v1/scan-wallet",
)

SYSTEM_PROGRAM_ID: str = "11111111111111111111111111111111"
SPL_TOKEN_PROGRAM_ID: str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM_ID: str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
