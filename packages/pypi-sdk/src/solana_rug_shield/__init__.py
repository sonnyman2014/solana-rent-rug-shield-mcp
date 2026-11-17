"""Solana Rent & Rug Shield Python SDK and MCP Stdio Server (solana-rug-shield)."""

from __future__ import annotations

from .client import AsyncRugShieldClient, RugShieldClient
from .constants import (
    DEFAULT_API_URL,
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
    PACKAGE_NAME,
    PACKAGE_VERSION,
    TREASURY_WALLET,
    X402_TIERS,
    X402_TREASURY,
)
from .mcp_server import MCP_TOOLS_SPEC, MCPStdioServer, run_mcp_stdio_server
from .tx_inspector import inspect_solana_transaction_local
from .x402 import (
    SolanaKeyMaterial,
    X402AutoPayer,
    X402Challenge,
    X402Option,
    X402PaymentRequired,
    b58decode,
    b58encode,
    build_mock_signature_88,
    build_solana_transfer_transaction,
    decode_x_payment_header,
    encode_x_payment_header,
    normalize_x402_option,
    parse_402_challenge,
    parse_solana_private_key,
)

__version__ = PACKAGE_VERSION

__all__ = [
    "__version__",
    "PACKAGE_NAME",
    "PACKAGE_VERSION",
    "DEFAULT_API_URL",
    "DEFAULT_SOLANA_RPC_URL",
    "TREASURY_WALLET",
    "X402_TREASURY",
    "FREE_PINGS_LIMIT",
    "OPTION_A_PRO_PASS",
    "OPTION_A_LAMPORTS",
    "OPTION_A_SOL",
    "OPTION_A_USD",
    "OPTION_B_SINGLE_SCAN",
    "OPTION_B_LAMPORTS",
    "OPTION_B_SOL",
    "OPTION_B_USD",
    "X402_TIERS",
    "RugShieldClient",
    "AsyncRugShieldClient",
    "X402Option",
    "X402Challenge",
    "X402PaymentRequired",
    "X402AutoPayer",
    "SolanaKeyMaterial",
    "parse_solana_private_key",
    "build_solana_transfer_transaction",
    "build_mock_signature_88",
    "parse_402_challenge",
    "encode_x_payment_header",
    "decode_x_payment_header",
    "normalize_x402_option",
    "b58encode",
    "b58decode",
    "inspect_solana_transaction_local",
    "MCP_TOOLS_SPEC",
    "MCPStdioServer",
    "run_mcp_stdio_server",
]
