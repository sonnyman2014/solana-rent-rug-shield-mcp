"""Command-line entry point for solana-rug-shield (CLI + --mcp-stdio JSON-RPC 2.0 server)."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from .client import RugShieldClient
from .constants import PACKAGE_NAME, PACKAGE_VERSION
from .mcp_server import run_mcp_stdio_server
from .x402 import X402PaymentRequired


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PACKAGE_NAME,
        description=(
            "Solana Rent & Rug Shield Python SDK and MCP Stdio Server "
            "(10-layer token gate, Layer-9 tx drain simulator, and read-only ATA rent scanner)."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PACKAGE_NAME} {PACKAGE_VERSION}",
    )
    parser.add_argument(
        "--mcp-stdio",
        action="store_true",
        help="Run JSON-RPC 2.0 Model Context Protocol (MCP) server over stdin/stdout.",
    )
    parser.add_argument(
        "--api-url",
        default=None,
        help="Override upstream base URL (defaults to RENTSHIELD_API_URL or https://rentandrugshield.com).",
    )
    parser.add_argument(
        "--pro-pass-token",
        default=None,
        help="Optional X-Pro-Pass-Token from Option A (0.026 SOL) Unlimited Pro Pass.",
    )
    parser.add_argument(
        "--payment-signature",
        default=None,
        help="Optional confirmed Solana transaction signature for manual x402 retry.",
    )

    sub = parser.add_subparsers(dest="command")

    p_mcp = sub.add_parser("mcp-stdio", help="Start MCP JSON-RPC 2.0 stdio server.")
    p_mcp.set_defaults(mcp_mode=True)

    p_audit = sub.add_parser("audit", help="Run <120ms 10-layer pre-buy Solana token safety audit.")
    p_audit.add_argument("mint", help="Base58 Solana SPL or Token-2022 mint address.")
    p_audit.add_argument("--pool-address", default=None, help="Optional AMM/bonding-curve pool address.")
    p_audit.add_argument("--wallet", default=None, help="Optional caller Solana wallet address.")

    p_sim = sub.add_parser("simulate", help="Simulate serialized Solana tx for Layer-9 Inner-CPI drains.")
    p_sim.add_argument("transaction", help="Base64 or Base58 serialized Solana transaction.")
    p_sim.add_argument("--wallet", default=None, help="Optional protected wallet public key.")
    p_sim.add_argument("--encoding", choices=["base64", "base58"], default="base64")

    p_scan = sub.add_parser("scan-wallet", help="Read-only scan for unclaimed SOL rent in empty/dust ATAs.")
    p_scan.add_argument("wallet", help="Base58 Solana wallet public key.")
    p_scan.add_argument(
        "--no-token-2022",
        action="store_true",
        help="Exclude Token-2022 accounts from wallet scan output.",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)

    if "--mcp-stdio" in raw_args or (raw_args and raw_args[0] in ("mcp-stdio", "stdio")):
        parser = build_parser()
        ns, _ = parser.parse_known_args(raw_args)
        client = RugShieldClient(
            api_url=ns.api_url,
            pro_pass_token=ns.pro_pass_token,
            raise_on_402=True,
        )
        return run_mcp_stdio_server(client=client)

    if not raw_args and not sys.stdin.isatty():
        return run_mcp_stdio_server()

    parser = build_parser()
    ns = parser.parse_args(raw_args)

    if getattr(ns, "mcp_stdio", False) or getattr(ns, "mcp_mode", False):
        client = RugShieldClient(
            api_url=ns.api_url,
            pro_pass_token=ns.pro_pass_token,
            raise_on_402=True,
        )
        return run_mcp_stdio_server(client=client)

    if not ns.command:
        parser.print_help()
        return 0

    with RugShieldClient(
        api_url=ns.api_url,
        pro_pass_token=ns.pro_pass_token,
        raise_on_402=True,
    ) as client:
        try:
            if ns.command == "audit":
                out = client.audit_solana_token_10_layer(
                    mint=ns.mint,
                    pool_address=ns.pool_address,
                    wallet=ns.wallet,
                    payment_signature=ns.payment_signature,
                    pro_pass_token=ns.pro_pass_token,
                )
            elif ns.command == "simulate":
                out = client.simulate_solana_tx_drain(
                    transaction=ns.transaction,
                    wallet=ns.wallet,
                    encoding=ns.encoding,
                    payment_signature=ns.payment_signature,
                    pro_pass_token=ns.pro_pass_token,
                )
            elif ns.command == "scan-wallet":
                out = client.scan_wallet_unclaimed_sol(
                    wallet=ns.wallet,
                    include_token_2022=not ns.no_token_2022,
                    payment_signature=ns.payment_signature,
                    pro_pass_token=ns.pro_pass_token,
                )
            else:
                parser.print_help()
                return 2
            print(json.dumps(out, indent=2))
            return 0
        except X402PaymentRequired as pay_err:
            print(json.dumps(pay_err.to_dict(), indent=2))
            return 2


if __name__ == "__main__":
    raise SystemExit(main())
