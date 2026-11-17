"""JSON-RPC 2.0 Model Context Protocol (MCP) stdio server for solana-rug-shield."""

from __future__ import annotations

import json
import sys
import time
from typing import Any, BinaryIO, Dict, List, Optional, Tuple

from .client import RugShieldClient
from .constants import PACKAGE_NAME, PACKAGE_VERSION
from .x402 import X402PaymentRequired

SUPPORTED_PROTOCOL_VERSIONS = (
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
)

MCP_TOOLS_SPEC: List[Dict[str, Any]] = [
    {
        "name": "audit_solana_token_10_layer",
        "description": (
            "Sub-120ms 10-layer pre-buy Solana token anti-rug and Token-2022 extension safety gate "
            "backed by https://rentandrugshield.com with 10 free pings and Solana x402 auto-upgrade."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["mint"],
            "properties": {
                "mint": {
                    "type": "string",
                    "description": "Base58 Solana SPL or Token-2022 mint address.",
                },
                "pool_address": {
                    "type": "string",
                    "description": "Optional AMM or bonding-curve pool address hint.",
                },
                "wallet": {
                    "type": "string",
                    "description": "Optional caller or Pro-Pass Solana wallet address.",
                },
                "payment_signature": {
                    "type": "string",
                    "description": "Optional confirmed Solana tx signature for manual x402 retry.",
                },
                "pro_pass_token": {
                    "type": "string",
                    "description": "Optional X-Pro-Pass-Token from Option A (0.026 SOL) upgrade.",
                },
            },
            "additionalProperties": False,
        },
        "annotations": {
            "title": "10-Layer Solana Token Safety Gate",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    },
    {
        "name": "simulate_solana_tx_drain",
        "description": (
            "Layer-9 Inner-CPI drainer, authority hijack, and hidden PDA rent trap check "
            "for serialized Solana transactions (base64 or base58)."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["transaction"],
            "properties": {
                "transaction": {
                    "type": "string",
                    "description": "Serialized Solana transaction (base64 or base58).",
                },
                "wallet": {
                    "type": "string",
                    "description": "Optional signer/user Solana wallet address expected to be protected.",
                },
                "encoding": {
                    "type": "string",
                    "enum": ["base64", "base58"],
                    "default": "base64",
                    "description": "Serialization encoding of transaction payload (default: base64).",
                },
                "payment_signature": {
                    "type": "string",
                    "description": "Optional confirmed Solana tx signature for manual x402 retry.",
                },
                "pro_pass_token": {
                    "type": "string",
                    "description": "Optional X-Pro-Pass-Token from Option A (0.026 SOL) upgrade.",
                },
            },
            "additionalProperties": False,
        },
        "annotations": {
            "title": "Layer-9 Inner-CPI Transaction Drainer Simulator",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    },
    {
        "name": "scan_wallet_unclaimed_sol",
        "description": (
            "Read-only Solana wallet scan for unclaimed SOL rent in empty ATAs, "
            "dead/dust token accounts, and frozen Token-2022 traps."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["wallet"],
            "properties": {
                "wallet": {
                    "type": "string",
                    "description": "Base58 Solana wallet public key to scan.",
                },
                "include_token_2022": {
                    "type": "boolean",
                    "default": True,
                    "description": "Whether to include Token-2022 accounts alongside SPL Token accounts.",
                },
                "payment_signature": {
                    "type": "string",
                    "description": "Optional confirmed Solana tx signature for manual x402 retry.",
                },
                "pro_pass_token": {
                    "type": "string",
                    "description": "Optional X-Pro-Pass-Token from Option A (0.026 SOL) upgrade.",
                },
            },
            "additionalProperties": False,
        },
        "annotations": {
            "title": "Read-Only Wallet Unclaimed SOL Rent Scanner",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    },
]


class MCPStdioServer:
    """JSON-RPC 2.0 MCP server supporting both newline-delimited JSON and Content-Length framing."""

    def __init__(self, client: Optional[RugShieldClient] = None) -> None:
        self.client = client or RugShieldClient(raise_on_402=True)

    def close(self) -> None:
        self.client.close()

    def handle_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(message, dict):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid JSON-RPC request object"},
            }

        method = message.get("method")
        msg_id = message.get("id")
        is_notification = "id" not in message

        if not isinstance(method, str):
            if is_notification:
                return None
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32600, "message": "Missing JSON-RPC method"},
            }

        if method in ("notifications/initialized", "initialized", "notifications/cancelled"):
            return None

        params = message.get("params") if isinstance(message.get("params"), dict) else {}

        if method == "initialize":
            req_ver = str(params.get("protocolVersion") or "2024-11-05")
            negotiated = req_ver if req_ver in SUPPORTED_PROTOCOL_VERSIONS else "2024-11-05"
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": negotiated,
                    "capabilities": {
                        "tools": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": PACKAGE_NAME,
                        "version": PACKAGE_VERSION,
                    },
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": MCP_TOOLS_SPEC},
            }

        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": []}}

        if method == "prompts/list":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": []}}

        if method == "tools/call":
            return self._handle_tools_call(msg_id, params)

        if is_notification:
            return None

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    def _handle_tools_call(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = str(params.get("name") or "").strip()
        args = params.get("arguments")
        if args is None:
            args = {}
        if not isinstance(args, dict):
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({"ok": False, "error": "Tool arguments must be an object"}),
                        }
                    ],
                },
            }

        known_names = {t["name"] for t in MCP_TOOLS_SPEC}
        if tool_name not in known_names:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32602, "message": f"Unknown tool: {tool_name}"},
            }

        t0 = time.perf_counter()
        try:
            if tool_name == "audit_solana_token_10_layer":
                mint = str(args.get("mint") or "").strip()
                if not mint:
                    raise ValueError("Missing required parameter: mint")
                res = self.client.audit_solana_token_10_layer(
                    mint=mint,
                    pool_address=args.get("pool_address"),
                    wallet=args.get("wallet"),
                    payment_signature=args.get("payment_signature"),
                    pro_pass_token=args.get("pro_pass_token"),
                )
            elif tool_name == "simulate_solana_tx_drain":
                tx = str(args.get("transaction") or "").strip()
                if not tx:
                    raise ValueError("Missing required parameter: transaction")
                res = self.client.simulate_solana_tx_drain(
                    transaction=tx,
                    wallet=args.get("wallet"),
                    encoding=str(args.get("encoding") or "base64"),
                    payment_signature=args.get("payment_signature"),
                    pro_pass_token=args.get("pro_pass_token"),
                )
            else:
                wallet = str(args.get("wallet") or "").strip()
                if not wallet:
                    raise ValueError("Missing required parameter: wallet")
                inc_2022 = args.get("include_token_2022")
                res = self.client.scan_wallet_unclaimed_sol(
                    wallet=wallet,
                    include_token_2022=True if inc_2022 is None else bool(inc_2022),
                    payment_signature=args.get("payment_signature"),
                    pro_pass_token=args.get("pro_pass_token"),
                )

            status_code = int(res.get("status") or 200)
            is_err = bool(not res.get("ok", True) and status_code >= 500)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "isError": is_err,
                    "content": [{"type": "text", "text": json.dumps(res)}],
                    "structuredContent": res,
                },
            }
        except X402PaymentRequired as pay_err:
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            challenge_dict = pay_err.to_dict()
            challenge_dict["x402Challenge"] = pay_err.challenge.to_dict()
            challenge_dict["quota"] = self.client.get_quota_state()
            challenge_dict["latency_ms"] = elapsed_ms
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "isError": False,
                    "content": [{"type": "text", "text": json.dumps(challenge_dict)}],
                    "structuredContent": challenge_dict,
                },
            }
        except Exception as exc:
            err_payload = {"ok": False, "error": str(exc)}
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "isError": True,
                    "content": [{"type": "text", "text": json.dumps(err_payload)}],
                },
            }

    @staticmethod
    def _read_next_frame(stdin_bin: BinaryIO) -> Optional[Tuple[bytes, str]]:
        while True:
            line = stdin_bin.readline()
            if not line:
                return None
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.lower().startswith(b"content-length:"):
                content_length = int(stripped.split(b":", 1)[1].strip())
                while True:
                    hdr_line = stdin_bin.readline()
                    if not hdr_line or hdr_line in (b"\r\n", b"\n"):
                        break
                body = stdin_bin.read(content_length)
                if not body:
                    return None
                return body, "content-length"
            return stripped, "newline"

    @staticmethod
    def _write_frame(stdout_bin: BinaryIO, payload: Dict[str, Any], mode: str) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if mode == "content-length":
            header = f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii")
            stdout_bin.write(header + encoded)
        else:
            stdout_bin.write(encoded + b"\n")
        stdout_bin.flush()

    def serve_forever(
        self,
        stdin_stream: Optional[BinaryIO] = None,
        stdout_stream: Optional[BinaryIO] = None,
    ) -> int:
        in_bin = stdin_stream or sys.stdin.buffer
        out_bin = stdout_stream or sys.stdout.buffer
        try:
            while True:
                frame = self._read_next_frame(in_bin)
                if frame is None:
                    break
                raw_bytes, framing_mode = frame
                try:
                    parsed = json.loads(raw_bytes.decode("utf-8"))
                except Exception as exc:
                    err_resp = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": f"Parse error: {exc}"},
                    }
                    self._write_frame(out_bin, err_resp, framing_mode)
                    continue

                if isinstance(parsed, list):
                    batch_out = []
                    for item in parsed:
                        resp = self.handle_message(item)
                        if resp is not None:
                            batch_out.append(resp)
                    if batch_out:
                        encoded = json.dumps(batch_out, separators=(",", ":")).encode("utf-8")
                        if framing_mode == "content-length":
                            out_bin.write(f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii") + encoded)
                        else:
                            out_bin.write(encoded + b"\n")
                        out_bin.flush()
                else:
                    resp = self.handle_message(parsed)
                    if resp is not None:
                        self._write_frame(out_bin, resp, framing_mode)
        finally:
            self.close()
        return 0


def run_mcp_stdio_server(client: Optional[RugShieldClient] = None) -> int:
    server = MCPStdioServer(client=client)
    return server.serve_forever()


def main() -> int:
    return run_mcp_stdio_server()


if __name__ == "__main__":
    raise SystemExit(main())
