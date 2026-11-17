"""Comprehensive offline unit, warm-socket latency, x402 auto-pay, async, and MCP stdio tests."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import http.server
import io
import json
import os
import pathlib
import socketserver
import struct
import subprocess
import sys
import threading
import time
import unittest
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure local src/ is importable regardless of test runner invocation directory
_PKG_ROOT = pathlib.Path(__file__).resolve().parents[1]
_SRC_DIR = _PKG_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from solana_rug_shield import (
    DEFAULT_API_URL,
    FREE_PINGS_LIMIT,
    OPTION_A_LAMPORTS,
    OPTION_A_PRO_PASS,
    OPTION_A_SOL,
    OPTION_B_LAMPORTS,
    OPTION_B_SINGLE_SCAN,
    OPTION_B_SOL,
    TREASURY_WALLET,
    AsyncRugShieldClient,
    MCPStdioServer,
    RugShieldClient,
    X402PaymentRequired,
    b58decode,
    b58encode,
    build_mock_signature_88,
    build_solana_transfer_transaction,
    decode_x_payment_header,
    encode_x_payment_header,
    inspect_solana_transaction_local,
    parse_402_challenge,
    parse_solana_private_key,
)
from solana_rug_shield.constants import SPL_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID
from solana_rug_shield.x402 import _pure_ed25519_pubkey, _pure_ed25519_sign, ed25519_pubkey_from_seed, ed25519_sign


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _MockX402GatewayState:
    def __init__(self, treasury: str = TREASURY_WALLET, audit_404_primary: bool = False, sim_404: bool = False) -> None:
        self.lock = threading.Lock()
        self.treasury = treasury
        self.audit_404_primary = audit_404_primary
        self.sim_404 = sim_404
        self.agent_pings: Dict[str, int] = {}
        self.used_signatures: Set[str] = set()
        self.issued_pro_tokens: Set[str] = set()
        self.recorded_requests: List[Dict[str, Any]] = []
        self.rpc_submitted_txs: List[str] = []


def _make_gateway_handler(state: _MockX402GatewayState):
    class GatewayHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _send_json(self, status: int, payload: Dict[str, Any], extra_headers: Optional[Dict[str, str]] = None) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "keep-alive")
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/api/health":
                self._send_json(200, {"ok": True, "status": "healthy"})
                return
            self._send_json(404, {"ok": False, "error": "not found"})

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            raw_body = self.rfile.read(length) if length > 0 else b"{}"
            try:
                body = json.loads(raw_body.decode("utf-8"))
            except Exception:
                body = {}

            # Support mock Solana JSON-RPC on /rpc for live SOLANA_PRIVATE_KEY tests
            if self.path == "/rpc":
                method = body.get("method")
                if method == "getLatestBlockhash":
                    bh = b58encode(hashlib.sha256(b"mock-mainnet-blockhash-1").digest())
                    self._send_json(
                        200,
                        {
                            "jsonrpc": "2.0",
                            "id": body.get("id", 1),
                            "result": {"value": {"blockhash": bh, "lastValidBlockHeight": 999999}},
                        },
                    )
                    return
                if method == "sendTransaction":
                    tx_b64 = body["params"][0]
                    raw_tx = base64.b64decode(tx_b64)
                    sig_b58 = b58encode(raw_tx[1:65])
                    with state.lock:
                        state.rpc_submitted_txs.append(sig_b58)
                    self._send_json(200, {"jsonrpc": "2.0", "id": body.get("id", 1), "result": sig_b58})
                    return

            if state.audit_404_primary and self.path == "/api/v1/shield-check":
                self._send_json(404, {"ok": False, "error": "primary route disabled in test"})
                return
            if state.sim_404 and self.path in ("/api/v1/simulate-tx", "/api/simulate-tx", "/api/simulate-drain"):
                self._send_json(404, {"ok": False, "error": "unpatched server has no simulate route"})
                return

            agent_id = self.headers.get("X-Agent-Id") or "anon"
            pro_tok = self.headers.get("X-Pro-Pass-Token") or ""
            x_pay = self.headers.get("X-Payment") or ""
            tx_sig_hdr = self.headers.get("X-Solana-Tx-Signature") or ""

            with state.lock:
                state.recorded_requests.append(
                    {
                        "path": self.path,
                        "headers": {k: v for k, v in self.headers.items()},
                        "body": body,
                    }
                )

                extra_200: Dict[str, str] = {}
                authorized = False

                if pro_tok and pro_tok in state.issued_pro_tokens:
                    authorized = True
                    extra_200["X-Pro-Pass-Active"] = "true"
                elif x_pay:
                    decoded = decode_x_payment_header(x_pay)
                    if decoded and isinstance(decoded.get("payload"), dict):
                        pay = decoded["payload"]
                        sig = str(pay.get("signature") or "")
                        pay_to = str(pay.get("payTo") or "")
                        lamports = int(pay.get("lamports") or 0)
                        opt = str(pay.get("option") or "")
                        if (
                            sig
                            and sig == tx_sig_hdr
                            and sig not in state.used_signatures
                            and pay_to == state.treasury
                        ):
                            if opt == OPTION_A_PRO_PASS and lamports >= OPTION_A_LAMPORTS:
                                state.used_signatures.add(sig)
                                new_tok = f"x402pp_v1_{hashlib.sha256(sig.encode()).hexdigest()[:24]}"
                                state.issued_pro_tokens.add(new_tok)
                                extra_200["X-Pro-Pass-Token"] = new_tok
                                extra_200["X-Payment-Verified"] = "true"
                                authorized = True
                            elif opt == OPTION_B_SINGLE_SCAN and lamports >= OPTION_B_LAMPORTS:
                                state.used_signatures.add(sig)
                                extra_200["X-Payment-Verified"] = "true"
                                authorized = True

                if not authorized:
                    used = state.agent_pings.get(agent_id, 0)
                    if used < FREE_PINGS_LIMIT:
                        used += 1
                        state.agent_pings[agent_id] = used
                        rem = FREE_PINGS_LIMIT - used
                        extra_200["X-Free-Pings-Limit"] = str(FREE_PINGS_LIMIT)
                        extra_200["X-Free-Pings-Used"] = str(used)
                        extra_200["X-Free-Pings-Remaining"] = str(rem)
                        authorized = True

                if not authorized:
                    challenge_body = {
                        "ok": False,
                        "code": "PAYMENT_REQUIRED",
                        "x402Version": 1,
                        "treasury": state.treasury,
                        "freePingsLimit": FREE_PINGS_LIMIT,
                        "freePingsUsed": FREE_PINGS_LIMIT,
                        "freePingsRemaining": 0,
                        "accepts": [
                            {
                                "option": OPTION_A_PRO_PASS,
                                "scheme": "exact",
                                "network": "solana-mainnet",
                                "payTo": state.treasury,
                                "maxAmountRequired": str(OPTION_A_LAMPORTS),
                                "lamports": OPTION_A_LAMPORTS,
                                "amountSol": OPTION_A_SOL,
                                "priceUsd": 1.99,
                            },
                            {
                                "option": OPTION_B_SINGLE_SCAN,
                                "scheme": "exact",
                                "network": "solana-mainnet",
                                "payTo": state.treasury,
                                "maxAmountRequired": str(OPTION_B_LAMPORTS),
                                "lamports": OPTION_B_LAMPORTS,
                                "amountSol": OPTION_B_SOL,
                                "priceUsd": 0.02,
                            },
                        ],
                    }
                    b64_ch = base64.b64encode(
                        json.dumps(challenge_body, separators=(",", ":")).encode("utf-8")
                    ).decode("ascii")
                    headers_402 = {
                        "WWW-Authenticate": (
                            f'x402 network="solana:mainnet-beta", treasury="{state.treasury}", '
                            f'option_a_sol="0.026", option_b_sol="0.0003"'
                        ),
                        "Payment-Required": b64_ch,
                        "X-Payment-Required": b64_ch,
                        "X-402-Treasury": state.treasury,
                        "X-Free-Pings-Used": str(FREE_PINGS_LIMIT),
                        "X-Free-Pings-Remaining": "0",
                    }
                    self._send_json(402, challenge_body, extra_headers=headers_402)
                    return

            if self.path in ("/api/v1/shield-check", "/api/scan-token", "/api/audit-mint", "/api/audit"):
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "mint": body.get("mint"),
                        "symbol": "$SOL",
                        "score": 96,
                        "safety_score": 96,
                        "safe_to_buy": True,
                        "verdict": "SAFE â€¢ 10-LAYER SHIELD PASSED",
                        "layers_checked": 10,
                        "layers_passed": 10,
                        "hidden_pda_rent_trap": False,
                    },
                    extra_headers=extra_200,
                )
            elif self.path in ("/api/v1/simulate-tx", "/api/simulate-tx"):
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "safe": True,
                        "drain_detected": False,
                        "inner_cpi_drain": False,
                        "hidden_pda_rent_trap": False,
                        "risk_level": "LOW",
                        "verdict": "SAFE",
                        "estimated_lamports_delta": -5000,
                        "estimated_sol_delta": -0.000005,
                        "flagged_programs": [],
                        "warnings": [],
                        "units_consumed": 12000,
                        "logs": ["Program 11111111111111111111111111111111 success"],
                    },
                    extra_headers=extra_200,
                )
            elif self.path in ("/api/scan-wallet", "/api/v1/scan-wallet"):
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "wallet": body.get("wallet"),
                        "sol_usd": 150.0,
                        "fee_pct": 5,
                        "empty_count": 2,
                        "dust_count": 0,
                        "active_count": 1,
                        "reclaimable_count": 2,
                        "instant_reclaimable_lamports": 4_114_080,
                        "instant_reclaimable_sol": 0.004114,
                        "dust_reclaimable_lamports": 0,
                        "dust_reclaimable_sol": 0.0,
                        "total_reclaimable_lamports": 4_114_080,
                        "total_reclaimable_sol": 0.004114,
                        "total_reclaimable_usd": 0.62,
                        "empty_reclaimable": [
                            {
                                "pubkey": "Ata1111111111111111111111111111111111111111",
                                "program_id": SPL_TOKEN_PROGRAM_ID,
                                "program_label": "SPL Token",
                                "rent_lamports": 2_039_280,
                            },
                            {
                                "pubkey": "Ata2222222222222222222222222222222222222222",
                                "program_id": TOKEN_2022_PROGRAM_ID,
                                "program_label": "Token-2022",
                                "rent_lamports": 2_074_800,
                            },
                        ],
                        "dust_reclaimable": [],
                        "frozen_traps": [],
                        "active_holdings": [
                            {
                                "pubkey": "Hold222222222222222222222222222222222222222",
                                "program_id": TOKEN_2022_PROGRAM_ID,
                                "program_label": "Token-2022",
                                "rent_lamports": 2_074_800,
                            }
                        ],
                    },
                    extra_headers=extra_200,
                )
            else:
                self._send_json(404, {"ok": False, "error": f"unknown path {self.path}"})

    return GatewayHandler


def _start_mock_server(state: _MockX402GatewayState) -> Tuple[_ThreadingHTTPServer, str]:
    srv = _ThreadingHTTPServer(("127.0.0.1", 0), _make_gateway_handler(state))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{port}"


class TestSolanaRugShieldSDK(unittest.TestCase):
    def test_constants_and_zero_dash_readme(self) -> None:
        self.assertEqual(DEFAULT_API_URL, "https://rentandrugshield.com")
        self.assertEqual(TREASURY_WALLET, "89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1")
        self.assertEqual(OPTION_A_LAMPORTS, 26_000_000)
        self.assertEqual(OPTION_B_LAMPORTS, 300_000)

        readme = (_PKG_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertGreater(len(readme), 500)
        self.assertEqual(readme.count("\u2014"), 0, "README contains forbidden em-dash")
        self.assertEqual(readme.count("\u2013"), 0, "README contains forbidden en-dash")
        self.assertEqual(readme.count(" - "), 0, "README contains forbidden spaced hyphen")
        self.assertEqual(readme.count(" -- "), 0, "README contains forbidden spaced double-hyphen")

    def test_base58_and_ed25519_key_formats_and_transfer_tx(self) -> None:
        seed = hashlib.sha256(b"unit-test-solana-keypair-seed").digest()
        pub_pure = _pure_ed25519_pubkey(seed)
        pub_main = ed25519_pubkey_from_seed(seed)
        self.assertEqual(pub_pure, pub_main)

        sample_msg = b"solana-x402-transfer-message-test"
        self.assertEqual(_pure_ed25519_sign(seed, sample_msg), ed25519_sign(seed, sample_msg))

        kp64 = seed + pub_main
        km_b58 = parse_solana_private_key(b58encode(kp64))
        km_json = parse_solana_private_key(json.dumps(list(kp64)))
        km_hex = parse_solana_private_key("0x" + seed.hex())
        self.assertEqual(km_b58.pubkey_b58, km_json.pubkey_b58)
        self.assertEqual(km_b58.pubkey_b58, km_hex.pubkey_b58)

        bh = b58encode(hashlib.sha256(b"recent-bh").digest())
        wire_tx, sig_b58 = build_solana_transfer_transaction(
            seed32=seed,
            pubkey32=pub_main,
            to_pubkey_b58=TREASURY_WALLET,
            lamports=OPTION_A_LAMPORTS,
            recent_blockhash_b58=bh,
        )
        self.assertEqual(len(b58decode(sig_b58)), 64)

        tx_b64 = base64.b64encode(wire_tx).decode("ascii")
        inspected = inspect_solana_transaction_local(tx_b64, encoding="base64", wallet=km_b58.pubkey_b58)
        self.assertTrue(inspected["ok"])
        self.assertTrue(inspected["safe"])
        self.assertFalse(inspected["drain_detected"])
        self.assertEqual(inspected["estimated_lamports_delta"], -OPTION_A_LAMPORTS)

        # Verify against solders.transaction.Transaction if installed in environment
        try:
            from solders.transaction import Transaction  # type: ignore

            parsed_tx = Transaction.from_bytes(wire_tx)
            parsed_tx.verify()
            self.assertEqual(str(parsed_tx.signatures[0]), sig_b58)
        except ImportError:
            pass

        mock_a = build_mock_signature_88(OPTION_A_PRO_PASS, b"seed-a")
        mock_b = build_mock_signature_88(OPTION_B_SINGLE_SCAN, b"seed-b")
        self.assertEqual(len(mock_a), 88)
        self.assertEqual(len(mock_b), 88)
        self.assertTrue(mock_a.startswith("5MockA"))
        self.assertTrue(mock_b.startswith("5MockB"))
        for bad_ch in ("0", "O", "I", "l"):
            self.assertNotIn(bad_ch, mock_a)
            self.assertNotIn(bad_ch, mock_b)

    def test_warm_socket_latency_under_120ms(self) -> None:
        state = _MockX402GatewayState()
        srv, base_url = _start_mock_server(state)
        try:
            with RugShieldClient(
                api_url=base_url,
                mock_signer=True,
                x402_option=OPTION_A_PRO_PASS,
            ) as client:
                self.assertTrue(client.warmup())
                latencies: List[float] = []
                for _ in range(20):
                    t0 = time.perf_counter()
                    res = client.audit_solana_token_10_layer("So11111111111111111111111111111111111111112")
                    dt_ms = (time.perf_counter() - t0) * 1000.0
                    self.assertTrue(res["ok"])
                    self.assertTrue(res["safe_to_buy"])
                    latencies.append(dt_ms)
                latencies.sort()
                p95_ms = latencies[int(len(latencies) * 0.95)]
                self.assertLess(p95_ms, 120.0, f"Warm p95 latency {p95_ms:.2f}ms exceeded 120ms SLA")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_10_free_pings_then_unpaid_402_challenge(self) -> None:
        state = _MockX402GatewayState()
        srv, base_url = _start_mock_server(state)
        try:
            with RugShieldClient(api_url=base_url, agent_id="agent-unpaid-test") as client:
                for i in range(10):
                    out = client.audit_solana_token_10_layer("So11111111111111111111111111111111111111112")
                    self.assertTrue(out["ok"])
                    self.assertEqual(out["quota"]["freePingsUsed"], i + 1)
                    self.assertEqual(out["quota"]["freePingsRemaining"], 10 - (i + 1))

                with self.assertRaises(X402PaymentRequired) as ctx:
                    client.audit_solana_token_10_layer("So11111111111111111111111111111111111111112")

                err = ctx.exception
                self.assertEqual(err.status_code, 402)
                self.assertEqual(err.treasury, TREASURY_WALLET)
                self.assertEqual(err.option_a.lamports, OPTION_A_LAMPORTS)
                self.assertEqual(err.option_b.lamports, OPTION_B_LAMPORTS)
                d = err.to_dict()
                self.assertFalse(d["ok"])
                self.assertTrue(d["paymentRequired"])

            with RugShieldClient(
                api_url=base_url, agent_id="agent-unpaid-test", raise_on_402=False
            ) as non_raising:
                resp402 = non_raising.audit_solana_token_10_layer(
                    "So11111111111111111111111111111111111111112"
                )
                self.assertEqual(resp402["status"], 402)
                self.assertEqual(resp402["treasury"], TREASURY_WALLET)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_option_a_pro_pass_auto_upgrade_caches_token(self) -> None:
        state = _MockX402GatewayState()
        srv, base_url = _start_mock_server(state)
        try:
            with RugShieldClient(
                api_url=base_url,
                agent_id="agent-opt-a",
                mock_signer=True,
                x402_option=OPTION_A_PRO_PASS,
            ) as client:
                for _ in range(10):
                    r = client.audit_solana_token_10_layer("So11111111111111111111111111111111111111112")
                    self.assertTrue(r["ok"])
                    self.assertNotIn("x402_auto_paid", r)

                # 11th call triggers 402 -> auto-pays 0.026 SOL -> caches X-Pro-Pass-Token
                r11 = client.audit_solana_token_10_layer("So11111111111111111111111111111111111111112")
                self.assertTrue(r11["ok"])
                self.assertIn("x402_auto_paid", r11)
                self.assertEqual(r11["x402_auto_paid"]["option"], OPTION_A_PRO_PASS)
                self.assertEqual(r11["x402_auto_paid"]["lamports"], OPTION_A_LAMPORTS)
                self.assertTrue(r11["x402_auto_paid"]["proPassTokenCached"])
                self.assertIsNotNone(client.pro_pass_token)

                # Calls 12..16 reuse cached X-Pro-Pass-Token with zero additional payments
                for _ in range(5):
                    r_next = client.scan_wallet_unclaimed_sol(TREASURY_WALLET)
                    self.assertTrue(r_next["ok"])
                    self.assertNotIn("x402_auto_paid", r_next)

                self.assertEqual(client.auto_payer.payments_executed, 1)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_option_b_single_scan_and_real_rpc_private_key_flow(self) -> None:
        state = _MockX402GatewayState()
        srv, base_url = _start_mock_server(state)
        try:
            with RugShieldClient(
                api_url=base_url,
                agent_id="agent-opt-b",
                mock_signer=True,
                x402_option=OPTION_B_SINGLE_SCAN,
            ) as client_b:
                for _ in range(10):
                    client_b.simulate_solana_tx_drain("AQ==")

                r11 = client_b.simulate_solana_tx_drain("AQ==")
                r12 = client_b.simulate_solana_tx_drain("AQ==")
                self.assertTrue(r11["ok"])
                self.assertTrue(r12["ok"])
                self.assertEqual(r11["x402_auto_paid"]["option"], OPTION_B_SINGLE_SCAN)
                self.assertEqual(r11["x402_auto_paid"]["lamports"], OPTION_B_LAMPORTS)
                self.assertNotEqual(
                    r11["x402_auto_paid"]["signature"],
                    r12["x402_auto_paid"]["signature"],
                )
                self.assertEqual(client_b.auto_payer.payments_executed, 2)

            # Test real SOLANA_PRIVATE_KEY signing + sendTransaction over mock JSON-RPC
            seed = hashlib.sha256(b"real-rpc-key-test").digest()
            kp_b58 = b58encode(seed + ed25519_pubkey_from_seed(seed))
            with RugShieldClient(
                api_url=base_url,
                agent_id="agent-real-key",
                solana_private_key=kp_b58,
                solana_rpc_url=f"{base_url}/rpc",
                x402_option=OPTION_B_SINGLE_SCAN,
                mock_signer=False,
            ) as real_client:
                for _ in range(10):
                    real_client.audit_solana_token_10_layer("So11111111111111111111111111111111111111112")
                r_paid = real_client.audit_solana_token_10_layer(
                    "So11111111111111111111111111111111111111112"
                )
                self.assertTrue(r_paid["ok"])
                self.assertEqual(len(state.rpc_submitted_txs), 1)
                self.assertEqual(r_paid["x402_auto_paid"]["signature"], state.rpc_submitted_txs[0])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_treasury_spoof_rejected(self) -> None:
        rogue_state = _MockX402GatewayState(treasury="11111111111111111111111111111111")
        srv, base_url = _start_mock_server(rogue_state)
        try:
            with RugShieldClient(
                api_url=base_url,
                agent_id="agent-spoof-guard",
                mock_signer=True,
            ) as client:
                for _ in range(10):
                    client.audit_solana_token_10_layer("So11111111111111111111111111111111111111112")
                with self.assertRaises(ValueError):
                    client.audit_solana_token_10_layer("So11111111111111111111111111111111111111112")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_fallbacks_drainer_inspector_and_readonly_wallet_filter(self) -> None:
        state = _MockX402GatewayState(audit_404_primary=True, sim_404=True)
        srv, base_url = _start_mock_server(state)
        try:
            with RugShieldClient(api_url=base_url, agent_id="agent-fallback") as client:
                # 1. Audit 404 on /api/v1/shield-check -> falls back cleanly to /api/scan-token
                audit_res = client.audit_solana_token_10_layer(
                    "So11111111111111111111111111111111111111112"
                )
                self.assertTrue(audit_res["ok"])

                # 2. Simulate 404 -> local wire inspector catches SPL Token Approve (opcode 4) drain
                payer_pk = hashlib.sha256(b"victim").digest()
                spl_prog = b58decode(SPL_TOKEN_PROGRAM_ID)
                bh = hashlib.sha256(b"bh").digest()
                ix_data = bytes([4]) + struct.pack("<Q", 1_000_000)  # SPL Token Approve
                msg = (
                    bytes([1, 0, 1])
                    + bytes([2])
                    + payer_pk
                    + spl_prog
                    + bh
                    + bytes([1, 1, 1, 0, len(ix_data)])
                    + ix_data
                )
                drain_tx_b64 = base64.b64encode(bytes([1]) + (b"\xaa" * 64) + msg).decode("ascii")
                sim_res = client.simulate_solana_tx_drain(drain_tx_b64)
                self.assertTrue(sim_res["ok"])
                self.assertFalse(sim_res["safe"])
                self.assertTrue(sim_res["drain_detected"])
                self.assertEqual(sim_res["fallback_mode"], "local_wire_inspector")

                # 3. Wallet scan sends read-only flags & filters Token-2022 when include_token_2022=False
                scan_all = client.scan_wallet_unclaimed_sol(TREASURY_WALLET, include_token_2022=True)
                self.assertEqual(scan_all["empty_count"], 2)
                last_req_body = state.recorded_requests[-1]["body"]
                self.assertIs(last_req_body["user_initiated"], False)
                self.assertIs(last_req_body["auto_collect"], False)

                scan_spl_only = client.scan_wallet_unclaimed_sol(TREASURY_WALLET, include_token_2022=False)
                self.assertEqual(scan_spl_only["empty_count"], 1)
                self.assertEqual(scan_spl_only["active_count"], 0)
                self.assertEqual(scan_spl_only["total_reclaimable_lamports"], 2_039_280)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_async_client_auto_pay_and_custom_async_signer(self) -> None:
        state = _MockX402GatewayState()
        srv, base_url = _start_mock_server(state)

        async def _run() -> None:
            async def custom_async_signer(opt: Any, challenge: Any) -> Dict[str, str]:
                await asyncio.sleep(0.001)
                return {
                    "signature": build_mock_signature_88(opt.option, b"async-custom-sig"),
                    "payer": "AsyncCustomPayer111111111111111111111111111",
                }

            async with AsyncRugShieldClient(
                api_url=base_url,
                agent_id="agent-async-sdk",
                x402_option=OPTION_A_PRO_PASS,
                payment_signer=custom_async_signer,
            ) as aclient:
                for _ in range(10):
                    res = await aclient.audit_solana_token_10_layer(
                        "So11111111111111111111111111111111111111112"
                    )
                    self.assertTrue(res["ok"])

                r11 = await aclient.audit_solana_token_10_layer(
                    "So11111111111111111111111111111111111111112"
                )
                self.assertTrue(r11["ok"])
                self.assertEqual(r11["x402_auto_paid"]["payer"], "AsyncCustomPayer111111111111111111111111111")
                self.assertIsNotNone(aclient.pro_pass_token)

                r12 = await aclient.scan_wallet_unclaimed_sol(TREASURY_WALLET)
                self.assertTrue(r12["ok"])
                self.assertEqual(aclient.auto_payer.payments_executed, 1)

        try:
            asyncio.run(_run())
        finally:
            srv.shutdown()
            srv.server_close()

    def test_mcp_stdio_subprocess_jsonrpc_and_content_length(self) -> None:
        state = _MockX402GatewayState()
        srv, base_url = _start_mock_server(state)
        try:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(_SRC_DIR)
            env["RENTSHIELD_API_URL"] = base_url
            env["X402_MOCK_SIGNER"] = "1"
            env["X402_OPTION"] = OPTION_A_PRO_PASS
            env["X402_AGENT_ID"] = "mcp-stdio-e2e-agent"

            proc = subprocess.Popen(
                [sys.executable, "-m", "solana_rug_shield", "--mcp-stdio"],
                cwd=str(_PKG_ROOT),
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert proc.stdin is not None and proc.stdout is not None

            def rpc(msg: Dict[str, Any]) -> Dict[str, Any]:
                proc.stdin.write(json.dumps(msg) + "\n")
                proc.stdin.flush()
                line = proc.stdout.readline()
                self.assertTrue(line, "Expected JSON-RPC response line from MCP stdio server")
                return json.loads(line)

            init_res = rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "unit-test", "version": "1.0.0"},
                    },
                }
            )
            self.assertEqual(init_res["result"]["serverInfo"]["name"], "solana-rug-shield")

            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            tools_res = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            tool_names = [t["name"] for t in tools_res["result"]["tools"]]
            self.assertEqual(
                tool_names,
                [
                    "audit_solana_token_10_layer",
                    "simulate_solana_tx_drain",
                    "scan_wallet_unclaimed_sol",
                ],
            )

            # Run 12 calls across the MCP stdio pipe: 10 free + 11th x402 auto-upgrade + 12th cached Pro Pass!
            for seq in range(1, 13):
                call_res = rpc(
                    {
                        "jsonrpc": "2.0",
                        "id": 100 + seq,
                        "method": "tools/call",
                        "params": {
                            "name": "audit_solana_token_10_layer",
                            "arguments": {"mint": "So11111111111111111111111111111111111111112"},
                        },
                    }
                )
                self.assertFalse(call_res["result"]["isError"])
                body = json.loads(call_res["result"]["content"][0]["text"])
                self.assertTrue(body["ok"])
                if seq == 11:
                    self.assertIn("x402_auto_paid", body)
                    self.assertEqual(body["x402_auto_paid"]["option"], OPTION_A_PRO_PASS)
                elif seq == 12:
                    self.assertNotIn("x402_auto_paid", body)
                    self.assertTrue(body["quota"]["proPassActive"])

            proc.stdin.close()
            proc.wait(timeout=10)
            proc.stdout.close()
            if proc.stderr is not None:
                proc.stderr.close()
            self.assertEqual(proc.returncode, 0)

            # Also verify Content-Length framing support in-memory
            cl_req = json.dumps({"jsonrpc": "2.0", "id": 77, "method": "tools/list", "params": {}}).encode("utf-8")
            in_buf = io.BytesIO(f"Content-Length: {len(cl_req)}\r\n\r\n".encode("ascii") + cl_req)
            out_buf = io.BytesIO()
            srv_inst = MCPStdioServer(RugShieldClient(api_url=base_url))
            srv_inst.serve_forever(stdin_stream=in_buf, stdout_stream=out_buf)
            raw_out = out_buf.getvalue()
            self.assertTrue(raw_out.startswith(b"Content-Length:"))
            _, json_part = raw_out.split(b"\r\n\r\n", 1)
            parsed_cl = json.loads(json_part.decode("utf-8"))
            self.assertEqual(parsed_cl["id"], 77)
            self.assertEqual(len(parsed_cl["result"]["tools"]), 3)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_cross_squad_real_x402_solana_middleware_interop(self) -> None:
        gateway_root = _PKG_ROOT.parents[1]
        mw_file = gateway_root / "x402_solana_middleware.py"
        if not mw_file.exists():
            self.skipTest("x402_solana_middleware.py not present")

        if str(gateway_root) not in sys.path:
            sys.path.insert(0, str(gateway_root))

        from aiohttp import web  # type: ignore
        import x402_solana_middleware as x402_mw  # type: ignore

        async def _run_real_mw() -> None:
            mock_rpc = x402_mw.MockSolanaRpcVerifier.for_e2e_harness()
            gatekeeper = x402_mw.X402SolanaGatekeeper(rpc_verifier=mock_rpc)
            mw = x402_mw.create_x402_aiohttp_middleware(gatekeeper)
            app = web.Application(middlewares=[mw])

            async def handle_audit(request: web.Request) -> web.Response:
                body = await request.json()
                return web.json_response(
                    {
                        "ok": True,
                        "mint": body.get("mint"),
                        "score": 95,
                        "safe_to_buy": True,
                        "verdict": "SAFE",
                    }
                )

            async def handle_sim(request: web.Request) -> web.Response:
                return web.json_response({"ok": True, "safe": True, "drain_detected": False, "verdict": "SAFE"})

            async def handle_scan(request: web.Request) -> web.Response:
                body = await request.json()
                return web.json_response({"ok": True, "wallet": body.get("wallet"), "total_reclaimable_sol": 0.012})

            app.router.add_post("/api/v1/shield-check", handle_audit)
            app.router.add_post("/api/v1/simulate-tx", handle_sim)
            app.router.add_post("/api/scan-wallet", handle_scan)

            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
            url = f"http://127.0.0.1:{port}"
            try:
                # 1. Option B single scan flow against REAL x402_solana_middleware.py
                async with AsyncRugShieldClient(
                    api_url=url,
                    agent_id="real-mw-opt-b",
                    mock_signer=True,
                    x402_option=OPTION_B_SINGLE_SCAN,
                ) as client_b:
                    for _ in range(10):
                        r = await client_b.audit_solana_token_10_layer(
                            "So11111111111111111111111111111111111111112"
                        )
                        self.assertTrue(r["ok"])
                    r11 = await client_b.simulate_solana_tx_drain("AQ==")
                    self.assertTrue(r11["ok"])
                    self.assertEqual(r11["x402_auto_paid"]["option"], OPTION_B_SINGLE_SCAN)

                # 2. Option A Unlimited Pro Pass flow against REAL x402_solana_middleware.py
                async with AsyncRugShieldClient(
                    api_url=url,
                    agent_id="real-mw-opt-a",
                    mock_signer=True,
                    x402_option=OPTION_A_PRO_PASS,
                ) as client_a:
                    for _ in range(10):
                        await client_a.scan_wallet_unclaimed_sol(TREASURY_WALLET)
                    r11_a = await client_a.audit_solana_token_10_layer(
                        "So11111111111111111111111111111111111111112"
                    )
                    self.assertTrue(r11_a["ok"])
                    self.assertTrue(r11_a["x402_auto_paid"]["proPassTokenCached"])
                    self.assertTrue(str(client_a.pro_pass_token).startswith("x402pp_v1"))

                    for _ in range(5):
                        r_cached = await client_a.audit_solana_token_10_layer(
                            "So11111111111111111111111111111111111111112"
                        )
                        self.assertTrue(r_cached["ok"])
                        self.assertNotIn("x402_auto_paid", r_cached)
                    self.assertEqual(client_a.auto_payer.payments_executed, 1)
            finally:
                await runner.cleanup()

        asyncio.run(_run_real_mw())


if __name__ == "__main__":
    unittest.main()
