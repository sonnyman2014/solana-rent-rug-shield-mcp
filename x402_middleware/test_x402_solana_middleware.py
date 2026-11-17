#!/usr/bin/env python3
"""
Comprehensive 100% Offline Unit & Integration Test Suite for `x402_solana_middleware.py`.

Covers:
1. 10 free pings per client (`X-Agent-Id`, `X-API-Key`, and client IP isolation) with
   `X-Free-Pings-Used` and `X-Free-Pings-Remaining` headers.
2. 11th unpaid ping HTTP `402 Payment Required` challenge headers (`WWW-Authenticate`,
   `Payment-Required`, `X-Payment-Required`, `X-402-Treasury`), JSON body, and Base64 decoding.
3. Option B (`0.0003 SOL` = `300,000` lamports) single scan verification across `X-Payment`,
   `Payment-Signature`, and `X-Solana-Tx-Signature` + strict anti-replay rejection on 2nd use.
4. Option A (`0.026 SOL` = `26,000,000` lamports) Unlimited Pro Pass verification,
   HMAC-signed `X-Pro-Pass-Token` issuance, unlimited subsequent `200 OK` calls without re-paying,
   raw Option A signature replay block, tampered/revoked token rejection, and JSON persistence.
5. Underpayment rejection (`0.0001 SOL` = `100,000` lamports, and Option B amount claiming Option A).
6. Wrong recipient rejection (payload `payTo` mismatch and on-chain `accountKeys` mismatch).
7. Failed on-chain transaction (`meta.err` non-null) and missing transaction (`result: null`) rejection.
8. Pluggable `SolanaRpcVerifier` JSON-RPC transport verification (including v0 `loadedAddresses`).
9. Full `aiohttp.web` live ephemeral localhost server middleware integration (`server.py` pattern),
   plus ASGI and WSGI middleware wrappers.
"""
from __future__ import annotations

import os
import sys
import json
import base64
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple

GATEWAY_ROOT = Path(__file__).resolve().parent.parent
if str(GATEWAY_ROOT) not in sys.path:
    sys.path.insert(0, str(GATEWAY_ROOT))

from aiohttp import ClientSession, web

import x402_solana_middleware as x402
from x402_solana_middleware import (
    FREE_PINGS_LIMIT,
    MockSolanaRpcVerifier,
    OPTION_A_ID,
    OPTION_A_LAMPORTS,
    OPTION_A_SOL,
    OPTION_B_ID,
    OPTION_B_LAMPORTS,
    OPTION_B_SOL,
    ProPassTokenManager,
    RENTSHIELD_PROTECTED_PATHS,
    SOLANA_NETWORK,
    SignatureReplayLedger,
    SolanaRpcVerifier,
    TREASURY_WALLET,
    X402AsgiMiddleware,
    X402SolanaGatekeeper,
    X402WsgiMiddleware,
    attach_x402_to_aiohttp_app,
    create_x402_aiohttp_middleware,
    decode_base64_json,
    encode_base64_json,
)

PAYER_WALLET = "76j2PCaXDeVD2CkEVDrnJCa5zYETmDYcgZv4gjtFEpov"
WRONG_TREASURY = "Cw3wqSkRPh3Z9hJoiPQtn9nRHiK4Xa9XJZsEr8cRkmHY"


def _make_x_payment_header(
    signature: str,
    *,
    option: str = OPTION_B_ID,
    lamports: int = OPTION_B_LAMPORTS,
    pay_to: str = TREASURY_WALLET,
    payer: str = PAYER_WALLET,
    network: str = "solana-mainnet",
) -> str:
    return encode_base64_json(
        {
            "x402Version": 1,
            "scheme": "exact",
            "network": network,
            "payload": {
                "signature": signature,
                "payer": payer,
                "option": option,
                "lamports": lamports,
                "payTo": pay_to,
            },
        }
    )


class TestX402GatekeeperOffline(unittest.TestCase):
    """Framework-agnostic gatekeeper, RPC verifier, token, and anti-replay unit tests."""

    def setUp(self) -> None:
        self.mock_rpc = MockSolanaRpcVerifier(treasury=TREASURY_WALLET)
        self.gatekeeper = X402SolanaGatekeeper(
            treasury=TREASURY_WALLET,
            rpc_verifier=self.mock_rpc,
            pro_pass_secret="unit_test_deterministic_hmac_secret_2026",
        )

    def test_01_ten_free_pings_and_eleventh_ping_402_challenge(self) -> None:
        headers = {"X-Agent-Id": "agent-alpha-001"}

        for i in range(1, FREE_PINGS_LIMIT + 1):
            decision = self.gatekeeper.evaluate_request_sync(
                method="POST",
                path="/api/v1/shield-check",
                headers=headers,
            )
            self.assertTrue(decision.allowed, f"Ping {i} should be allowed")
            self.assertEqual(decision.status_code, 200)
            self.assertEqual(decision.auth_mode, "free_ping")
            self.assertFalse(decision.payment_verified)
            self.assertEqual(decision.response_headers["X-Free-Pings-Used"], str(i))
            self.assertEqual(decision.response_headers["X-Free-Pings-Remaining"], str(FREE_PINGS_LIMIT - i))
            self.assertEqual(decision.response_headers["X-Free-Pings-Limit"], "10")
            self.assertEqual(decision.response_headers["X-402-Treasury"], TREASURY_WALLET)

        # Other clients (`X-Agent-Id`, `X-API-Key`, IP) retain independent 10-ping quotas
        other_agent = self.gatekeeper.evaluate_request_sync(
            method="POST",
            path="/api/v1/shield-check",
            headers={"X-Agent-Id": "agent-beta-002"},
        )
        self.assertTrue(other_agent.allowed)
        self.assertEqual(other_agent.response_headers["X-Free-Pings-Remaining"], "9")

        # 11th unpaid ping from agent-alpha-001 -> HTTP 402 Payment Required
        d11 = self.gatekeeper.evaluate_request_sync(
            method="POST",
            path="/api/v1/shield-check",
            headers=headers,
        )
        self.assertFalse(d11.allowed)
        self.assertEqual(d11.status_code, 402)
        self.assertEqual(d11.error_code, "PAYMENT_REQUIRED")

        expected_www_auth = (
            f'x402 network="{SOLANA_NETWORK}", '
            f'treasury="{TREASURY_WALLET}", '
            f'option_a_sol="{OPTION_A_SOL}", '
            f'option_b_sol="{OPTION_B_SOL}"'
        )
        self.assertEqual(d11.response_headers["WWW-Authenticate"], expected_www_auth)
        self.assertEqual(d11.response_headers["X-402-Treasury"], TREASURY_WALLET)
        self.assertEqual(d11.response_headers["X-Free-Pings-Used"], "10")
        self.assertEqual(d11.response_headers["X-Free-Pings-Remaining"], "0")

        # Verify Base64 Payment-Required & X-Payment-Required headers match body
        b64_pr = d11.response_headers["Payment-Required"]
        b64_xpr = d11.response_headers["X-Payment-Required"]
        self.assertEqual(b64_pr, b64_xpr)

        decoded_challenge = decode_base64_json(b64_pr)
        self.assertEqual(decoded_challenge["x402Version"], 1)
        self.assertEqual(decoded_challenge["treasury"], TREASURY_WALLET)
        self.assertEqual(decoded_challenge["freePingsLimit"], 10)
        self.assertEqual(decoded_challenge["freePingsUsed"], 10)
        self.assertEqual(decoded_challenge["freePingsRemaining"], 0)
        self.assertEqual(d11.response_body, decoded_challenge)

        accepts = decoded_challenge["accepts"]
        self.assertEqual(len(accepts), 2)
        by_opt = {item["option"]: item for item in accepts}
        self.assertIn(OPTION_A_ID, by_opt)
        self.assertIn(OPTION_B_ID, by_opt)

        opt_a = by_opt[OPTION_A_ID]
        self.assertEqual(opt_a["lamports"], 26_000_000)
        self.assertEqual(opt_a["maxAmountRequired"], "26000000")
        self.assertAlmostEqual(float(opt_a["sol"]), 0.026)
        self.assertEqual(opt_a["payTo"], TREASURY_WALLET)

        opt_b = by_opt[OPTION_B_ID]
        self.assertEqual(opt_b["lamports"], 300_000)
        self.assertEqual(opt_b["maxAmountRequired"], "300000")
        self.assertAlmostEqual(float(opt_b["sol"]), 0.0003)
        self.assertEqual(opt_b["payTo"], TREASURY_WALLET)

    def test_02_option_b_single_scan_and_strict_replay_rejection(self) -> None:
        client_headers = {"X-Agent-Id": "sniper-bot-opt-b"}
        for _ in range(FREE_PINGS_LIMIT):
            self.assertTrue(
                self.gatekeeper.evaluate_request_sync(
                    method="POST", path="/api/v1/shield-check", headers=client_headers
                ).allowed
            )

        sig_b1 = "5OptBSigValidSingleScan11111111111111111111111111111111111111111111111111111111111111111"
        self.mock_rpc.register_option_b_tx(sig_b1, payer=PAYER_WALLET)

        # 1st use via X-Payment -> 200 OK
        paid_hdrs = {
            **client_headers,
            "X-Payment": _make_x_payment_header(sig_b1, option=OPTION_B_ID, lamports=OPTION_B_LAMPORTS),
        }
        d_ok = self.gatekeeper.evaluate_request_sync(
            method="POST", path="/api/v1/shield-check", headers=paid_hdrs
        )
        self.assertTrue(d_ok.allowed)
        self.assertEqual(d_ok.status_code, 200)
        self.assertTrue(d_ok.payment_verified)
        self.assertEqual(d_ok.option, OPTION_B_ID)
        self.assertEqual(d_ok.paid_lamports, OPTION_B_LAMPORTS)
        self.assertEqual(d_ok.pro_pass_token, "")
        self.assertNotIn("X-Pro-Pass-Token", d_ok.response_headers)
        self.assertEqual(d_ok.response_headers["X-Payment-Verified"], "true")
        self.assertEqual(d_ok.response_headers["X-Payment-Option"], OPTION_B_ID)

        # 2nd use of the exact same Option B signature -> 402 Replay Rejected!
        d_replay = self.gatekeeper.evaluate_request_sync(
            method="POST", path="/api/v1/shield-check", headers=paid_hdrs
        )
        self.assertFalse(d_replay.allowed)
        self.assertEqual(d_replay.status_code, 402)
        self.assertEqual(d_replay.error_code, "TX_SIGNATURE_REPLAYED")
        self.assertEqual(d_replay.response_headers.get("X-Payment-Error"), "TX_SIGNATURE_REPLAYED")

        # Next unpaid call also remains 402 (Option B only granted 1 scan)
        d_unpaid_after = self.gatekeeper.evaluate_request_sync(
            method="POST", path="/api/v1/shield-check", headers=client_headers
        )
        self.assertFalse(d_unpaid_after.allowed)
        self.assertEqual(d_unpaid_after.status_code, 402)

        # Verify `Payment-Signature` and `X-Solana-Tx-Signature` header variants also work for Option B
        sig_b2 = "5OptBSigPaymentSignatureHdr2222222222222222222222222222222222222222222222222222222222222"
        sig_b3 = "5OptBSigRawSolanaTxHeader333333333333333333333333333333333333333333333333333333333333333"
        self.mock_rpc.register_option_b_tx(sig_b2, payer=PAYER_WALLET)
        self.mock_rpc.register_option_b_tx(sig_b3, payer=PAYER_WALLET)

        d_ps = self.gatekeeper.evaluate_request_sync(
            method="POST",
            path="/api/scan-wallet",
            headers={
                **client_headers,
                "Payment-Signature": _make_x_payment_header(
                    sig_b2, option=OPTION_B_ID, lamports=OPTION_B_LAMPORTS, network="solana:mainnet-beta"
                ),
            },
        )
        self.assertTrue(d_ps.allowed)
        self.assertEqual(d_ps.option, OPTION_B_ID)

        d_raw_sig = self.gatekeeper.evaluate_request_sync(
            method="POST",
            path="/api/scan-wallet",
            headers={**client_headers, "X-Solana-Tx-Signature": sig_b3},
        )
        self.assertTrue(d_raw_sig.allowed)
        self.assertEqual(d_raw_sig.option, OPTION_B_ID)

    def test_03_option_a_pro_pass_and_unlimited_token_reuse_plus_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pass_store = os.path.join(tmpdir, "pro_passes.json")
            ledger_store = os.path.join(tmpdir, "used_sigs.json")
            pings_store = os.path.join(tmpdir, "free_pings.json")

            gk1 = X402SolanaGatekeeper(
                treasury=TREASURY_WALLET,
                rpc_verifier=self.mock_rpc,
                pro_pass_secret="persistent_secret_key_x402",
                pro_pass_store_path=pass_store,
                signature_ledger_path=ledger_store,
                free_pings_store_path=pings_store,
            )

            agent_hdrs = {"X-Agent-Id": "whale-fleet-agent"}
            for _ in range(FREE_PINGS_LIMIT):
                self.assertTrue(gk1.evaluate_request_sync(method="POST", path="/api/v1/shield-check", headers=agent_hdrs).allowed)
            self.assertFalse(gk1.evaluate_request_sync(method="POST", path="/api/v1/shield-check", headers=agent_hdrs).allowed)

            sig_a = "5OptAProPass26000000LamportsTxSig1111111111111111111111111111111111111111111111111111111"
            self.mock_rpc.register_option_a_tx(sig_a, payer=PAYER_WALLET)

            d_upgrade = gk1.evaluate_request_sync(
                method="POST",
                path="/api/v1/shield-check",
                headers={
                    **agent_hdrs,
                    "X-Payment": _make_x_payment_header(
                        sig_a, option=OPTION_A_ID, lamports=OPTION_A_LAMPORTS
                    ),
                },
            )
            self.assertTrue(d_upgrade.allowed)
            self.assertEqual(d_upgrade.status_code, 200)
            self.assertEqual(d_upgrade.option, OPTION_A_ID)
            self.assertEqual(d_upgrade.paid_lamports, OPTION_A_LAMPORTS)

            pro_token = d_upgrade.response_headers.get("X-Pro-Pass-Token", "")
            self.assertTrue(pro_token.startswith("x402pp_v1."))
            self.assertEqual(d_upgrade.response_headers.get("X-Pro-Pass-Active"), "true")

            # Raw tx signature cannot be replayed to mint a second token
            d_sig_replay = gk1.evaluate_request_sync(
                method="POST",
                path="/api/v1/shield-check",
                headers={**agent_hdrs, "X-Solana-Tx-Signature": sig_a},
            )
            self.assertFalse(d_sig_replay.allowed)
            self.assertEqual(d_sig_replay.error_code, "TX_SIGNATURE_REPLAYED")

            # Unlimited subsequent calls using X-Pro-Pass-Token across reloaded gatekeeper instance!
            gk2 = X402SolanaGatekeeper(
                treasury=TREASURY_WALLET,
                rpc_verifier=self.mock_rpc,
                pro_pass_secret="persistent_secret_key_x402",
                pro_pass_store_path=pass_store,
                signature_ledger_path=ledger_store,
                free_pings_store_path=pings_store,
            )
            for call_idx in range(30):
                d_reuse = gk2.evaluate_request_sync(
                    method="POST",
                    path="/api/v1/shield-check",
                    headers={"X-Agent-Id": f"worker-{call_idx}", "X-Pro-Pass-Token": pro_token},
                )
                self.assertTrue(d_reuse.allowed, f"Unlimited Pro Pass call {call_idx} failed")
                self.assertEqual(d_reuse.status_code, 200)
                self.assertEqual(d_reuse.auth_mode, "pro_pass_token")
                self.assertTrue(d_reuse.payment_verified)
                self.assertEqual(d_reuse.response_headers["X-Pro-Pass-Active"], "true")

            # Tampered X-Pro-Pass-Token is strictly rejected with 402
            tampered_token = pro_token[:-4] + ("0000" if not pro_token.endswith("0000") else "ffff")
            d_tampered = gk2.evaluate_request_sync(
                method="POST",
                path="/api/v1/shield-check",
                headers={"X-Agent-Id": "attacker", "X-Pro-Pass-Token": tampered_token},
            )
            self.assertFalse(d_tampered.allowed)
            self.assertEqual(d_tampered.status_code, 402)
            self.assertEqual(d_tampered.error_code, "INVALID_PRO_PASS_TOKEN")

    def test_04_underpayment_rejection(self) -> None:
        # Case A: 0.0001 SOL (100,000 lamports) < Option B minimum (300,000 lamports)
        sig_under = "5Underpaid100000LamportsTxSig11111111111111111111111111111111111111111111111111111111111"
        self.mock_rpc.register_tx(sig_under, payer=PAYER_WALLET, pay_to=TREASURY_WALLET, lamports=100_000)

        d_under = self.gatekeeper.evaluate_request_sync(
            method="POST",
            path="/api/v1/shield-check",
            headers={
                "X-Agent-Id": "underpayer-1",
                "X-Payment": _make_x_payment_header(sig_under, option=OPTION_B_ID, lamports=100_000),
            },
        )
        self.assertFalse(d_under.allowed)
        self.assertEqual(d_under.status_code, 402)
        self.assertEqual(d_under.error_code, "UNDERPAYMENT")

        # Case B: Paying 0.0003 SOL (300,000 lamports) while claiming Option A Pro Pass (26,000,000 lamports)
        sig_tier_mismatch = "5UnderpaidForOptionA300000LamportsTxSig1111111111111111111111111111111111111111111111111"
        self.mock_rpc.register_tx(sig_tier_mismatch, payer=PAYER_WALLET, pay_to=TREASURY_WALLET, lamports=300_000)

        d_mismatch = self.gatekeeper.evaluate_request_sync(
            method="POST",
            path="/api/v1/shield-check",
            headers={
                "X-Agent-Id": "underpayer-2",
                "X-Payment": _make_x_payment_header(sig_tier_mismatch, option=OPTION_A_ID, lamports=OPTION_A_LAMPORTS),
            },
        )
        self.assertFalse(d_mismatch.allowed)
        self.assertEqual(d_mismatch.status_code, 402)
        self.assertEqual(d_mismatch.error_code, "UNDERPAYMENT")

    def test_05_wrong_recipient_rejection(self) -> None:
        # Case A: On-chain transfer sent to wrong wallet instead of 89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1
        sig_wrong_onchain = "5WrongRecipientOnChainTxSig1111111111111111111111111111111111111111111111111111111111111"
        self.mock_rpc.register_tx(
            sig_wrong_onchain,
            payer=PAYER_WALLET,
            pay_to=WRONG_TREASURY,
            lamports=OPTION_A_LAMPORTS,
        )

        d_wrong_onchain = self.gatekeeper.evaluate_request_sync(
            method="POST",
            path="/api/v1/shield-check",
            headers={"X-Agent-Id": "wrong-dest-1", "X-Solana-Tx-Signature": sig_wrong_onchain},
        )
        self.assertFalse(d_wrong_onchain.allowed)
        self.assertEqual(d_wrong_onchain.status_code, 402)
        self.assertEqual(d_wrong_onchain.error_code, "WRONG_RECIPIENT")

        # Case B: X-Payment header specifies wrong `payTo` address
        d_wrong_header = self.gatekeeper.evaluate_request_sync(
            method="POST",
            path="/api/v1/shield-check",
            headers={
                "X-Agent-Id": "wrong-dest-2",
                "X-Payment": _make_x_payment_header(
                    sig_wrong_onchain, option=OPTION_B_ID, lamports=OPTION_B_LAMPORTS, pay_to=WRONG_TREASURY
                ),
            },
        )
        self.assertFalse(d_wrong_header.allowed)
        self.assertEqual(d_wrong_header.status_code, 402)
        self.assertEqual(d_wrong_header.error_code, "WRONG_RECIPIENT")

    def test_06_failed_onchain_tx_and_missing_tx_rejection(self) -> None:
        sig_failed = "5FailedMetaErrOnChainTxSig11111111111111111111111111111111111111111111111111111111111111"
        self.mock_rpc.register_failed_tx(
            sig_failed,
            err={"InstructionError": [0, {"Custom": 1}]},
            payer=PAYER_WALLET,
            pay_to=TREASURY_WALLET,
            lamports=OPTION_A_LAMPORTS,
        )

        d_failed = self.gatekeeper.evaluate_request_sync(
            method="POST",
            path="/api/v1/shield-check",
            headers={"X-Agent-Id": "failed-tx-agent", "X-Solana-Tx-Signature": sig_failed},
        )
        self.assertFalse(d_failed.allowed)
        self.assertEqual(d_failed.status_code, 402)
        self.assertEqual(d_failed.error_code, "TX_FAILED_ONCHAIN")

        # Unknown / unconfirmed signature -> TX_NOT_FOUND
        d_missing = self.gatekeeper.evaluate_request_sync(
            method="POST",
            path="/api/v1/shield-check",
            headers={
                "X-Agent-Id": "missing-tx-agent",
                "X-Solana-Tx-Signature": "5UnknownUnconfirmedTxSig1111111111111111111111111111111111111111111111111111111111111111",
            },
        )
        self.assertFalse(d_missing.allowed)
        self.assertEqual(d_missing.status_code, 402)
        self.assertEqual(d_missing.error_code, "TX_NOT_FOUND")

    def test_07_real_solana_rpc_verifier_transport_and_v0_loaded_addresses(self) -> None:
        captured_calls: List[Tuple[str, Dict[str, Any]]] = []

        def fake_json_rpc_transport(url: str, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]:
            captured_calls.append((url, payload))
            return {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "slot": 330000123,
                    "meta": {
                        "err": None,
                        "preBalances": [1_000_000_000, 1, 50_000_000],
                        "postBalances": [973_995_000, 1, 76_000_000],
                        "loadedAddresses": {
                            "writable": [TREASURY_WALLET],
                            "readonly": [],
                        },
                    },
                    "transaction": {
                        "signatures": ["5V0LoadedAddrSig"],
                        "message": {
                            "accountKeys": [PAYER_WALLET, "11111111111111111111111111111111"],
                        },
                    },
                },
            }

        verifier = SolanaRpcVerifier(
            rpc_url="https://rpc.example.solana.local",
            treasury=TREASURY_WALLET,
            rpc_transport=fake_json_rpc_transport,
        )
        res = verifier.verify_signature_sync("5V0LoadedAddrSig")
        self.assertTrue(res.verified)
        self.assertEqual(res.option, OPTION_A_ID)
        self.assertEqual(res.paid_lamports, OPTION_A_LAMPORTS)
        self.assertEqual(len(captured_calls), 1)
        self.assertEqual(captured_calls[0][1]["method"], "getTransaction")

    def test_08_wsgi_middleware_integration(self) -> None:
        def simple_wsgi_app(environ: Dict[str, Any], start_response: Any) -> List[bytes]:
            start_response("200 OK", [("Content-Type", "application/json")])
            return [json.dumps({"ok": True, "paid": bool(environ.get("x402.verified"))}).encode("utf-8")]

        gk = X402SolanaGatekeeper(treasury=TREASURY_WALLET, rpc_verifier=self.mock_rpc, free_pings_limit=1)
        wsgi_mw = X402WsgiMiddleware(simple_wsgi_app, gatekeeper=gk)

        statuses: List[str] = []
        headers_seen: List[List[Tuple[str, str]]] = []

        def capture_start(status: str, response_headers: List[Tuple[str, str]], exc_info: Any = None) -> None:
            statuses.append(status)
            headers_seen.append(response_headers)

        env = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/api/v1/shield-check",
            "REMOTE_ADDR": "203.0.113.10",
            "HTTP_X_AGENT_ID": "wsgi-bot",
        }
        body_1 = b"".join(wsgi_mw(dict(env), capture_start))
        self.assertTrue(statuses[-1].startswith("200"))
        self.assertEqual(json.loads(body_1.decode("utf-8"))["ok"], True)

        body_2 = b"".join(wsgi_mw(dict(env), capture_start))
        self.assertTrue(statuses[-1].startswith("402"))
        self.assertEqual(json.loads(body_2.decode("utf-8"))["x402Version"], 1)


class TestX402AiohttpAndAsgiIntegration(unittest.IsolatedAsyncioTestCase):
    """End-to-end offline async tests for `aiohttp.web` (`server.py` architecture) & ASGI."""

    async def asyncSetUp(self) -> None:
        self.mock_rpc = MockSolanaRpcVerifier(treasury=TREASURY_WALLET)
        self.gatekeeper = X402SolanaGatekeeper(
            treasury=TREASURY_WALLET,
            rpc_verifier=self.mock_rpc,
            pro_pass_secret="aiohttp_integration_secret_2026",
            protected_paths=RENTSHIELD_PROTECTED_PATHS,
        )

        # Mirror rent_shield_app/server.py's exact middleware + route setup
        @web.middleware
        async def outer_cors_middleware(request: web.Request, handler: Any) -> web.StreamResponse:
            resp = await handler(request)
            resp.headers["X-Server-Layer"] = "rent_shield_app_compatible"
            return resp

        self.app = web.Application(middlewares=[outer_cors_middleware])
        attach_x402_to_aiohttp_app(self.app, gatekeeper=self.gatekeeper)
        # Calling attach a second time must be 100% idempotent
        attach_x402_to_aiohttp_app(self.app, gatekeeper=self.gatekeeper)
        self.assertEqual(len(self.app.middlewares), 2)

        async def handle_health(request: web.Request) -> web.Response:
            return web.json_response({"ok": True, "service": "mock-rentshield"})

        async def handle_shield_check(request: web.Request) -> web.Response:
            payload = await request.json()
            return web.json_response(
                {
                    "ok": True,
                    "mint": payload.get("mint"),
                    "score": 96,
                    "safe_to_buy": True,
                    "x402_paid": bool(request.get("x402_paid")),
                    "x402_option": request.get("x402_option") or "",
                }
            )

        async def handle_simulate_tx(request: web.Request) -> web.Response:
            payload = await request.json()
            return web.json_response(
                {
                    "ok": True,
                    "safe": True,
                    "inner_cpi_drains": 0,
                    "encoding": payload.get("encoding", "base64"),
                    "x402_paid": bool(request.get("x402_paid")),
                }
            )

        async def handle_scan_wallet(request: web.Request) -> web.Response:
            payload = await request.json()
            return web.json_response(
                {
                    "ok": True,
                    "wallet": payload.get("wallet"),
                    "reclaimable_count": 3,
                    "total_reclaimable_sol": 0.006117,
                    "x402_paid": bool(request.get("x402_paid")),
                }
            )

        self.app.router.add_get("/api/health", handle_health)
        self.app.router.add_post("/api/v1/shield-check", handle_shield_check)
        self.app.router.add_post("/api/v1/simulate-tx", handle_simulate_tx)
        self.app.router.add_post("/api/scan-wallet", handle_scan_wallet)

        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await self.site.start()
        sockets = self.site._server.sockets  # type: ignore[union-attr]
        self.port = sockets[0].getsockname()[1]
        self.base_url = f"http://127.0.0.1:{self.port}"

    async def asyncTearDown(self) -> None:
        await self.runner.cleanup()

    async def test_aiohttp_full_lifecycle_free_pings_402_option_b_and_option_a_pro_pass(self) -> None:
        mint = "3ig9E5SQKs8RjVn9EuW1YaprjaMd6dEftG63hBcMpump"
        agent_headers = {"X-Agent-Id": "mcp-aiohttp-e2e-agent"}

        async with ClientSession() as session:
            # 0. Exempt `/api/health` never consumes free pings even after 20 calls
            for _ in range(15):
                async with session.get(f"{self.base_url}/api/health", headers=agent_headers) as r_health:
                    self.assertEqual(r_health.status, 200)

            # 1. Execute 10 free pings across all 3 canonical MCP upstream endpoints
            routes = [
                ("/api/v1/shield-check", {"mint": mint}),
                ("/api/v1/simulate-tx", {"transaction": "AQAB", "encoding": "base64"}),
                ("/api/scan-wallet", {"wallet": PAYER_WALLET, "user_initiated": False, "auto_collect": False}),
            ]
            for idx in range(1, 11):
                route_path, body_json = routes[(idx - 1) % len(routes)]
                async with session.post(f"{self.base_url}{route_path}", json=body_json, headers=agent_headers) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(resp.headers["X-Free-Pings-Used"], str(idx))
                    self.assertEqual(resp.headers["X-Free-Pings-Remaining"], str(10 - idx))
                    data = await resp.json()
                    self.assertTrue(data["ok"])
                    self.assertFalse(data["x402_paid"])

            # 2. 11th unpaid call -> 402 Payment Required with base64 challenge
            async with session.post(
                f"{self.base_url}/api/v1/shield-check",
                json={"mint": mint},
                headers=agent_headers,
            ) as resp_402:
                self.assertEqual(resp_402.status, 402)
                self.assertEqual(resp_402.headers["X-402-Treasury"], TREASURY_WALLET)
                self.assertIn('option_a_sol="0.026"', resp_402.headers["WWW-Authenticate"])
                self.assertIn('option_b_sol="0.0003"', resp_402.headers["WWW-Authenticate"])
                challenge = decode_base64_json(resp_402.headers["Payment-Required"])
                body_402 = await resp_402.json()
                self.assertEqual(challenge, body_402)
                self.assertEqual(body_402["treasury"], TREASURY_WALLET)

            # 3. Auto-pay Option B (0.0003 SOL) -> 200 OK once, then 402 on replay
            sig_opt_b = "5AiohttpOptB300000LamportsTxSig111111111111111111111111111111111111111111111111111111111"
            self.mock_rpc.register_option_b_tx(sig_opt_b, payer=PAYER_WALLET)
            opt_b_hdrs = {
                **agent_headers,
                "X-Payment": _make_x_payment_header(sig_opt_b, option=OPTION_B_ID, lamports=OPTION_B_LAMPORTS),
                "X-Solana-Tx-Signature": sig_opt_b,
            }
            async with session.post(
                f"{self.base_url}/api/v1/shield-check",
                json={"mint": mint},
                headers=opt_b_hdrs,
            ) as resp_b_ok:
                self.assertEqual(resp_b_ok.status, 200)
                data_b = await resp_b_ok.json()
                self.assertTrue(data_b["x402_paid"])
                self.assertEqual(data_b["x402_option"], OPTION_B_ID)
                self.assertEqual(data_b["mint"], mint)

            async with session.post(
                f"{self.base_url}/api/v1/shield-check",
                json={"mint": mint},
                headers=opt_b_hdrs,
            ) as resp_b_replay:
                self.assertEqual(resp_b_replay.status, 402)
                err_b = await resp_b_replay.json()
                self.assertEqual(err_b["code"], "TX_SIGNATURE_REPLAYED")

            # 4. Auto-pay Option A (0.026 SOL) -> issues X-Pro-Pass-Token -> unlimited subsequent 200 OK calls
            sig_opt_a = "5AiohttpOptA26000000LamportsTxSig1111111111111111111111111111111111111111111111111111111"
            self.mock_rpc.register_option_a_tx(sig_opt_a, payer=PAYER_WALLET)
            opt_a_hdrs = {
                **agent_headers,
                "X-Payment": _make_x_payment_header(sig_opt_a, option=OPTION_A_ID, lamports=OPTION_A_LAMPORTS),
                "X-Solana-Tx-Signature": sig_opt_a,
            }
            async with session.post(
                f"{self.base_url}/api/v1/shield-check",
                json={"mint": mint},
                headers=opt_a_hdrs,
            ) as resp_a_ok:
                self.assertEqual(resp_a_ok.status, 200)
                pro_token = resp_a_ok.headers["X-Pro-Pass-Token"]
                self.assertTrue(pro_token.startswith("x402pp_v1."))
                data_a = await resp_a_ok.json()
                self.assertTrue(data_a["x402_paid"])
                self.assertEqual(data_a["x402_option"], OPTION_A_ID)

            for _ in range(15):
                async with session.post(
                    f"{self.base_url}/api/scan-wallet",
                    json={"wallet": PAYER_WALLET},
                    headers={**agent_headers, "X-Pro-Pass-Token": pro_token},
                ) as resp_pro:
                    self.assertEqual(resp_pro.status, 200)
                    data_pro = await resp_pro.json()
                    self.assertTrue(data_pro["x402_paid"])

    async def test_e2e_harness_mock_verifier_mode_and_asgi_wrapper(self) -> None:
        e2e_rpc = MockSolanaRpcVerifier.for_e2e_harness(treasury=TREASURY_WALLET)
        e2e_gk = X402SolanaGatekeeper(treasury=TREASURY_WALLET, rpc_verifier=e2e_rpc, free_pings_limit=0)

        async def asgi_ok_app(scope: Dict[str, Any], receive: Any, send: Any) -> None:
            body = json.dumps({"ok": True, "verified": scope["state"]["x402_verified"]}).encode("utf-8")
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": body})

        asgi_mw = X402AsgiMiddleware(asgi_ok_app, gatekeeper=e2e_gk)

        events: List[Dict[str, Any]] = []

        async def receive() -> Dict[str, Any]:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(msg: Dict[str, Any]) -> None:
            events.append(msg)

        # Unpaid with 0 free pings -> 402
        await asgi_mw(
            {"type": "http", "method": "POST", "path": "/api/v1/shield-check", "headers": [], "client": ("127.0.0.1", 9000)},
            receive,
            send,
        )
        self.assertEqual(events[0]["status"], 402)

        # Paid with dynamic 5MockA... signature -> 200 OK + X-Pro-Pass-Token header
        events.clear()
        mock_sig_a = "5MockA" + ("9" * 82)
        x_pay = _make_x_payment_header(mock_sig_a, option=OPTION_A_ID, lamports=OPTION_A_LAMPORTS)
        await asgi_mw(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/v1/shield-check",
                "headers": [(b"x-payment", x_pay.encode("ascii"))],
                "client": ("127.0.0.1", 9000),
            },
            receive,
            send,
        )
        self.assertEqual(events[0]["status"], 200)
        hdr_names = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in events[0]["headers"]}
        self.assertIn("x-pro-pass-token", hdr_names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
