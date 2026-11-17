"""Sync and Async Python SDK clients for Solana Rent & Rug Shield with persistent HTTP keep-alive and x402 auto-pay."""

from __future__ import annotations

import asyncio
import http.client
import json
import os
import socket
import ssl
import threading
import time
import urllib.parse
import uuid
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from .constants import (
    DEFAULT_API_URL,
    DEFAULT_AUDIT_ROUTES,
    DEFAULT_SCAN_WALLET_ROUTES,
    DEFAULT_SIMULATE_ROUTES,
    FREE_PINGS_LIMIT,
    PACKAGE_VERSION,
    TOKEN_2022_PROGRAM_ID,
    TREASURY_WALLET,
    X402_TIERS,
)
from .tx_inspector import inspect_solana_transaction_local
from .x402 import (
    X402AutoPayer,
    X402PaymentRequired,
    encode_x_payment_header,
    normalize_x402_option,
    parse_402_challenge,
)


class _TCPNoDelayHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection with TCP_NODELAY enabled for sub-millisecond keep-alive round-trips."""

    def connect(self) -> None:
        super().connect()
        if self.sock is not None:
            try:
                self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except OSError:
                pass


class _TCPNoDelayHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection with TCP_NODELAY enabled for sub-120ms warm TLS pre-buy checks."""

    def connect(self) -> None:
        super().connect()
        if self.sock is not None:
            try:
                self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except OSError:
                pass


class _KeepAliveConnectionPool:
    """Thread-safe persistent HTTP/1.1 keep-alive connection pool."""

    def __init__(
        self,
        base_url: str,
        max_pool_size: int = 8,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url.rstrip("/"))
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Unsupported API URL scheme in {base_url!r}; expected http or https.")
        self.scheme = parsed.scheme
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.base_path = parsed.path.rstrip("/")
        self.max_pool_size = max(1, int(max_pool_size))
        self.ssl_context = ssl_context or (ssl.create_default_context() if self.scheme == "https" else None)
        self._idle: List[http.client.HTTPConnection] = []
        self._lock = threading.Lock()
        self._closed = False

    def _new_conn(self, timeout: float) -> http.client.HTTPConnection:
        if self.scheme == "https":
            return _TCPNoDelayHTTPSConnection(
                self.host,
                self.port,
                timeout=timeout,
                context=self.ssl_context,
            )
        return _TCPNoDelayHTTPConnection(self.host, self.port, timeout=timeout)

    def _acquire(self, timeout: float) -> http.client.HTTPConnection:
        with self._lock:
            while self._idle:
                conn = self._idle.pop()
                conn.timeout = timeout
                if conn.sock is not None:
                    try:
                        conn.sock.settimeout(timeout)
                    except OSError:
                        try:
                            conn.close()
                        except Exception:
                            pass
                        continue
                return conn
        return self._new_conn(timeout)

    def _release(self, conn: http.client.HTTPConnection) -> None:
        with self._lock:
            if self._closed or len(self._idle) >= self.max_pool_size:
                try:
                    conn.close()
                except Exception:
                    pass
                return
            self._idle.append(conn)

    def request(
        self,
        method: str,
        path: str,
        body_bytes: Optional[bytes],
        headers: Mapping[str, str],
        timeout: float,
    ) -> Tuple[int, Dict[str, str], bytes]:
        rel = path if path.startswith("/") else f"/{path}"
        full_path = f"{self.base_path}{rel}" if self.base_path else rel
        req_headers = dict(headers)
        req_headers.setdefault("Connection", "keep-alive")
        if body_bytes is not None:
            req_headers["Content-Length"] = str(len(body_bytes))

        last_exc: Optional[BaseException] = None
        for attempt in range(2):
            conn = self._acquire(timeout) if attempt == 0 else self._new_conn(timeout)
            try:
                conn.request(method.upper(), full_path, body=body_bytes, headers=req_headers)
                resp = conn.getresponse()
                resp_body = resp.read()
                resp_headers = {k: v for k, v in resp.getheaders()}
                status = int(resp.status)
                conn_hdr = (resp.getheader("Connection") or "").lower()
                if conn_hdr == "close" or resp.will_close:
                    conn.close()
                else:
                    self._release(conn)
                return status, resp_headers, resp_body
            except (
                http.client.RemoteDisconnected,
                http.client.CannotSendRequest,
                http.client.ResponseNotReady,
                BrokenPipeError,
                ConnectionResetError,
                EOFError,
            ) as exc:
                last_exc = exc
                try:
                    conn.close()
                except Exception:
                    pass
                if attempt == 0:
                    continue
                raise
            except BaseException:
                try:
                    conn.close()
                except Exception:
                    pass
                raise
        assert last_exc is not None
        raise last_exc

    def close(self) -> None:
        with self._lock:
            self._closed = True
            conns = list(self._idle)
            self._idle.clear()
        for conn in conns:
            try:
                conn.close()
            except Exception:
                pass


def _ci_get(headers: Mapping[str, str], name: str) -> Optional[str]:
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target and v is not None:
            return str(v)
    return None


def _filter_token_2022_wallet_scan(data: Dict[str, Any]) -> Dict[str, Any]:
    """Filter Token-2022 accounts client-side when include_token_2022=False."""
    out = dict(data)
    sol_usd = float(out.get("sol_usd") or 0.0)
    fee_pct = float(out.get("fee_pct") if out.get("fee_pct") is not None else 5.0)

    def _keep(item: Any) -> bool:
        if not isinstance(item, Mapping):
            return True
        pid = str(item.get("program_id") or "")
        plbl = str(item.get("program_label") or "").lower()
        return pid != TOKEN_2022_PROGRAM_ID and "token-2022" not in plbl and "token_2022" not in plbl

    empty_list = [x for x in (out.get("empty_reclaimable") or []) if _keep(x)]
    dust_list = [x for x in (out.get("dust_reclaimable") or []) if _keep(x)]
    frozen_list = [x for x in (out.get("frozen_traps") or []) if _keep(x)]
    active_list = [x for x in (out.get("active_holdings") or []) if _keep(x)]

    if (
        "empty_reclaimable" not in out
        and "dust_reclaimable" not in out
        and "active_holdings" not in out
    ):
        out["include_token_2022"] = False
        return out

    instant_lamports = sum(int(x.get("rent_lamports") or 0) for x in empty_list if isinstance(x, Mapping))
    dust_lamports = sum(int(x.get("rent_lamports") or 0) for x in dust_list if isinstance(x, Mapping))
    total_lamports = instant_lamports + dust_lamports
    total_sol = round(total_lamports / 1_000_000_000, 6)
    total_usd = round(total_sol * sol_usd, 2)
    fee_lamports = int(round(total_lamports * (fee_pct / 100.0)))
    net_lamports = total_lamports - fee_lamports
    net_sol = round(net_lamports / 1_000_000_000, 6)

    out["include_token_2022"] = False
    out["empty_reclaimable"] = empty_list
    out["dust_reclaimable"] = dust_list
    out["frozen_traps"] = frozen_list
    out["active_holdings"] = active_list
    out["empty_count"] = len(empty_list)
    out["empty_accounts"] = len(empty_list)
    out["dust_count"] = len(dust_list)
    out["active_count"] = len(active_list)
    out["reclaimable_count"] = len(empty_list) + len(dust_list)
    out["instant_reclaimable_lamports"] = instant_lamports
    out["instant_reclaimable_sol"] = round(instant_lamports / 1_000_000_000, 6)
    out["dust_reclaimable_lamports"] = dust_lamports
    out["dust_reclaimable_sol"] = round(dust_lamports / 1_000_000_000, 6)
    out["total_reclaimable_lamports"] = total_lamports
    out["total_reclaimable_sol"] = total_sol
    out["total_reclaimable_usd"] = total_usd
    out["user_net_95_lamports"] = net_lamports
    out["user_net_95_sol"] = net_sol
    out["user_net_95_usd"] = round(net_sol * sol_usd, 2)
    out["service_fee_5_lamports"] = fee_lamports
    out["service_fee_5_sol"] = round(fee_lamports / 1_000_000_000, 6)
    return out


class _ClientStateMixin:
    """Shared quota, header, and x402 token caching logic for sync and async SDK clients."""

    def _init_shared_state(
        self,
        api_url: Optional[str],
        agent_id: Optional[str],
        api_key: Optional[str],
        pro_pass_token: Optional[str],
        solana_private_key: Optional[Union[str, bytes, List[int]]],
        solana_rpc_url: Optional[str],
        x402_option: Optional[str],
        mock_signer: Optional[bool],
        payment_signer: Optional[Callable[..., Any]],
        timeout: float,
        audit_timeout: float,
        raise_on_402: bool,
        expected_treasury: str,
        audit_routes: Optional[Sequence[str]],
        simulate_routes: Optional[Sequence[str]],
        scan_wallet_routes: Optional[Sequence[str]],
    ) -> None:
        resolved_url = (
            api_url
            or os.environ.get("RENTSHIELD_API_URL")
            or DEFAULT_API_URL
        ).strip().rstrip("/")
        self.api_url: str = resolved_url
        self.agent_id: str = (
            agent_id
            or os.environ.get("X402_AGENT_ID")
            or os.environ.get("RENTSHIELD_AGENT_ID")
            or f"rugshield-py-{uuid.uuid4().hex[:10]}"
        ).strip()
        self.api_key: Optional[str] = (
            api_key
            or os.environ.get("RENTSHIELD_API_KEY")
            or None
        )
        self.pro_pass_token: Optional[str] = (
            pro_pass_token
            or os.environ.get("X402_PRO_PASS_TOKEN")
            or os.environ.get("RENTSHIELD_PRO_PASS_TOKEN")
            or None
        )
        self.timeout: float = float(timeout)
        self.audit_timeout: float = float(audit_timeout)
        self.raise_on_402: bool = bool(raise_on_402)
        self.expected_treasury: str = expected_treasury

        self.audit_routes: Tuple[str, ...] = tuple(audit_routes or DEFAULT_AUDIT_ROUTES)
        self.simulate_routes: Tuple[str, ...] = tuple(simulate_routes or DEFAULT_SIMULATE_ROUTES)
        self.scan_wallet_routes: Tuple[str, ...] = tuple(scan_wallet_routes or DEFAULT_SCAN_WALLET_ROUTES)

        self.free_pings_limit: int = FREE_PINGS_LIMIT
        self.free_pings_used: int = 0
        self.free_pings_remaining: int = FREE_PINGS_LIMIT
        self._state_lock = threading.Lock()

        self.auto_payer = X402AutoPayer(
            agent_id=self.agent_id,
            solana_private_key=solana_private_key,
            solana_rpc_url=solana_rpc_url,
            x402_option=x402_option,
            mock_signer=mock_signer,
            payment_signer=payment_signer,
            expected_treasury=expected_treasury,
        )

    def get_quota_state(self) -> Dict[str, Any]:
        with self._state_lock:
            return {
                "agentId": self.agent_id,
                "freePingsLimit": self.free_pings_limit,
                "freePingsUsed": self.free_pings_used,
                "freePingsRemaining": self.free_pings_remaining,
                "proPassActive": bool(self.pro_pass_token),
                "hasProPassToken": bool(self.pro_pass_token),
                "proPassToken": self.pro_pass_token,
                "autoPayEnabled": self.auto_payer.can_auto_pay,
                "selectedOption": self.auto_payer.selected_option,
                "paymentsExecuted": self.auto_payer.payments_executed,
                "lastPaymentSignature": self.auto_payer.last_payment_signature,
            }

    def _build_request_headers(
        self,
        wallet: Optional[str] = None,
        payment_signature: Optional[str] = None,
        pro_pass_token: Optional[str] = None,
        auto_paid_info: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"solana-rug-shield/{PACKAGE_VERSION}",
            "X-Agent-Id": self.agent_id,
        }
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        eff_token = (pro_pass_token or self.pro_pass_token or "").strip()
        if eff_token:
            headers["X-Pro-Pass-Token"] = eff_token

        if auto_paid_info is not None:
            sig = str(auto_paid_info["signature"])
            b64_hdr = str(auto_paid_info["x_payment_header"])
            opt_id = str(auto_paid_info["option"])
            headers["X-Payment"] = b64_hdr
            headers["Payment-Signature"] = b64_hdr
            headers["X-Solana-Tx-Signature"] = sig
            headers["X-Payment-Option"] = opt_id
        elif payment_signature:
            sig = payment_signature.strip()
            opt_id = normalize_x402_option(self.auto_payer.selected_option)
            lam = int(X402_TIERS[opt_id]["lamports"])
            payer = (wallet or self.auto_payer.get_payer_pubkey() or "manual_payer").strip()
            b64_hdr = encode_x_payment_header(
                signature=sig,
                payer=payer,
                option=opt_id,
                lamports=lam,
                pay_to=self.expected_treasury,
            )
            headers["X-Payment"] = b64_hdr
            headers["Payment-Signature"] = b64_hdr
            headers["X-Solana-Tx-Signature"] = sig
            headers["X-Payment-Option"] = opt_id

        return headers

    def _record_200_headers_and_body(
        self,
        resp_headers: Mapping[str, str],
        parsed_body: Mapping[str, Any],
        was_paid_or_token: bool,
    ) -> bool:
        pro_token_cached = False
        hdr_tok = _ci_get(resp_headers, "x-pro-pass-token")
        body_tok = (
            parsed_body.get("pro_pass_token")
            or parsed_body.get("proPassToken")
            or parsed_body.get("x_pro_pass_token")
        )
        new_tok = str(hdr_tok or body_tok or "").strip()

        hdr_limit = _ci_get(resp_headers, "x-free-pings-limit")
        hdr_used = _ci_get(resp_headers, "x-free-pings-used")
        hdr_rem = _ci_get(resp_headers, "x-free-pings-remaining")

        with self._state_lock:
            if new_tok:
                self.pro_pass_token = new_tok
                pro_token_cached = True
            if hdr_limit is not None and hdr_limit.isdigit():
                self.free_pings_limit = int(hdr_limit)
            if hdr_used is not None and hdr_used.isdigit():
                self.free_pings_used = int(hdr_used)
            elif not was_paid_or_token and not self.pro_pass_token:
                self.free_pings_used = min(self.free_pings_limit, self.free_pings_used + 1)

            if hdr_rem is not None and hdr_rem.isdigit():
                self.free_pings_remaining = int(hdr_rem)
            else:
                self.free_pings_remaining = max(0, self.free_pings_limit - self.free_pings_used)

        return pro_token_cached

    def _decorate_response(
        self,
        parsed: Dict[str, Any],
        latency_ms: float,
        auto_paid_info: Optional[Dict[str, Any]],
        pro_token_cached: bool,
    ) -> Dict[str, Any]:
        result = dict(parsed)
        result.setdefault("ok", True)
        result["latency_ms"] = latency_ms
        result["quota"] = {
            "agentId": self.agent_id,
            "freePingsLimit": self.free_pings_limit,
            "freePingsUsed": self.free_pings_used,
            "freePingsRemaining": self.free_pings_remaining,
            "proPassActive": bool(self.pro_pass_token),
        }
        if auto_paid_info is not None:
            paid_meta = {
                "option": auto_paid_info["option"],
                "lamports": auto_paid_info["lamports"],
                "sol": auto_paid_info["sol"],
                "signature": auto_paid_info["signature"],
                "payer": auto_paid_info["payer"],
                "payTo": auto_paid_info["payTo"],
                "proPassTokenCached": pro_token_cached or bool(self.pro_pass_token),
            }
            result["x402_auto_paid"] = paid_meta
            result["x402AutoPaid"] = paid_meta
        return result


class RugShieldClient(_ClientStateMixin):
    """Synchronous Python SDK client with persistent TCP_NODELAY HTTP/1.1 keep-alive pool."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        *,
        agent_id: Optional[str] = None,
        api_key: Optional[str] = None,
        pro_pass_token: Optional[str] = None,
        solana_private_key: Optional[Union[str, bytes, List[int]]] = None,
        solana_rpc_url: Optional[str] = None,
        x402_option: Optional[str] = None,
        mock_signer: Optional[bool] = None,
        payment_signer: Optional[Callable[..., Any]] = None,
        timeout: float = 5.0,
        audit_timeout: float = 3.5,
        raise_on_402: bool = True,
        expected_treasury: str = TREASURY_WALLET,
        audit_routes: Optional[Sequence[str]] = None,
        simulate_routes: Optional[Sequence[str]] = None,
        scan_wallet_routes: Optional[Sequence[str]] = None,
        max_pool_size: int = 8,
    ) -> None:
        self._init_shared_state(
            api_url=api_url,
            agent_id=agent_id,
            api_key=api_key,
            pro_pass_token=pro_pass_token,
            solana_private_key=solana_private_key,
            solana_rpc_url=solana_rpc_url,
            x402_option=x402_option,
            mock_signer=mock_signer,
            payment_signer=payment_signer,
            timeout=timeout,
            audit_timeout=audit_timeout,
            raise_on_402=raise_on_402,
            expected_treasury=expected_treasury,
            audit_routes=audit_routes,
            simulate_routes=simulate_routes,
            scan_wallet_routes=scan_wallet_routes,
        )
        self._pool = _KeepAliveConnectionPool(self.api_url, max_pool_size=max_pool_size)

    def __enter__(self) -> "RugShieldClient":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self) -> None:
        self._pool.close()

    def warmup(self) -> bool:
        """Warm up persistent keep-alive socket against /api/health."""
        try:
            status, _, _ = self._pool.request(
                "GET",
                "/api/health",
                None,
                {"Accept": "application/json", "X-Agent-Id": self.agent_id},
                timeout=min(2.0, self.audit_timeout),
            )
            return status < 500
        except Exception:
            return False

    def _execute_cascade_sync(
        self,
        routes: Sequence[str],
        payload: Dict[str, Any],
        timeout: float,
        wallet: Optional[str] = None,
        payment_signature: Optional[str] = None,
        pro_pass_token: Optional[str] = None,
        allow_404_return: bool = False,
    ) -> Tuple[int, Dict[str, Any]]:
        t0 = time.perf_counter()
        body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        had_explicit_payment = bool(payment_signature or pro_pass_token or self.pro_pass_token)

        last_status = 404
        last_body: Dict[str, Any] = {"ok": False, "error": "No upstream route matched"}

        for idx, route in enumerate(routes):
            headers = self._build_request_headers(
                wallet=wallet,
                payment_signature=payment_signature,
                pro_pass_token=pro_pass_token,
            )
            status, resp_headers, raw_resp = self._pool.request(
                "POST", route, body_bytes, headers, timeout=timeout
            )

            # Only fallback to alias routes on 404 or 405; ALWAYS propagate 402 immediately!
            if status in (404, 405) and idx + 1 < len(routes):
                last_status = status
                continue
            if status in (404, 405) and allow_404_return:
                return status, {"ok": False, "status": status}

            auto_paid_info: Optional[Dict[str, Any]] = None
            if status == 402:
                with self._state_lock:
                    self.free_pings_used = max(self.free_pings_used, self.free_pings_limit)
                    self.free_pings_remaining = 0
                challenge = parse_402_challenge(
                    resp_headers,
                    raw_resp,
                    fallback_used_pings=self.free_pings_limit,
                    expected_treasury=self.expected_treasury,
                )
                if not self.auto_payer.can_auto_pay or payment_signature:
                    err = X402PaymentRequired(challenge, headers=resp_headers, body=challenge.raw_body)
                    if self.raise_on_402:
                        raise err
                    err_dict = err.to_dict()
                    err_dict["latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
                    err_dict["quota"] = self.get_quota_state()
                    return 402, err_dict

                auto_paid_info = self.auto_payer.execute_payment_sync(challenge)
                retry_headers = self._build_request_headers(
                    wallet=wallet,
                    pro_pass_token=pro_pass_token,
                    auto_paid_info=auto_paid_info,
                )
                status, resp_headers, raw_resp = self._pool.request(
                    "POST", route, body_bytes, retry_headers, timeout=timeout
                )
                if status == 402:
                    retry_challenge = parse_402_challenge(
                        resp_headers,
                        raw_resp,
                        fallback_used_pings=self.free_pings_limit,
                        expected_treasury=self.expected_treasury,
                    )
                    err = X402PaymentRequired(
                        retry_challenge, headers=resp_headers, body=retry_challenge.raw_body
                    )
                    if self.raise_on_402:
                        raise err
                    return 402, err.to_dict()

            try:
                parsed = json.loads(raw_resp.decode("utf-8", errors="replace")) if raw_resp else {}
                if not isinstance(parsed, dict):
                    parsed = {"data": parsed}
            except Exception:
                parsed = {"ok": status < 400, "raw": raw_resp.decode("utf-8", errors="replace")}

            latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            if 200 <= status < 300:
                pro_cached = self._record_200_headers_and_body(
                    resp_headers,
                    parsed,
                    was_paid_or_token=(had_explicit_payment or auto_paid_info is not None),
                )
                return status, self._decorate_response(parsed, latency_ms, auto_paid_info, pro_cached)

            parsed.setdefault("ok", False)
            parsed["status"] = status
            parsed["latency_ms"] = latency_ms
            return status, parsed

        return last_status, last_body

    def audit_solana_token_10_layer(
        self,
        mint: str,
        pool_address: Optional[str] = None,
        wallet: Optional[str] = None,
        payment_signature: Optional[str] = None,
        pro_pass_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute <120ms 10-layer pre-buy Solana token safety gate check."""
        mint_clean = (mint or "").strip()
        if not mint_clean:
            raise ValueError("mint is required for audit_solana_token_10_layer")
        payload: Dict[str, Any] = {
            "mint": mint_clean,
            "user_initiated": False,
        }
        if pool_address:
            payload["pool_address"] = pool_address.strip()
        if wallet:
            payload["wallet"] = wallet.strip()

        _, res = self._execute_cascade_sync(
            routes=self.audit_routes,
            payload=payload,
            timeout=self.audit_timeout,
            wallet=wallet,
            payment_signature=payment_signature,
            pro_pass_token=pro_pass_token,
        )
        if res.get("ok") and "safe_to_buy" not in res and "score" in res:
            res["safe_to_buy"] = bool(
                int(res.get("score") or 0) >= 75 and not res.get("hidden_pda_rent_trap")
            )
        return res

    def simulate_solana_tx_drain(
        self,
        transaction: str,
        wallet: Optional[str] = None,
        encoding: str = "base64",
        payment_signature: Optional[str] = None,
        pro_pass_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute Layer-9 Inner-CPI drainer and authority hijack simulation on a serialized Solana tx."""
        tx_clean = (transaction or "").strip()
        if not tx_clean:
            raise ValueError("transaction is required for simulate_solana_tx_drain")
        enc = (encoding or "base64").strip().lower()
        if enc not in ("base64", "base58"):
            raise ValueError(f"Unsupported transaction encoding {encoding!r}; expected 'base64' or 'base58'.")

        payload: Dict[str, Any] = {
            "transaction": tx_clean,
            "encoding": enc,
        }
        if wallet:
            payload["wallet"] = wallet.strip()

        t0 = time.perf_counter()
        status, res = self._execute_cascade_sync(
            routes=self.simulate_routes,
            payload=payload,
            timeout=self.timeout,
            wallet=wallet,
            payment_signature=payment_signature,
            pro_pass_token=pro_pass_token,
            allow_404_return=True,
        )
        if status in (404, 405):
            local_res = inspect_solana_transaction_local(tx_clean, encoding=enc, wallet=wallet)
            local_res["latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
            local_res["quota"] = self.get_quota_state()
            local_res["fallback_mode"] = "local_wire_inspector"
            return local_res
        return res

    def scan_wallet_unclaimed_sol(
        self,
        wallet: str,
        include_token_2022: bool = True,
        payment_signature: Optional[str] = None,
        pro_pass_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Read-only Solana wallet scan for unclaimed SOL rent in empty/dust ATAs."""
        wallet_clean = (wallet or "").strip()
        if not wallet_clean:
            raise ValueError("wallet is required for scan_wallet_unclaimed_sol")
        payload: Dict[str, Any] = {
            "wallet": wallet_clean,
            "include_token_2022": bool(include_token_2022),
            "user_initiated": False,
            "auto_collect": False,
        }
        status, res = self._execute_cascade_sync(
            routes=self.scan_wallet_routes,
            payload=payload,
            timeout=self.timeout,
            wallet=wallet_clean,
            payment_signature=payment_signature,
            pro_pass_token=pro_pass_token,
        )
        if 200 <= status < 300 and not include_token_2022 and res.get("ok"):
            return _filter_token_2022_wallet_scan(res)
        return res


class AsyncRugShieldClient(_ClientStateMixin):
    """Asynchronous Python SDK client with persistent HTTP keep-alive connection pool and x402 auto-pay."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        *,
        agent_id: Optional[str] = None,
        api_key: Optional[str] = None,
        pro_pass_token: Optional[str] = None,
        solana_private_key: Optional[Union[str, bytes, List[int]]] = None,
        solana_rpc_url: Optional[str] = None,
        x402_option: Optional[str] = None,
        mock_signer: Optional[bool] = None,
        payment_signer: Optional[Callable[..., Any]] = None,
        timeout: float = 5.0,
        audit_timeout: float = 3.5,
        raise_on_402: bool = True,
        expected_treasury: str = TREASURY_WALLET,
        audit_routes: Optional[Sequence[str]] = None,
        simulate_routes: Optional[Sequence[str]] = None,
        scan_wallet_routes: Optional[Sequence[str]] = None,
        max_pool_size: int = 8,
    ) -> None:
        self._init_shared_state(
            api_url=api_url,
            agent_id=agent_id,
            api_key=api_key,
            pro_pass_token=pro_pass_token,
            solana_private_key=solana_private_key,
            solana_rpc_url=solana_rpc_url,
            x402_option=x402_option,
            mock_signer=mock_signer,
            payment_signer=payment_signer,
            timeout=timeout,
            audit_timeout=audit_timeout,
            raise_on_402=raise_on_402,
            expected_treasury=expected_treasury,
            audit_routes=audit_routes,
            simulate_routes=simulate_routes,
            scan_wallet_routes=scan_wallet_routes,
        )
        self._fallback_pool = _KeepAliveConnectionPool(self.api_url, max_pool_size=max_pool_size)
        self._httpx_client: Any = None
        try:
            import httpx  # type: ignore

            self._httpx_client = httpx.AsyncClient(
                base_url=self.api_url,
                timeout=httpx.Timeout(self.timeout),
                limits=httpx.Limits(
                    max_keepalive_connections=max_pool_size,
                    max_connections=max_pool_size * 2,
                ),
            )
        except Exception:
            self._httpx_client = None

    async def __aenter__(self) -> "AsyncRugShieldClient":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        self._fallback_pool.close()
        if self._httpx_client is not None:
            await self._httpx_client.aclose()
            self._httpx_client = None

    async def close(self) -> None:
        await self.aclose()

    async def _raw_request_async(
        self,
        method: str,
        route: str,
        body_bytes: Optional[bytes],
        headers: Mapping[str, str],
        timeout: float,
    ) -> Tuple[int, Dict[str, str], bytes]:
        if self._httpx_client is not None:
            resp = await self._httpx_client.request(
                method,
                route,
                content=body_bytes,
                headers=dict(headers),
                timeout=timeout,
            )
            return int(resp.status_code), dict(resp.headers), bytes(resp.content)
        return await asyncio.to_thread(
            self._fallback_pool.request,
            method,
            route,
            body_bytes,
            headers,
            timeout,
        )

    async def warmup(self) -> bool:
        try:
            status, _, _ = await self._raw_request_async(
                "GET",
                "/api/health",
                None,
                {"Accept": "application/json", "X-Agent-Id": self.agent_id},
                timeout=min(2.0, self.audit_timeout),
            )
            return status < 500
        except Exception:
            return False

    async def _execute_cascade_async(
        self,
        routes: Sequence[str],
        payload: Dict[str, Any],
        timeout: float,
        wallet: Optional[str] = None,
        payment_signature: Optional[str] = None,
        pro_pass_token: Optional[str] = None,
        allow_404_return: bool = False,
    ) -> Tuple[int, Dict[str, Any]]:
        t0 = time.perf_counter()
        body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        had_explicit_payment = bool(payment_signature or pro_pass_token or self.pro_pass_token)

        last_status = 404
        last_body: Dict[str, Any] = {"ok": False, "error": "No upstream route matched"}

        for idx, route in enumerate(routes):
            headers = self._build_request_headers(
                wallet=wallet,
                payment_signature=payment_signature,
                pro_pass_token=pro_pass_token,
            )
            status, resp_headers, raw_resp = await self._raw_request_async(
                "POST", route, body_bytes, headers, timeout=timeout
            )

            if status in (404, 405) and idx + 1 < len(routes):
                last_status = status
                continue
            if status in (404, 405) and allow_404_return:
                return status, {"ok": False, "status": status}

            auto_paid_info: Optional[Dict[str, Any]] = None
            if status == 402:
                with self._state_lock:
                    self.free_pings_used = max(self.free_pings_used, self.free_pings_limit)
                    self.free_pings_remaining = 0
                challenge = parse_402_challenge(
                    resp_headers,
                    raw_resp,
                    fallback_used_pings=self.free_pings_limit,
                    expected_treasury=self.expected_treasury,
                )
                if not self.auto_payer.can_auto_pay or payment_signature:
                    err = X402PaymentRequired(challenge, headers=resp_headers, body=challenge.raw_body)
                    if self.raise_on_402:
                        raise err
                    err_dict = err.to_dict()
                    err_dict["latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
                    err_dict["quota"] = self.get_quota_state()
                    return 402, err_dict

                auto_paid_info = await self.auto_payer.execute_payment_async(challenge)
                retry_headers = self._build_request_headers(
                    wallet=wallet,
                    pro_pass_token=pro_pass_token,
                    auto_paid_info=auto_paid_info,
                )
                status, resp_headers, raw_resp = await self._raw_request_async(
                    "POST", route, body_bytes, retry_headers, timeout=timeout
                )
                if status == 402:
                    retry_challenge = parse_402_challenge(
                        resp_headers,
                        raw_resp,
                        fallback_used_pings=self.free_pings_limit,
                        expected_treasury=self.expected_treasury,
                    )
                    err = X402PaymentRequired(
                        retry_challenge, headers=resp_headers, body=retry_challenge.raw_body
                    )
                    if self.raise_on_402:
                        raise err
                    return 402, err.to_dict()

            try:
                parsed = json.loads(raw_resp.decode("utf-8", errors="replace")) if raw_resp else {}
                if not isinstance(parsed, dict):
                    parsed = {"data": parsed}
            except Exception:
                parsed = {"ok": status < 400, "raw": raw_resp.decode("utf-8", errors="replace")}

            latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            if 200 <= status < 300:
                pro_cached = self._record_200_headers_and_body(
                    resp_headers,
                    parsed,
                    was_paid_or_token=(had_explicit_payment or auto_paid_info is not None),
                )
                return status, self._decorate_response(parsed, latency_ms, auto_paid_info, pro_cached)

            parsed.setdefault("ok", False)
            parsed["status"] = status
            parsed["latency_ms"] = latency_ms
            return status, parsed

        return last_status, last_body

    async def audit_solana_token_10_layer(
        self,
        mint: str,
        pool_address: Optional[str] = None,
        wallet: Optional[str] = None,
        payment_signature: Optional[str] = None,
        pro_pass_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        mint_clean = (mint or "").strip()
        if not mint_clean:
            raise ValueError("mint is required for audit_solana_token_10_layer")
        payload: Dict[str, Any] = {
            "mint": mint_clean,
            "user_initiated": False,
        }
        if pool_address:
            payload["pool_address"] = pool_address.strip()
        if wallet:
            payload["wallet"] = wallet.strip()

        _, res = await self._execute_cascade_async(
            routes=self.audit_routes,
            payload=payload,
            timeout=self.audit_timeout,
            wallet=wallet,
            payment_signature=payment_signature,
            pro_pass_token=pro_pass_token,
        )
        if res.get("ok") and "safe_to_buy" not in res and "score" in res:
            res["safe_to_buy"] = bool(
                int(res.get("score") or 0) >= 75 and not res.get("hidden_pda_rent_trap")
            )
        return res

    async def simulate_solana_tx_drain(
        self,
        transaction: str,
        wallet: Optional[str] = None,
        encoding: str = "base64",
        payment_signature: Optional[str] = None,
        pro_pass_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        tx_clean = (transaction or "").strip()
        if not tx_clean:
            raise ValueError("transaction is required for simulate_solana_tx_drain")
        enc = (encoding or "base64").strip().lower()
        if enc not in ("base64", "base58"):
            raise ValueError(f"Unsupported transaction encoding {encoding!r}; expected 'base64' or 'base58'.")

        payload: Dict[str, Any] = {
            "transaction": tx_clean,
            "encoding": enc,
        }
        if wallet:
            payload["wallet"] = wallet.strip()

        t0 = time.perf_counter()
        status, res = await self._execute_cascade_async(
            routes=self.simulate_routes,
            payload=payload,
            timeout=self.timeout,
            wallet=wallet,
            payment_signature=payment_signature,
            pro_pass_token=pro_pass_token,
            allow_404_return=True,
        )
        if status in (404, 405):
            local_res = inspect_solana_transaction_local(tx_clean, encoding=enc, wallet=wallet)
            local_res["latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
            local_res["quota"] = self.get_quota_state()
            local_res["fallback_mode"] = "local_wire_inspector"
            return local_res
        return res

    async def scan_wallet_unclaimed_sol(
        self,
        wallet: str,
        include_token_2022: bool = True,
        payment_signature: Optional[str] = None,
        pro_pass_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        wallet_clean = (wallet or "").strip()
        if not wallet_clean:
            raise ValueError("wallet is required for scan_wallet_unclaimed_sol")
        payload: Dict[str, Any] = {
            "wallet": wallet_clean,
            "include_token_2022": bool(include_token_2022),
            "user_initiated": False,
            "auto_collect": False,
        }
        status, res = await self._execute_cascade_async(
            routes=self.scan_wallet_routes,
            payload=payload,
            timeout=self.timeout,
            wallet=wallet_clean,
            payment_signature=payment_signature,
            pro_pass_token=pro_pass_token,
        )
        if 200 <= status < 300 and not include_token_2022 and res.get("ok"):
            return _filter_token_2022_wallet_scan(res)
        return res
