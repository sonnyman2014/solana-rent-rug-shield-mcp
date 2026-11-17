# Solana x402 AutoPay Middleware (`x402_solana_middleware.py`)

Production Solana `x402` (`HTTP 402 Payment Required`) machine autopay middleware and gatekeeper built for `https://rentandrugshield.com` (`rent_shield_app/server.py`).

## Treasury and Pricing Contract

* **Solana Mainnet Treasury**: `89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1`
* **Free Discovery Quota**: `10` free pings per client (`X-Agent-Id`, `X-API-Key`, or client IP) returning `X-Free-Pings-Limit: 10`, `X-Free-Pings-Used`, and `X-Free-Pings-Remaining` headers
* **Option A (`option_a_pro_pass`)**: `0.026 SOL` (`26000000` lamports, `$1.99` Unlimited Pro Pass) issuing an HMAC SHA256 signed `X-Pro-Pass-Token` header for unlimited subsequent `200 OK` calls without paying again
* **Option B (`option_b_single_scan`)**: `0.0003 SOL` (`300000` lamports, `$0.02` instant single scan) granting `1` verified request per unique Solana transaction signature with strict replay prevention

## HTTP 402 Challenge Wire Format

On the 11th unpaid ping, the middleware responds with `HTTP 402 Payment Required` and the following headers:

* `WWW-Authenticate`: `x402 network="solana:mainnet-beta", treasury="89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1", option_a_sol="0.026", option_b_sol="0.0003"`
* `Payment-Required` and `X-Payment-Required`: Base64 encoded UTF8 JSON `x402` v1 challenge listing `option_a_pro_pass` (`26000000` lamports) and `option_b_single_scan` (`300000` lamports)
* `X-402-Treasury`: `89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1`
* `X-Free-Pings-Used`: `10`
* `X-Free-Pings-Remaining`: `0`

## Accepted Payment Headers

* `X-Payment`: Base64 JSON `{x402Version: 1, scheme: "exact", network: "solana-mainnet", payload: {signature, payer, option, lamports, payTo}}`
* `Payment-Signature`: Base64 JSON `x402` payload or raw base58 Solana transaction signature
* `X-Solana-Tx-Signature`: Raw base58 Solana transaction signature (`auto` resolves Option A at `>= 26000000` lamports or Option B at `>= 300000` lamports)
* `X-Pro-Pass-Token`: Signed HMAC token returned after an Option A `0.026 SOL` upgrade

## OnChain RPC Verification Rules

`SolanaRpcVerifier` calls Solana JSON RPC `getTransaction` (`confirmed`, `jsonParsed`, `maxSupportedTransactionVersion: 0`) and enforces:

* Transaction exists on chain and `meta.err` is `None`
* `accountKeys` (including v0 `loadedAddresses`) includes `89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1`
* Net treasury balance delta `postBalances[idx]` minus `preBalances[idx]` meets or exceeds `26000000` lamports (`Option A`) or `300000` lamports (`Option B`)
* `SignatureReplayLedger` atomically records every redeemed signature so no signature can ever be replayed

## Framework Integration (`aiohttp.web`, ASGI, WSGI)

```python
from aiohttp import web
from x402_solana_middleware import (
    MockSolanaRpcVerifier,
    X402SolanaGatekeeper,
    attach_x402_to_aiohttp_app,
    create_x402_aiohttp_middleware,
    create_x402_asgi_middleware,
    create_x402_wsgi_middleware,
)

# Attach idempotently to rent_shield_app/server.py create_app()
app = web.Application()
attach_x402_to_aiohttp_app(app)

# Or build with deterministic offline E2E mock verifier
e2e_gatekeeper = X402SolanaGatekeeper(
    rpc_verifier=MockSolanaRpcVerifier.for_e2e_harness()
)
e2e_app = web.Application(middlewares=[create_x402_aiohttp_middleware(e2e_gatekeeper)])
```

## Running Offline Unit Tests

```bash
python3 x402_middleware/test_x402_solana_middleware.py
```
