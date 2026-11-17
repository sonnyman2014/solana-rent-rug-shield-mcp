# solana-rug-shield

Python SDK (`RugShieldClient` and `AsyncRugShieldClient`) and Model Context Protocol (`MCP`) `stdio` JSON-RPC 2.0 server for [Rent and Rug Shield](https://rentandrugshield.com).

Built for autonomous Solana trading agents, wallet co-pilots, and IDE assistants requiring a sub-120ms pre-buy token safety gate, Layer 9 Inner CPI drainer simulation, read-only ATA rent scanning, and frictionless Solana `x402` HTTP 402 micropayments.

## Core Capabilities

* `audit_solana_token_10_layer`: Sub-120ms 10-layer pre-buy Solana SPL and Token-2022 safety gate powered by a persistent `TCP_NODELAY` HTTP/1.1 keep-alive connection pool.
* `simulate_solana_tx_drain`: Layer 9 Inner CPI drainer, authority hijack (`SetAuthority`, `Approve`), and hidden PDA rent trap simulator for Base64 or Base58 transactions.
* `scan_wallet_unclaimed_sol`: Strictly read-only Solana wallet scanner for unclaimed SOL rent locked inside empty ATAs, dead rug accounts, and frozen Token-2022 traps (`user_initiated=false`, `auto_collect=false`).
* Built-in `10` Free Pings per `X-Agent-Id` plus automatic Solana `x402` HTTP `402` upgrade to treasury `89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1`.

## Installation

Zero mandatory third-party runtime dependencies are required for standard usage and MCP `stdio` operation:

```bash
pip install solana-rug-shield
```

Optional extras for native `solders` C/Rust cryptography or `httpx` async pooling:

```bash
pip install "solana-rug-shield[solana,async]"
```

## Zero-Install Remote Streamable HTTP MCP (`https://rentandrugshield.com/mcp`)

Connect any Streamable HTTP MCP client (`Claude`, `Cursor`, `Windsurf`, `Cline`, `OpenAI Agents`, `LangGraph`) directly with **zero local installation**:

```json
{
  "mcpServers": {
    "rentandrugshield": {
      "type": "streamable-http",
      "url": "https://rentandrugshield.com/mcp"
    }
  }
}
```

* **Zero-Install Streamable HTTP Endpoint**: `https://rentandrugshield.com/mcp` (`MCP 2025-03-26` and `2024-11-05`)
* **Discovery Manifests**: `https://rentandrugshield.com/.well-known/mcp.json` and `https://rentandrugshield.com/.well-known/x402`
* **Solana `x402` V1 & V2 Auto-Pay**: 10 free pings per `X-Agent-Id`, then `0.026 SOL` (`$1.99` Unlimited Pro Pass) or `0.0003 SOL` (`~$0.02` single scan) to `89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1` via `PAYMENT-SIGNATURE` or `X-Payment`.

## Quickstart (Synchronous Python SDK)

```python
from solana_rug_shield import RugShieldClient, X402PaymentRequired

with RugShieldClient() as client:
    # 1. Sub-120ms 10-layer pre-buy token audit
    audit = client.audit_solana_token_10_layer(
        mint="So11111111111111111111111111111111111111112"
    )
    print(audit["safe_to_buy"], audit["score"], audit["latency_ms"])

    # 2. Layer 9 Inner CPI transaction drain check
    sim = client.simulate_solana_tx_drain(
        transaction="AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAED...",
        encoding="base64",
    )
    print(sim["safe"], sim["verdict"])

    # 3. Read-only unclaimed ATA SOL rent scan
    rent = client.scan_wallet_unclaimed_sol(
        wallet="89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1",
        include_token_2022=True,
    )
    print(rent["total_reclaimable_sol"])
```

## Quickstart (Asynchronous Python SDK)

```python
import asyncio
from solana_rug_shield import AsyncRugShieldClient

async def run_checks() -> None:
    async with AsyncRugShieldClient(x402_option="option_a_pro_pass") as client:
        res = await client.audit_solana_token_10_layer(
            mint="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        )
        print(res["verdict"], res["quota"])

asyncio.run(run_checks())
```

## 10 Free Pings and Solana x402 Auto-Upgrade

Every agent receives `10` free pings tracked via `X-Agent-Id`. On the `11th` unpaid request, the gateway returns HTTP `402 Payment Required` with `Payment-Required` and `X-Payment-Required` Base64 JSON headers targeting treasury `89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1`:

* **Option A (`option_a_pro_pass`)**: `0.026 SOL` (`26000000` lamports, `$1.99` Unlimited Pro Pass). Returns a signed `X-Pro-Pass-Token` that `RugShieldClient` automatically caches in memory for unlimited subsequent `200 OK` calls without re-paying.
* **Option B (`option_b_single_scan`)**: `0.0003 SOL` (`300000` lamports, `$0.02` instant single scan). Unlocks `1` verified request with strict on-chain signature anti-replay protection.

### Automatic x402 Signing Modes

* **Environment Private Key**: Set `SOLANA_PRIVATE_KEY` (or `X402_SOLANA_PRIVATE_KEY`) as a Base58 secret key, JSON byte array `[12, 34, ...]`, or hex seed. Select tier via `X402_OPTION=option_a_pro_pass` or `X402_OPTION=option_b_single_scan`. The SDK builds an Ed25519-signed `SystemProgram.transfer` to `89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1`, submits via `SOLANA_RPC_URL`, and retries transparently with `X-Payment` and `X-Solana-Tx-Signature`.
* **Custom Signer Callback**: Pass `payment_signer=my_callback` to `RugShieldClient(...)` or `AsyncRugShieldClient(...)` to sign via hardware enclave, KMS, or custodial agent wallet.
* **Offline E2E Test Signer**: Set `X402_MOCK_SIGNER=1` in local test harnesses to emit deterministic 88-character Base58 signatures (`5MockA...` and `5MockB...`).
* **Unconfigured Signer Fallback**: When no signer or private key is configured, `RugShieldClient` raises `X402PaymentRequired` containing structured Option A (`0.026 SOL`) and Option B (`0.0003 SOL`) instructions (or returns `err.to_dict()` when `raise_on_402=False`).

## MCP Stdio Server Configuration

Launch the JSON-RPC 2.0 MCP server directly from the CLI:

```bash
solana-rug-shield --mcp-stdio
```

Or via Python module execution:

```bash
python3 -m solana_rug_shield --mcp-stdio
```

### Claude Desktop / Cursor / Windsurf Configuration

```json
{
  "mcpServers": {
    "solana-rug-shield": {
      "command": "solana-rug-shield",
      "args": ["--mcp-stdio"],
      "env": {
        "RENTSHIELD_API_URL": "https://rentandrugshield.com",
        "X402_OPTION": "option_a_pro_pass"
      }
    }
  }
}
```

## Environment Variables

* `RENTSHIELD_API_URL`: Upstream gateway base URL (defaults to `https://rentandrugshield.com`).
* `SOLANA_PRIVATE_KEY` / `X402_SOLANA_PRIVATE_KEY`: Optional Solana keypair for automatic HTTP `402` upgrades.
* `SOLANA_RPC_URL` / `X402_SOLANA_RPC_URL`: Solana RPC endpoint for `sendTransaction` (defaults to `https://api.mainnet-beta.solana.com`).
* `X402_OPTION`: Preferred auto-pay tier (`option_a_pro_pass` for `0.026 SOL` Unlimited Pro Pass or `option_b_single_scan` for `0.0003 SOL` single scan).
* `X402_PRO_PASS_TOKEN`: Optional pre-provisioned `X-Pro-Pass-Token`.
* `X402_AGENT_ID`: Optional custom `X-Agent-Id` identifier.
* `X402_MOCK_SIGNER`: Set to `1` for deterministic offline E2E testing.

## License

MIT License. Copyright (c) 2026 Rent and Rug Shield (`https://rentandrugshield.com`).
