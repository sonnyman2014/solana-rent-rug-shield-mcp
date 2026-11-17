# @rentandrugshield/mcp-server

Official Model Context Protocol (MCP) server and TypeScript SDK for [Rent & Rug Shield](https://rentandrugshield.com) on Solana Mainnet. Built for autonomous trading agents, sniper bots, AI coding assistants, and wallet security pipelines requiring sub-120ms pre-buy token safety checks, Layer 9 Inner CPI transaction drain simulation, and read-only unclaimed ATA SOL rent discovery with native Solana `x402` HTTP 402 auto-upgrade.

## Core Capabilities

* **`audit_solana_token_10_layer`**: Sub-120ms pre-buy 10-layer Solana token safety gate over persistent keep-alive HTTP/HTTPS connection pools. Evaluates mint authority, freeze authority, Token-2022 extensions (`transferFeeConfig`, `permanentDelegate`, `transferHook`, `defaultAccountState`), liquidity lock/burn status, holder cluster concentration, exit liquidity solvency, Inner CPI rent traps, pool age, and orderflow velocity.
* **`simulate_solana_tx_drain`**: Pre-sign Layer 9 Inner CPI drainer check for base64 or base58 serialized Solana transactions. Detects stealth `SetAuthority` ownership hijacks, `Approve` token allowance drainers, `SystemProgram` account reassignments, creator-vault rent traps, and unexpected SOL balance deltas before signing.
* **`scan_wallet_unclaimed_sol`**: 100% read-only Solana wallet scanner for SPL Token and Token-2022 Associated Token Accounts (ATAs). Discovers reclaimable SOL locked in empty and dust accounts with exact lamport, SOL, and USD breakdowns without ever requesting private keys for scanning.

## 10 Free Pings and Solana x402 Machine Auto-Pay

Every agent session (`X-Agent-Id`) receives **10 free pings** out of the box against `https://rentandrugshield.com`. On the 11th unpaid request, the gateway returns an `x402` v1 HTTP `402 Payment Required` challenge (`Payment-Required` base64 JSON header and body) targeting the verified treasury wallet:

* **Treasury Address**: `89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1`
* **Option A (`option_a_pro_pass`)**: `0.026 SOL` (`26000000` lamports, `$1.99` Unlimited Pro Pass). Issues a signed `X-Pro-Pass-Token` cached automatically by the MCP server so all subsequent calls execute with unlimited access and zero extra transfers.
* **Option B (`option_b_single_scan`)**: `0.0003 SOL` (`300000` lamports, `~$0.02` instant single scan). Unlocks 1 verified request with on-chain anti-replay protection.

When `SOLANA_PRIVATE_KEY` (or `X402_SOLANA_PRIVATE_KEY`) is configured, `@rentandrugshield/mcp-server` automatically builds and broadcasts the `SystemProgram.transfer` transaction to `89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1`, attaches `X-Payment` (base64 JSON) plus `X-Solana-Tx-Signature`, caches `X-Pro-Pass-Token` when using Option A, and retries the tool call transparently. When no private key is configured, the tool returns a structured `x402` payment challenge with exact Option A and Option B instructions so callers can retry manually with `payment_signature` or `pro_pass_token`.

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

## Quick Start (NPX and CLI)

Run directly over MCP `stdio`:

```bash
npx -y @rentandrugshield/mcp-server
```

Or install globally:

```bash
npm install -g @rentandrugshield/mcp-server
rentandrugshield-mcp
```

## MCP Client Configuration (Claude Desktop, Cursor, Windsurf, Cline)

### Read-Only + 10 Free Pings Mode (No Private Key Required)

```json
{
  "mcpServers": {
    "rentandrugshield": {
      "command": "npx",
      "args": ["-y", "@rentandrugshield/mcp-server"],
      "env": {
        "RENTSHIELD_API_URL": "https://rentandrugshield.com"
      }
    }
  }
}
```

### Autonomous Solana x402 Auto-Upgrade Mode

```json
{
  "mcpServers": {
    "rentandrugshield": {
      "command": "npx",
      "args": ["-y", "@rentandrugshield/mcp-server"],
      "env": {
        "RENTSHIELD_API_URL": "https://rentandrugshield.com",
        "SOLANA_PRIVATE_KEY": "<YOUR_BASE58_OR_JSON_BYTE_ARRAY_KEY>",
        "X402_OPTION": "option_a_pro_pass",
        "SOLANA_RPC_URL": "https://api.mainnet-beta.solana.com"
      }
    }
  }
}
```

## Environment Variables

* `RENTSHIELD_API_URL`: Upstream gateway base URL (defaults to `https://rentandrugshield.com`).
* `SOLANA_PRIVATE_KEY` (alias `X402_SOLANA_PRIVATE_KEY`): Optional Solana secret key (base58 string or JSON byte array) enabling automatic HTTP `402` `x402` upgrades.
* `X402_OPTION`: Auto-pay tier (`option_a_pro_pass` for `0.026 SOL` Unlimited Pro Pass or `option_b_single_scan` for `0.0003 SOL` single scan; defaults to `option_a_pro_pass`).
* `SOLANA_RPC_URL`: Solana RPC endpoint used when broadcasting `x402` payment transfers (defaults to `https://api.mainnet-beta.solana.com`).
* `X402_PRO_PASS_TOKEN` (alias `RENTSHIELD_PRO_PASS_TOKEN`): Optional pre-issued `X-Pro-Pass-Token` header value.
* `X402_AGENT_ID` (alias `RENTSHIELD_AGENT_ID`): Optional persistent `X-Agent-Id` identifier.
* `RENTSHIELD_AUDIT_TIMEOUT_MS`: Fast socket timeout in milliseconds for `audit_solana_token_10_layer` (defaults to `3500`).
* `X402_MOCK_SIGNER`: Set to `1` in local integration tests to generate deterministic 88-character base58 mock signatures (`5MockA...` / `5MockB...`) without live mainnet RPC broadcasts.

## Tool Schemas

### 1. `audit_solana_token_10_layer`

* `mint` (`string`, required): Solana SPL or Token-2022 token mint address (base58).
* `pool_address` (`string`, optional): Liquidity pool or AMM pair address hint.
* `wallet` (`string`, optional): Caller Solana wallet public key.
* `payment_signature` (`string`, optional): Confirmed Solana transaction signature for manual `x402` retry.
* `pro_pass_token` (`string`, optional): `X-Pro-Pass-Token` from Option A Pro Pass.

### 2. `simulate_solana_tx_drain`

* `transaction` (`string`, required): Unsigned or signed serialized Solana transaction payload.
* `wallet` (`string`, optional): Signer Solana wallet public key to protect.
* `encoding` (`"base64" | "base58"`, optional): Serialization format (defaults to `"base64"`).
* `payment_signature` (`string`, optional): Confirmed Solana transaction signature for manual `x402` retry.
* `pro_pass_token` (`string`, optional): `X-Pro-Pass-Token` from Option A Pro Pass.

### 3. `scan_wallet_unclaimed_sol`

* `wallet` (`string`, required): Solana wallet public key (base58) to scan read-only.
* `include_token_2022` (`boolean`, optional): Include Token-2022 accounts alongside SPL Token accounts (defaults to `true`).
* `payment_signature` (`string`, optional): Confirmed Solana transaction signature for manual `x402` retry.
* `pro_pass_token` (`string`, optional): `X-Pro-Pass-Token` from Option A Pro Pass.

## Programmatic TypeScript Usage

```ts
import { RentShieldClient } from "@rentandrugshield/mcp-server";

const client = new RentShieldClient({
  apiUrl: "https://rentandrugshield.com",
  x402Option: "option_a_pro_pass"
});

const audit = await client.auditSolanaToken10Layer({
  mint: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"
});
console.log(audit.ok, audit.latencyMs, audit.data);

client.destroy();
```

## License

MIT
