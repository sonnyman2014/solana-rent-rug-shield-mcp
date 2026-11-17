# Solana Rent & Rug Shield on MCP.so (`@rentandrugshield/mcp-server` & `solana-rug-shield`)

* **Name:** Solana Rent and Rug Shield MCP Gateway
* **Type:** Remote MCP server (Streamable HTTP) and Local Stdio (`npx` and `pip`)
* **Description:** Production Solana security MCP server delivering a `<120ms` 10-layer pre-buy token anti-rug safety gate (`audit_solana_token_10_layer`), Layer 9 Inner CPI transaction drainer simulator (`simulate_solana_tx_drain`), and strictly read-only SPL and Token-2022 unclaimed ATA SOL rent scanner (`scan_wallet_unclaimed_sol`) with 10 free pings and native Solana `x402` machine auto-pay.
* **Endpoint:** https://rentandrugshield.com/mcp (and live dynamic Streamable HTTP transport https://rolled-raleigh-chair-shakespeare.trycloudflare.com/mcp)
* **Official MCP Registry:** `com.rentandrugshield/mcp-server` and `io.github.sonnyman2014/solana-rent-rug-shield-mcp`
* **Authentication:** None required for 10 free pings per `X-Agent-Id`; automatic Solana `x402` V1 and V2 (`PAYMENT-SIGNATURE` and `X-Payment`) settlement after free tier
* **Homepage:** https://rentandrugshield.com
* **Repository:** https://github.com/sonnyman2014/solana-rent-rug-shield-mcp
* **Release Packages (`v1.0.0`):** `npx -y https://github.com/sonnyman2014/solana-rent-rug-shield-mcp/releases/download/v1.0.0/rentandrugshield-mcp-server-1.0.0.tgz` and `pip install https://github.com/sonnyman2014/solana-rent-rug-shield-mcp/releases/download/v1.0.0/solana_rug_shield-1.0.0-py3-none-any.whl`
* **Category:** Security, Blockchain, Developer Tools
* **Tags:** solana, mcp, x402, defi-security, rug-check, token-2022, ata-rent, ai-agents
* **Pricing:** 10 free pings included with no API key or credit card; `0.026 SOL` (`$1.99` Unlimited Pro Pass) or `0.0003 SOL` (`~$0.02` single scan) to Solana treasury `89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1`


Official MCP.so submission listing for Solana Rent & Rug Shield, delivering institutional-grade pre-buy token rug auditing (`<120ms`), Layer 9 Inner CPI transaction drainer simulation, and read-only wallet ATA SOL rent scanning via [https://rentandrugshield.com](https://rentandrugshield.com) with native Solana `x402` auto-pay.

* **MCP.so Slug**: `solana-rent-and-rug-shield` (`registry/mcp_so_submission.json`)
* **Supported Ecosystems**: Node.js (`@rentandrugshield/mcp-server` on npm) and Python (`solana-rug-shield` on PyPI)

## Distribution Packages

* **TypeScript / NPX MCP Server**: `@rentandrugshield/mcp-server` (`npx -y @rentandrugshield/mcp-server` or binary `rentandrugshield-mcp`)
* **Python / PyPI SDK & MCP Server**: `solana-rug-shield` (`pip install solana-rug-shield` with built-in MCP `stdio` server mode and sync/async Python SDK)
* **Production Upstream Gateway**: [https://rentandrugshield.com](https://rentandrugshield.com)
* **Official MCP Registry Namespace**: `io.github.sonnyman2014/solana-rent-rug-shield-mcp` and `com.rentandrugshield/mcp-server`

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

## Quick Start Commands

### Launch via NPX (`@rentandrugshield/mcp-server`)

```bash
npx -y @rentandrugshield/mcp-server
```

### Install and Launch via PyPI (`solana-rug-shield`)

```bash
pip install solana-rug-shield
solana-rug-shield --mcp-stdio
```

### Direct Python SDK Usage (`solana-rug-shield`)

```python
from solana_rug_shield import RugShieldClient

client = RugShieldClient(api_url="https://rentandrugshield.com")

audit = client.audit_solana_token_10_layer(
    mint="So11111111111111111111111111111111111111112"
)
sim = client.simulate_solana_tx_drain(transaction="AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAED")
rent = client.scan_wallet_unclaimed_sol(
    wallet="89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1",
    include_token_2022=True,
)
```

## Core Solana Security Tools (3 MCP Tools)

### 1. `audit_solana_token_10_layer` (`<120ms` Pre-Buy Token Safety Gate)

* **Purpose**: High-speed `<120ms` warm-socket pre-buy anti-rug safety gate powered by persistent HTTP keep-alive connection pooling for autonomous sniper bots, DeFi execution agents, and trading terminals.
* **10 Security Layers Evaluated**: Mint authority status, freeze authority status, Token-2022 permanent delegate hooks, Token-2022 transfer fee mutations, non-transferable / close-authority traps, liquidity pool lock and burn ratio, top holder cluster concentration, metadata mutability, creator rug history, and live sellability verification (returning a `0` to `100` safety score plus actionable risk flags).
* **Inputs**: `mint` (required base58 mint address), optional `pool_address`, `wallet`, `payment_signature`, `pro_pass_token`.

### 2. `simulate_solana_tx_drain` (Layer 9 Inner CPI Drainer Check)

* **Purpose**: Pre-signing transaction firewall that simulates serialized Solana transactions (`base64` or `base58`) and inspects full Layer 9 Inner Cross-Program Invocations (`Inner CPI`) before an agent or user wallet signs.
* **Threats Blocked**: Stealth `SetAuthority` account ownership takeovers, hidden SPL / Token-2022 `Approve` delegate drains, multi-hop wrapper program SOL sweeps, and malicious CPI callback hooks disguised inside benign swap instructions.
* **Inputs**: `transaction` (required serialized transaction), optional `wallet`, `encoding` (`base64` or `base58`), `payment_signature`, `pro_pass_token`.

### 3. `scan_wallet_unclaimed_sol` (Read-Only ATA Rent Check)

* **Purpose**: Zero-custody, strictly read-only Mainnet wallet scanner that discovers reclaimable rent-exempt SOL locked in empty SPL (`Tokenkeg`) and `Token-2022` Associated Token Accounts (`ATAs`), dust accounts, and PumpSwap / Pump volume accumulator PDAs.
* **Safety Guarantee**: Requires only a public base58 `wallet` address; never requests private keys for scanning and reports exact account counts plus net reclaimable SOL (`95%` user payout structure on [https://rentandrugshield.com](https://rentandrugshield.com)).
* **Inputs**: `wallet` (required base58 wallet address), optional `include_token_2022` (boolean, default `true`), `payment_signature`, `pro_pass_token`.

## 10 Free Pings + Native Solana `x402` Machine Auto-Pay

Every agent and developer session connecting to `https://rentandrugshield.com` receives **10 free pings** out of the box with zero API keys, zero credit cards, and zero setup.

When the 11th unpaid request triggers `HTTP 402 Payment Required`, the gateway returns standard `Payment-Required` and `X-Payment-Required` base64 JSON `x402` v1 challenges targeting verified Solana Mainnet treasury **`89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1`** with two instant machine-payable tiers:

* **Option A (`option_a_pro_pass` / Unlimited Pro Pass)**: **`0.026 SOL`** (`26,000,000` lamports, **`$1.99` Unlimited Pro Pass**). Issues a signed `X-Pro-Pass-Token` cached automatically by `@rentandrugshield/mcp-server` and `solana-rug-shield` so all subsequent tool calls resolve `200 OK` with zero per-call settlement overhead.
* **Option B (`option_b_single_scan` / Instant Single Scan)**: **`0.0003 SOL`** (`300,000` lamports, **`$0.02` single scan**). Unlocks one immediate verified scan per unique Solana Mainnet transaction signature enforced by strict on-chain anti-replay verification.
* **Autonomous Agent Settlement**: When `SOLANA_PRIVATE_KEY` (or `X402_SOLANA_PRIVATE_KEY`) is configured in the MCP environment, both `@rentandrugshield/mcp-server` and `solana-rug-shield` automatically build and broadcast the exact SOL transfer to `89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1`, attach the base64 `X-Payment` payload plus `X-Solana-Tx-Signature`, and retry the tool call transparently in a single turn.
* **Keyless / Manual Settlement**: When no private key is configured, the MCP tool returns the structured `x402` challenge instructions so human operators or external signers can pass `payment_signature` or `pro_pass_token` directly on retry.

## Environment Variables

* `RENTSHIELD_API_URL`: Upstream gateway base URL (defaults to `https://rentandrugshield.com`).
* `SOLANA_PRIVATE_KEY`: Optional base58 string or JSON byte array `[...]` for automatic `x402` HTTP 402 SOL settlement.
* `X402_SOLANA_PRIVATE_KEY`: Optional dedicated alias for `SOLANA_PRIVATE_KEY`.
* `X402_OPTION`: Select `option_a_pro_pass` (`0.026 SOL` `$1.99` Unlimited Pro Pass, default) or `option_b_single_scan` (`0.0003 SOL` `$0.02` single scan).
* `RENTSHIELD_PRO_PASS_TOKEN`: Optional pre-provisioned `X-Pro-Pass-Token` for instant unlimited Pro Pass access.
* `SOLANA_RPC_URL`: Solana Mainnet RPC URL used when broadcasting automatic `x402` transfers (defaults to `https://api.mainnet-beta.solana.com`).

## Client and Agent Framework Configurations

### 1. Claude Desktop (`claude_desktop_config.json`)

#### Option 1A: Node / NPX (`@rentandrugshield/mcp-server`)

```json
{
  "mcpServers": {
    "rentandrugshield": {
      "command": "npx",
      "args": ["-y", "@rentandrugshield/mcp-server"],
      "env": {
        "RENTSHIELD_API_URL": "https://rentandrugshield.com",
        "X402_OPTION": "option_a_pro_pass"
      }
    }
  }
}
```

#### Option 1B: Python / PyPI (`solana-rug-shield`)

```json
{
  "mcpServers": {
    "rentandrugshield": {
      "command": "uvx",
      "args": ["solana-rug-shield", "--mcp-stdio"],
      "env": {
        "RENTSHIELD_API_URL": "https://rentandrugshield.com",
        "X402_OPTION": "option_a_pro_pass"
      }
    }
  }
}
```

### 2. Cursor (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "rentandrugshield": {
      "command": "npx",
      "args": ["-y", "@rentandrugshield/mcp-server"],
      "env": {
        "RENTSHIELD_API_URL": "https://rentandrugshield.com",
        "SOLANA_PRIVATE_KEY": "YOUR_OPTIONAL_AGENT_BASE58_KEY",
        "X402_OPTION": "option_a_pro_pass"
      }
    }
  }
}
```

### 3. Windsurf (`~/.codeium/windsurf/mcp_config.json`)

```json
{
  "mcpServers": {
    "rentandrugshield": {
      "command": "npx",
      "args": ["-y", "@rentandrugshield/mcp-server"],
      "env": {
        "RENTSHIELD_API_URL": "https://rentandrugshield.com",
        "X402_OPTION": "option_a_pro_pass"
      }
    }
  }
}
```

### 4. Cline (`cline_mcp_settings.json`)

```json
{
  "mcpServers": {
    "rentandrugshield": {
      "command": "npx",
      "args": ["-y", "@rentandrugshield/mcp-server"],
      "disabled": false,
      "autoApprove": [
        "audit_solana_token_10_layer",
        "simulate_solana_tx_drain",
        "scan_wallet_unclaimed_sol"
      ],
      "env": {
        "RENTSHIELD_API_URL": "https://rentandrugshield.com",
        "X402_OPTION": "option_b_single_scan"
      }
    }
  }
}
```

### 5. OpenAI Agents SDK (`openai-agents`)

```python
import asyncio
from agents import Agent, Runner
from agents.mcp import MCPServerStdio


async def main() -> None:
    async with MCPServerStdio(
        name="RentAndRugShield",
        params={
            "command": "npx",
            "args": ["-y", "@rentandrugshield/mcp-server"],
            "env": {
                "RENTSHIELD_API_URL": "https://rentandrugshield.com",
                "X402_OPTION": "option_a_pro_pass",
            },
        },
    ) as rug_shield_mcp:
        agent = Agent(
            name="SolanaExecutionGuard",
            instructions=(
                "Always call audit_solana_token_10_layer before any token swap and "
                "simulate_solana_tx_drain before signing any serialized transaction."
            ),
            mcp_servers=[rug_shield_mcp],
        )
        result = await Runner.run(
            agent,
            "Audit Solana mint So11111111111111111111111111111111111111112 and report safety score.",
        )
        print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
```

### 6. LangChain (`langchain-mcp-adapters` & `solana-rug-shield`)

```python
import asyncio
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent


async def run_guard() -> None:
    client = MultiServerMCPClient(
        {
            "rentandrugshield": {
                "command": "npx",
                "args": ["-y", "@rentandrugshield/mcp-server"],
                "transport": "stdio",
                "env": {
                    "RENTSHIELD_API_URL": "https://rentandrugshield.com",
                    "X402_OPTION": "option_a_pro_pass",
                },
            }
        }
    )
    tools = await client.get_tools()
    agent = create_react_agent("openai:gpt-4o", tools)
    response = await agent.ainvoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": "Scan wallet 89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1 for unclaimed ATA SOL rent.",
                }
            ]
        }
    )
    print(response["messages"][-1].content)


if __name__ == "__main__":
    asyncio.run(run_guard())
```

## License and Links

* **License**: MIT
* **Production Web App & API**: [https://rentandrugshield.com](https://rentandrugshield.com)
* **Source Repository**: [https://github.com/sonnyman2014/solana-rent-rug-shield-mcp](https://github.com/sonnyman2014/solana-rent-rug-shield-mcp)
* **Solana `x402` Treasury**: `89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1`
