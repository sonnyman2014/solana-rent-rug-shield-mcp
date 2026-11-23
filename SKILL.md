---
name: solana-rent-rug-shield
description: Non-custodial Solana SPL 0x09 empty ATA rent scanner and sub-120ms 12-layer pre-buy token rug and CPI drainer audit skill.
---

# Solana Rent & Rug Shield Skill

Use this skill when auditing Solana SPL or Token-2022 mints before swapping, simulating serialized Solana transactions for hidden inner-CPI drainers (`ApproveChecked`, `SetAuthority`, `Assign`), or scanning wallet addresses read-only for reclaimable empty ATA rent (`0x09 CloseAccount`).

## Endpoints & Usage

- **12-Layer Token Audit**: `GET https://rentandrugshield.com/audit/<MINT>`
- **MCP Server Repository**: `https://github.com/sonnyman2014/solana-rent-rug-shield-mcp`
- **Read-Only Web Scanner**: `https://rentandrugshield.com`
