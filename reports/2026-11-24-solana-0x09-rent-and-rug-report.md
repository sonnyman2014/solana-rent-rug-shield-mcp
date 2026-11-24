# Solana On-Chain SPL `0x09` Rent Recovery & 12-Layer Token Security Report (2026-11-24)

All figures below are deterministic, public Solana mainnet state verifications. Zero seed phrases or private keys are ever requested.

## 1. Verified Empty Associated Token Account (`0x09 CloseAccount`) Rent Recovery Benchmark
* **Inspected Mainnet Pubkey**: `D9GYt4W7VvteKCSvTgyjzuiBJyTy94Kmr6YiC9fbxGjW` ([Solscan Account Proof](https://solscan.io/account/D9GYt4W7VvteKCSvTgyjzuiBJyTy94Kmr6YiC9fbxGjW))
* **Total SPL Token Accounts**: `72,676`
* **Zero-Balance Reclaimable Empty ATAs**: `38,616`
* **Exact Locked Rent-Exempt Deposit**: `78,485,347,095 lamports` (`78.485347 SOL` at `~0.00203928 SOL` per 165-byte SPL Token account)
* **Read-Only Live Verification**: [https://rentandrugshield.com/?wallet=D9GYt4W7VvteKCSvTgyjzuiBJyTy94Kmr6YiC9fbxGjW&src=gist_report](https://rentandrugshield.com/?wallet=D9GYt4W7VvteKCSvTgyjzuiBJyTy94Kmr6YiC9fbxGjW&src=gist_report)

## 2. Live 12-Layer Pre-Buy Rug & Token-2022 Trap Detections
* **`$VEYRA` (`8zaYjmVacfAnMhf3cLsECgzK6pLtWrLQbBv65y3vjyR1`)**: Flagged `0/100 FAIL` due to `0.0%` LP burn (`lp_burned_pct = 0.0%`) prior to manual liquidity removal ([Live 12-Layer Audit](https://rentandrugshield.com/?token=8zaYjmVacfAnMhf3cLsECgzK6pLtWrLQbBv65y3vjyR1&autoscan=1&src=gist_report#tokenScanner) | [Solscan Token](https://solscan.io/token/8zaYjmVacfAnMhf3cLsECgzK6pLtWrLQbBv65y3vjyR1))
* **`$JENSEN` (`HKiMA2mKQHU2cjfZ4Kbmru5GBGCauSNqPtpu8cfmpump`)**: Flagged `CRITICAL FAIL` on deployer creator rug history ([Live 12-Layer Audit](https://rentandrugshield.com/?token=HKiMA2mKQHU2cjfZ4Kbmru5GBGCauSNqPtpu8cfmpump&autoscan=1&src=gist_report#tokenScanner) | [Solscan Token](https://solscan.io/token/HKiMA2mKQHU2cjfZ4Kbmru5GBGCauSNqPtpu8cfmpump))

## 3. Developer & Autonomous Agent Endpoints (Model Context Protocol)
* **Web Scanner (`0%` Fee on 1st Rent Claim)**: [https://rentandrugshield.com/](https://rentandrugshield.com/?src=gist_report)
* **Streamable HTTP MCP Gateway**: [https://rentandrugshield.com/mcp](https://rentandrugshield.com/mcp)
* **MCP Discovery Card**: [https://rentandrugshield.com/.well-known/mcp.json](https://rentandrugshield.com/.well-known/mcp.json)
* **Open-Source MCP Server & Skill (`MIT`)**: [https://github.com/sonnyman2014/solana-rent-rug-shield-mcp](https://github.com/sonnyman2014/solana-rent-rug-shield-mcp)
