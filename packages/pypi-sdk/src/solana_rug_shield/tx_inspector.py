"""Local Layer-9 Inner-CPI & Solana wire transaction drainer analyzer (fallback helper)."""

from __future__ import annotations

import base64
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

from .constants import SPL_TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, TREASURY_WALLET
from .x402 import b58decode, b58encode

_KNOWN_SAFE_PROGRAMS = {
    SYSTEM_PROGRAM_ID,
    SPL_TOKEN_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID,
    "ComputeBudget111111111111111111111111111111",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",
}


def _read_compact_u16(buf: bytes, offset: int) -> Tuple[int, int]:
    val = 0
    shift = 0
    idx = offset
    for _ in range(3):
        if idx >= len(buf):
            raise ValueError("Truncated compact-u16 in Solana transaction")
        byte = buf[idx]
        idx += 1
        val |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return val, idx
        shift += 7
    raise ValueError("Malformed compact-u16 in Solana transaction")


def inspect_solana_transaction_local(
    transaction: str,
    encoding: str = "base64",
    wallet: Optional[str] = None,
) -> Dict[str, Any]:
    """Decode a Base64/Base58 Solana wire transaction and inspect for Layer-9 drain vectors."""
    enc = (encoding or "base64").strip().lower()
    clean = (transaction or "").strip()
    if not clean:
        return {
            "ok": False,
            "safe": False,
            "drain_detected": False,
            "inner_cpi_drain": False,
            "hidden_pda_rent_trap": False,
            "risk_level": "INVALID",
            "verdict": "INVALID_TRANSACTION",
            "estimated_lamports_delta": 0,
            "estimated_sol_delta": 0.0,
            "flagged_programs": [],
            "warnings": ["Empty transaction payload"],
            "units_consumed": 0,
            "logs": [],
            "error": "Empty transaction payload",
        }

    try:
        if enc == "base58":
            raw = b58decode(clean)
        else:
            pad = (4 - (len(clean) % 4)) % 4
            raw = base64.b64decode(clean + ("=" * pad))
    except Exception as exc:
        return {
            "ok": False,
            "safe": False,
            "drain_detected": False,
            "inner_cpi_drain": False,
            "hidden_pda_rent_trap": False,
            "risk_level": "INVALID",
            "verdict": "INVALID_ENCODING",
            "estimated_lamports_delta": 0,
            "estimated_sol_delta": 0.0,
            "flagged_programs": [],
            "warnings": [f"Failed to decode {enc} transaction: {exc}"],
            "units_consumed": 0,
            "logs": [],
            "error": f"Failed to decode {enc} transaction: {exc}",
        }

    try:
        sig_count, pos = _read_compact_u16(raw, 0)
        pos += sig_count * 64
        if pos >= len(raw):
            raise ValueError("Transaction truncated before message header")

        version: Union[str, int] = "legacy"
        first_byte = raw[pos]
        if first_byte & 0x80:
            version = first_byte & 0x7F
            pos += 1

        if pos + 3 > len(raw):
            raise ValueError("Transaction truncated in message header")
        num_req_sigs = raw[pos]
        num_ro_signed = raw[pos + 1]
        num_ro_unsigned = raw[pos + 2]
        pos += 3

        acct_count, pos = _read_compact_u16(raw, pos)
        accounts: List[str] = []
        for _ in range(acct_count):
            if pos + 32 > len(raw):
                raise ValueError("Transaction truncated in static account keys")
            accounts.append(b58encode(raw[pos : pos + 32]))
            pos += 32

        if pos + 32 > len(raw):
            raise ValueError("Transaction truncated at recent blockhash")
        recent_blockhash = b58encode(raw[pos : pos + 32])
        pos += 32

        ix_count, pos = _read_compact_u16(raw, pos)
        warnings: List[str] = []
        flagged_programs: List[str] = []
        decoded_instructions: List[Dict[str, Any]] = []
        lamports_out = 0
        drain_detected = False
        inner_cpi_drain = False
        hidden_pda_trap = False
        protected_wallet = (wallet or (accounts[0] if accounts else "")).strip()

        for ix_idx in range(ix_count):
            if pos >= len(raw):
                break
            prog_idx = raw[pos]
            pos += 1
            ix_acct_len, pos = _read_compact_u16(raw, pos)
            ix_accts = list(raw[pos : pos + ix_acct_len])
            pos += ix_acct_len
            data_len, pos = _read_compact_u16(raw, pos)
            ix_data = raw[pos : pos + data_len]
            pos += data_len

            prog_id = accounts[prog_idx] if prog_idx < len(accounts) else f"lookup_{prog_idx}"
            decoded_instructions.append(
                {
                    "index": ix_idx,
                    "program_id": prog_id,
                    "account_indices": ix_accts,
                    "data_len": data_len,
                }
            )

            if prog_id in (SPL_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID) and ix_data:
                opcode = ix_data[0]
                if opcode in (4, 13):  # Approve / ApproveChecked
                    drain_detected = True
                    if prog_id not in flagged_programs:
                        flagged_programs.append(prog_id)
                    warnings.append(f"Instruction #{ix_idx}: Token Approve delegate drain vector detected ({prog_id})")
                elif opcode == 6:  # SetAuthority
                    drain_detected = True
                    if prog_id not in flagged_programs:
                        flagged_programs.append(prog_id)
                    warnings.append(f"Instruction #{ix_idx}: SetAuthority account owner/close hijack detected ({prog_id})")
                elif opcode == 9 and len(ix_accts) >= 2:  # CloseAccount
                    dest_idx = ix_accts[1]
                    dest_pk = accounts[dest_idx] if dest_idx < len(accounts) else "unknown"
                    if protected_wallet and dest_pk not in (protected_wallet, TREASURY_WALLET):
                        drain_detected = True
                        inner_cpi_drain = True
                        warnings.append(f"Instruction #{ix_idx}: CloseAccount diverts ATA rent to third party {dest_pk}")
            elif prog_id == SYSTEM_PROGRAM_ID and len(ix_data) >= 4:
                sys_op = struct.unpack_from("<I", ix_data, 0)[0]
                if sys_op == 1:  # Assign
                    drain_detected = True
                    if prog_id not in flagged_programs:
                        flagged_programs.append(prog_id)
                    warnings.append(f"Instruction #{ix_idx}: SystemProgram Assign wallet owner hijack detected")
                elif sys_op == 2 and len(ix_data) >= 12:  # Transfer
                    lam = struct.unpack_from("<Q", ix_data, 4)[0]
                    src_pk = accounts[ix_accts[0]] if len(ix_accts) > 0 and ix_accts[0] < len(accounts) else ""
                    dest_pk = accounts[ix_accts[1]] if len(ix_accts) > 1 and ix_accts[1] < len(accounts) else "unknown"
                    if not protected_wallet or src_pk == protected_wallet:
                        lamports_out += lam
                    if dest_pk not in (protected_wallet, TREASURY_WALLET) and lam >= 50_000_000:
                        warnings.append(
                            f"Instruction #{ix_idx}: Native SOL transfer of {lam / 1e9:.6f} SOL to {dest_pk}"
                        )
            elif prog_id not in _KNOWN_SAFE_PROGRAMS:
                inner_cpi_drain = False
                if prog_id not in flagged_programs and len(ix_accts) >= 6:
                    hidden_pda_trap = True
                    warnings.append(f"Instruction #{ix_idx}: Unverified external CPI program {prog_id} with {len(ix_accts)} accounts")

        is_safe = not drain_detected and not inner_cpi_drain
        risk_level = "CRITICAL" if drain_detected else ("MEDIUM" if warnings else "LOW")
        verdict = (
            "DANGER â€¢ LAYER 9 DRAIN DETECTED"
            if drain_detected
            else ("CAUTION â€¢ REVIEW WARNINGS" if warnings else "SAFE â€¢ 0 INNER CPI DRAINS")
        )
        return {
            "ok": True,
            "safe": is_safe,
            "drain_detected": drain_detected,
            "inner_cpi_drain": inner_cpi_drain,
            "hidden_pda_rent_trap": hidden_pda_trap,
            "risk_level": risk_level,
            "verdict": verdict,
            "estimated_lamports_delta": -lamports_out,
            "estimated_sol_delta": round(-lamports_out / 1_000_000_000, 9),
            "flagged_programs": flagged_programs,
            "warnings": warnings,
            "units_consumed": 5000 * max(1, len(decoded_instructions)),
            "logs": [f"Local wire inspection decoded {len(decoded_instructions)} instruction(s) ({version})"],
            "wallet": protected_wallet or None,
            "version": version,
            "num_required_signatures": num_req_sigs,
            "num_readonly_signed": num_ro_signed,
            "num_readonly_unsigned": num_ro_unsigned,
            "recent_blockhash": recent_blockhash,
            "accounts": accounts,
            "instructions": decoded_instructions,
        }
    except Exception as exc:
        return {
            "ok": False,
            "safe": False,
            "drain_detected": False,
            "inner_cpi_drain": False,
            "hidden_pda_rent_trap": False,
            "risk_level": "UNKNOWN",
            "verdict": "PARSE_ERROR",
            "estimated_lamports_delta": 0,
            "estimated_sol_delta": 0.0,
            "flagged_programs": [],
            "warnings": [f"Unable to parse Solana wire message: {exc}"],
            "units_consumed": 0,
            "logs": [],
            "error": f"Unable to parse Solana wire message: {exc}",
        }
