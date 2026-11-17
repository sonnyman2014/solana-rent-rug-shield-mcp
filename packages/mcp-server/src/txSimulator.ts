import {
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
  VersionedTransaction
} from "@solana/web3.js";
import bs58 from "bs58";

const SPL_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111";

const KNOWN_SAFE_CORE_PROGRAMS = new Set<string>([
  SystemProgram.programId.toBase58(),
  SPL_TOKEN_PROGRAM,
  TOKEN_2022_PROGRAM,
  ASSOCIATED_TOKEN_PROGRAM,
  COMPUTE_BUDGET_PROGRAM,
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
  "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo"
]);

export interface LocalTxDrainAnalysis {
  ok: boolean;
  safe: boolean;
  safe_to_sign: boolean;
  drain_detected: boolean;
  inner_cpi_drain: boolean;
  hidden_pda_rent_trap: boolean;
  layer: 9;
  gate: "Layer-9 Inner-CPI & Drainer Pre-Sign Check";
  verdict: string;
  risk_level: "SAFE" | "CAUTION" | "CRITICAL";
  estimated_lamports_delta: number;
  estimated_sol_delta: number;
  encoding: "base64" | "base58";
  wallet: string | null;
  version: "legacy" | number;
  instruction_count: number;
  programs_invoked: string[];
  flagged_programs: string[];
  unknown_programs: string[];
  warnings: string[];
  drainer_indicators: string[];
  units_consumed: number;
  logs: string[];
  simulated_onchain: boolean;
}

export function decodeSerializedTx(
  rawTx: string,
  encoding: "base64" | "base58" = "base64"
): Uint8Array {
  const trimmed = rawTx.trim();
  if (!trimmed) {
    throw new Error("Transaction payload cannot be empty.");
  }
  if (encoding === "base58") {
    return bs58.decode(trimmed);
  }
  const buf = Buffer.from(trimmed, "base64");
  if (buf.length === 0) {
    throw new Error("Invalid base64 transaction payload.");
  }
  return Uint8Array.from(buf);
}

export async function analyzeTransactionDrainFallback(params: {
  transaction: string;
  wallet?: string;
  encoding?: "base64" | "base58";
  solanaRpcUrl?: string;
  enableRpcSimulation?: boolean;
}): Promise<LocalTxDrainAnalysis> {
  const encoding = params.encoding ?? "base64";
  const txBytes = decodeSerializedTx(params.transaction, encoding);

  let version: "legacy" | number = "legacy";
  const programsInvoked = new Set<string>();
  const flaggedPrograms = new Set<string>();
  const warnings: string[] = [];
  const drainerIndicators: string[] = [];
  let instructionCount = 0;
  let totalTransferLamports = 0;
  let hiddenPdaRentTrap = false;
  let parsedLegacy: Transaction | null = null;
  let parsedVersioned: VersionedTransaction | null = null;

  try {
    parsedVersioned = VersionedTransaction.deserialize(txBytes);
    version = parsedVersioned.version;
    const msg = parsedVersioned.message;
    const staticKeys = msg.staticAccountKeys.map((k) => k.toBase58());
    instructionCount = msg.compiledInstructions.length;

    for (const ix of msg.compiledInstructions) {
      const progId = staticKeys[ix.programIdIndex] ?? `lookup_idx_${ix.programIdIndex}`;
      programsInvoked.add(progId);
      const res = inspectRawInstruction(progId, ix.data, warnings, drainerIndicators);
      totalTransferLamports += res.transferLamports;
      if (res.flagged) flaggedPrograms.add(progId);
      if (res.rentTrap) hiddenPdaRentTrap = true;
    }
  } catch {
    parsedLegacy = Transaction.from(Buffer.from(txBytes));
    version = "legacy";
    instructionCount = parsedLegacy.instructions.length;
    for (const ix of parsedLegacy.instructions) {
      const progId = ix.programId.toBase58();
      programsInvoked.add(progId);
      const res = inspectRawInstruction(
        progId,
        Uint8Array.from(ix.data),
        warnings,
        drainerIndicators
      );
      totalTransferLamports += res.transferLamports;
      if (res.flagged) flaggedPrograms.add(progId);
      if (res.rentTrap) hiddenPdaRentTrap = true;
    }
  }

  const allPrograms = Array.from(programsInvoked);
  const unknownPrograms = allPrograms.filter((p) => !KNOWN_SAFE_CORE_PROGRAMS.has(p));
  if (unknownPrograms.length > 0) {
    warnings.push(
      `External programs invoked (${unknownPrograms.length}): verify inner CPI instructions before signing.`
    );
  }

  let simulatedOnchain = false;
  let simulationLogs: string[] = [];
  let unitsConsumed = 0;

  if (params.enableRpcSimulation && params.solanaRpcUrl && parsedVersioned) {
    try {
      const conn = new Connection(params.solanaRpcUrl, "confirmed");
      const sim = await conn.simulateTransaction(parsedVersioned, {
        sigVerify: false,
        replaceRecentBlockhash: true
      });
      simulatedOnchain = true;
      simulationLogs = sim.value.logs ?? [];
      unitsConsumed = sim.value.unitsConsumed ?? 0;
      if (sim.value.err) {
        warnings.push(`RPC simulation returned execution error: ${JSON.stringify(sim.value.err)}`);
      }
      for (const line of simulationLogs) {
        if (/SetAuthority|ApproveChecked|Approve/i.test(line)) {
          drainerIndicators.push(`Inner CPI authority/delegate instruction detected in logs: ${line}`);
        }
      }
    } catch {
      // Static Layer-9 inspection still succeeds offline if RPC is unreachable
    }
  }

  if (params.wallet) {
    try {
      new PublicKey(params.wallet);
    } catch {
      warnings.push(`Provided wallet "${params.wallet}" is not a valid base58 public key.`);
    }
  }

  const drainDetected = drainerIndicators.length > 0;
  const riskLevel: "SAFE" | "CAUTION" | "CRITICAL" = drainDetected
    ? "CRITICAL"
    : unknownPrograms.length > 0
      ? "CAUTION"
      : "SAFE";

  const safe = !drainDetected;
  const estimatedLamportsDelta = -totalTransferLamports;
  const estimatedSolDelta = Number((estimatedLamportsDelta / 1e9).toFixed(9));

  const verdict = drainDetected
    ? "DANGER: LAYER-9 INNER-CPI / AUTHORITY DRAINER DETECTED"
    : riskLevel === "CAUTION"
      ? "CAUTION: EXTERNAL PROGRAM CPI DETECTED (NO KNOWN DRAIN OPCODES)"
      : "SAFE: LAYER-9 PRE-SIGN CHECK PASSED";

  return {
    ok: true,
    safe,
    safe_to_sign: safe,
    drain_detected: drainDetected,
    inner_cpi_drain: drainDetected || hiddenPdaRentTrap,
    hidden_pda_rent_trap: hiddenPdaRentTrap,
    layer: 9,
    gate: "Layer-9 Inner-CPI & Drainer Pre-Sign Check",
    verdict,
    risk_level: riskLevel,
    estimated_lamports_delta: estimatedLamportsDelta,
    estimated_sol_delta: estimatedSolDelta,
    encoding,
    wallet: params.wallet ?? null,
    version,
    instruction_count: instructionCount,
    programs_invoked: allPrograms,
    flagged_programs: Array.from(flaggedPrograms),
    unknown_programs: unknownPrograms,
    warnings,
    drainer_indicators: drainerIndicators,
    units_consumed: unitsConsumed,
    logs: simulationLogs,
    simulated_onchain: simulatedOnchain
  };
}

function inspectRawInstruction(
  programId: string,
  data: Uint8Array,
  warnings: string[],
  drainerIndicators: string[]
): { transferLamports: number; flagged: boolean; rentTrap: boolean } {
  let transferLamports = 0;
  let flagged = false;
  let rentTrap = false;

  if (programId === SPL_TOKEN_PROGRAM || programId === TOKEN_2022_PROGRAM) {
    if (data.length > 0) {
      const opcode = data[0];
      // SPL Token: 4 = Approve, 6 = SetAuthority, 9 = CloseAccount, 13 = ApproveChecked, 26/27 = TransferHook
      if (opcode === 6) {
        flagged = true;
        drainerIndicators.push(
          `SPL SetAuthority opcode (0x06) on ${programId}: potential wallet/ATA ownership hijack.`
        );
      } else if (opcode === 4 || opcode === 13) {
        flagged = true;
        drainerIndicators.push(
          `SPL Approve delegate opcode (0x${opcode.toString(16).padStart(2, "0")}) on ${programId}: stealth token allowance drainer risk.`
        );
      } else if (opcode === 9) {
        warnings.push(
          `SPL CloseAccount opcode (0x09) on ${programId}: verify rent destination matches your wallet.`
        );
      } else if (programId === TOKEN_2022_PROGRAM && opcode === 36) {
        rentTrap = true;
        warnings.push("Token-2022 TransferHook extension instruction detected.");
      }
    }
  } else if (programId === SystemProgram.programId.toBase58()) {
    // SystemProgram u32 LE: 1 = Assign, 2 = Transfer, 10 = AssignWithSeed
    if (data.length >= 4) {
      const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
      const sysIx = view.getUint32(0, true);
      if (sysIx === 1 || sysIx === 10) {
        flagged = true;
        drainerIndicators.push(
          `SystemProgram Assign opcode (${sysIx}): critical account owner reassignment drainer trap!`
        );
      } else if (sysIx === 2 && data.length >= 12) {
        const lamports = Number(view.getBigUint64(4, true));
        transferLamports += lamports;
        if (lamports >= 10_000_000) {
          warnings.push(
            `SystemProgram SOL transfer of ${(lamports / 1e9).toFixed(6)} SOL (${lamports} lamports) detected.`
          );
        }
      }
    }
  }

  return { transferLamports, flagged, rentTrap };
}
