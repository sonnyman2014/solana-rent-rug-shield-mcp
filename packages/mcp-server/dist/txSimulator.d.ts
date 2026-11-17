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
export declare function decodeSerializedTx(rawTx: string, encoding?: "base64" | "base58"): Uint8Array;
export declare function analyzeTransactionDrainFallback(params: {
    transaction: string;
    wallet?: string;
    encoding?: "base64" | "base58";
    solanaRpcUrl?: string;
    enableRpcSimulation?: boolean;
}): Promise<LocalTxDrainAnalysis>;
//# sourceMappingURL=txSimulator.d.ts.map