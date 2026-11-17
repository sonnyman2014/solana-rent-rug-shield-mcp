import { type AuditSolanaTokenInput, type ClientQuotaState, type RentShieldClientOptions, type ScanWalletUnclaimedSolInput, type SimulateSolanaTxDrainInput, type ToolCallResultEnvelope, type X402OptionId } from "./types.js";
export declare class RentShieldClient {
    readonly apiUrl: string;
    readonly agentId: string;
    private readonly apiKey?;
    private readonly auditTimeoutMs;
    private readonly requestTimeoutMs;
    private readonly routes;
    private readonly stickyRoute;
    private readonly httpAgent;
    private readonly httpsAgent;
    private readonly autoPayer;
    private selectedOption;
    private cachedProPassToken;
    private freePingsUsed;
    private freePingsRemaining;
    private paymentsExecuted;
    private lastPaymentSignature;
    private readonly solanaRpcUrl;
    constructor(options?: RentShieldClientOptions);
    getQuotaState(): ClientQuotaState;
    setX402Option(option: X402OptionId | string): void;
    setProPassToken(token: string | null): void;
    destroy(): void;
    auditSolanaToken10Layer(input: AuditSolanaTokenInput): Promise<ToolCallResultEnvelope<Record<string, unknown>>>;
    simulateSolanaTxDrain(input: SimulateSolanaTxDrainInput): Promise<ToolCallResultEnvelope<Record<string, unknown>>>;
    scanWalletUnclaimedSol(input: ScanWalletUnclaimedSolInput): Promise<ToolCallResultEnvelope<Record<string, unknown>>>;
    private getOrderedRoutes;
    private executeGatewayCall;
    private updateQuotaFromHeaders;
    private captureProPassToken;
    private normalizeBodyObject;
    private rawPostJson;
}
//# sourceMappingURL=client.d.ts.map