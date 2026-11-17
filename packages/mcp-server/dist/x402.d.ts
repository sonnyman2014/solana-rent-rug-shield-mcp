import { Keypair } from "@solana/web3.js";
import { type X402OptionId, type X402PaymentChallenge, type X402PaymentEnvelope, type X402PaymentSignerFn } from "./types.js";
export declare function normalizeX402Option(raw?: string | null): X402OptionId;
export declare function generateDeterministicMockSignature(option: X402OptionId, agentId: string, payer: string, nonce: number): string;
export declare function parseSolanaKeypair(secret: string): Keypair;
export declare function encodeX402PaymentHeader(envelope: X402PaymentEnvelope): string;
export declare function decodeBase64Json<T = Record<string, unknown>>(encoded: string): T | null;
export declare function parseX402Challenge(headers: Record<string, string | string[] | undefined>, body: unknown, fallbackUsedPings?: number): X402PaymentChallenge;
export interface AutoPayerConfig {
    solanaPrivateKey?: string;
    solanaRpcUrl?: string;
    mockSigner?: boolean;
    agentId: string;
    paymentSigner?: X402PaymentSignerFn;
}
export declare class X402SolanaAutoPayer {
    private readonly keypair;
    private readonly mockKeypair;
    private readonly mockSigner;
    private readonly solanaRpcUrl;
    private readonly agentId;
    private readonly customSigner?;
    private connection;
    private mockNonce;
    constructor(config: AutoPayerConfig);
    canAutoPay(): boolean;
    getPayerPublicKey(): string | null;
    buildManualPaymentEnvelope(signature: string, option: X402OptionId, payerWallet?: string): X402PaymentEnvelope;
    createAutoPayment(option: X402OptionId, challenge: X402PaymentChallenge): Promise<X402PaymentEnvelope>;
    private pollSignatureConfirmationHttp;
}
//# sourceMappingURL=x402.d.ts.map