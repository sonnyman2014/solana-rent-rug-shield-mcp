export const DEFAULT_API_URL = "https://rentandrugshield.com";
export const X402_TREASURY = "89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1";
export const X402_FREE_PINGS_LIMIT = 10;

export type X402OptionId = "option_a_pro_pass" | "option_b_single_scan";

export interface X402TierSpec {
  id: X402OptionId;
  sol: number;
  lamports: number;
  usd: number;
  unlimited: boolean;
  description: string;
}

export const X402_TIERS: Record<X402OptionId, X402TierSpec> = {
  option_a_pro_pass: {
    id: "option_a_pro_pass",
    sol: 0.026,
    lamports: 26_000_000,
    usd: 1.99,
    unlimited: true,
    description: "$1.99 Unlimited Pro Pass (0.026 SOL / 26000000 lamports) with cached X-Pro-Pass-Token"
  },
  option_b_single_scan: {
    id: "option_b_single_scan",
    sol: 0.0003,
    lamports: 300_000,
    usd: 0.02,
    unlimited: false,
    description: "~$0.02 Instant Single Scan (0.0003 SOL / 300000 lamports) for 1 verified request"
  }
};

export interface X402PaymentPayload {
  signature: string;
  payer: string;
  option: X402OptionId;
  lamports: number;
  payTo: string;
}

export interface X402PaymentEnvelope {
  x402Version: 1;
  scheme: "exact";
  network: "solana-mainnet";
  payload: X402PaymentPayload;
}

export interface X402ChallengeOption {
  option: X402OptionId;
  scheme: string;
  network: string;
  payTo: string;
  lamports: number;
  sol: number;
  usd?: number;
  description?: string;
}

export interface X402PaymentChallenge {
  x402Version: number;
  status: 402;
  treasury: string;
  treasuryVerified: boolean;
  freePingsLimit: number;
  freePingsUsed: number;
  freePingsRemaining: number;
  wwwAuthenticate?: string;
  options: {
    option_a_pro_pass: X402ChallengeOption;
    option_b_single_scan: X402ChallengeOption;
  };
  accepts: Record<string, unknown>[];
  rawHeaderChallenge?: Record<string, unknown> | null;
  rawBody?: unknown;
  instructions: {
    summary: string;
    manualRetry: string;
    autoPayEnv: string;
  };
}

export interface AuditSolanaTokenInput {
  mint: string;
  pool_address?: string;
  wallet?: string;
  payment_signature?: string;
  pro_pass_token?: string;
}

export interface SimulateSolanaTxDrainInput {
  transaction: string;
  wallet?: string;
  encoding?: "base64" | "base58";
  payment_signature?: string;
  pro_pass_token?: string;
}

export interface ScanWalletUnclaimedSolInput {
  wallet: string;
  include_token_2022?: boolean;
  payment_signature?: string;
  pro_pass_token?: string;
}

export type X402PaymentSignerFn = (params: {
  option: X402OptionId;
  lamports: number;
  payTo: string;
  challenge: X402PaymentChallenge;
}) => Promise<{ signature: string; payer: string }>;

export interface EndpointRoutesConfig {
  auditToken?: string[];
  simulateTx?: string[];
  scanWallet?: string[];
}

export interface RentShieldClientOptions {
  apiUrl?: string;
  agentId?: string;
  apiKey?: string;
  proPassToken?: string;
  solanaPrivateKey?: string;
  solanaRpcUrl?: string;
  x402Option?: X402OptionId | string;
  mockSigner?: boolean;
  auditTimeoutMs?: number;
  requestTimeoutMs?: number;
  routes?: EndpointRoutesConfig;
  paymentSigner?: X402PaymentSignerFn;
}

export interface ClientQuotaState {
  agentId: string;
  freePingsLimit: number;
  freePingsUsed: number;
  freePingsRemaining: number;
  hasProPassToken: boolean;
  proPassToken: string | null;
  autoPayEnabled: boolean;
  selectedOption: X402OptionId;
  paymentsExecuted: number;
  lastPaymentSignature: string | null;
}

export interface ToolCallResultEnvelope<T = Record<string, unknown>> {
  ok: boolean;
  status: number;
  latencyMs: number;
  paymentRequired?: boolean;
  x402Challenge?: X402PaymentChallenge;
  x402AutoPaid?: {
    option: X402OptionId;
    lamports: number;
    sol: number;
    signature: string;
    payer: string;
    payTo: string;
    proPassTokenCached: boolean;
  };
  quota: {
    agentId: string;
    freePingsUsed: number;
    freePingsRemaining: number;
    proPassActive: boolean;
  };
  data: T;
}
