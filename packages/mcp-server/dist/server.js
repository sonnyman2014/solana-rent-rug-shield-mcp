import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ErrorCode, ListToolsRequestSchema, McpError } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { RentShieldClient } from "./client.js";
import { X402_TREASURY } from "./types.js";
export const AuditTokenArgsSchema = z.object({
    mint: z
        .string()
        .min(32, "mint must be a valid base58 Solana mint address")
        .describe("Solana SPL or Token-2022 token mint address (base58) to audit pre-buy."),
    pool_address: z
        .string()
        .optional()
        .describe("Optional DEX liquidity pool or AMM pair address to inspect alongside the mint."),
    wallet: z
        .string()
        .optional()
        .describe("Optional buyer Solana wallet public key for Pro Pass verification or telemetry."),
    payment_signature: z
        .string()
        .optional()
        .describe(`Optional confirmed Solana transaction signature paying ${X402_TREASURY} (0.026 SOL Option A Pro Pass or 0.0003 SOL Option B single scan).`),
    pro_pass_token: z
        .string()
        .optional()
        .describe("Optional X-Pro-Pass-Token issued after Option A (0.026 SOL Unlimited Pro Pass) upgrade.")
});
export const SimulateTxDrainArgsSchema = z.object({
    transaction: z
        .string()
        .min(8, "transaction payload is required")
        .describe("Unsigned or signed serialized Solana transaction in base64 or base58."),
    wallet: z
        .string()
        .optional()
        .describe("Optional signer Solana wallet public key to evaluate balance delta and authority risk."),
    encoding: z
        .enum(["base64", "base58"])
        .optional()
        .default("base64")
        .describe("Serialization encoding of the transaction payload (default: base64)."),
    payment_signature: z
        .string()
        .optional()
        .describe(`Optional confirmed Solana transaction signature paying ${X402_TREASURY} for x402 retry.`),
    pro_pass_token: z
        .string()
        .optional()
        .describe("Optional X-Pro-Pass-Token for unlimited Pro Pass access.")
});
export const ScanWalletUnclaimedSolArgsSchema = z.object({
    wallet: z
        .string()
        .min(32, "wallet must be a valid base58 Solana public key")
        .describe("Solana wallet public key (base58) to scan read-only for unclaimed ATA SOL rent."),
    include_token_2022: z
        .boolean()
        .optional()
        .default(true)
        .describe("Whether to scan Token-2022 accounts in addition to classic SPL Token accounts (default: true)."),
    payment_signature: z
        .string()
        .optional()
        .describe(`Optional confirmed Solana transaction signature paying ${X402_TREASURY} for x402 retry.`),
    pro_pass_token: z
        .string()
        .optional()
        .describe("Optional X-Pro-Pass-Token for unlimited Pro Pass access.")
});
export const MCP_TOOLS = [
    {
        name: "audit_solana_token_10_layer",
        description: "<120ms pre-buy 10-layer Solana token safety gate over persistent keep-alive connections. Audits mint/freeze authorities, Token-2022 extensions (transfer fee, permanent delegate, transfer hook, default frozen), LP lock/burn status, top holder cluster concentration, exit liquidity solvency, Layer-8/9 Inner-CPI rent traps, pool age, and orderflow velocity. Includes 10 free pings and Solana x402 auto-upgrade.",
        inputSchema: {
            type: "object",
            properties: {
                mint: {
                    type: "string",
                    description: "Solana SPL or Token-2022 token mint address (base58) to audit pre-buy."
                },
                pool_address: {
                    type: "string",
                    description: "Optional DEX liquidity pool or pair address (base58)."
                },
                wallet: {
                    type: "string",
                    description: "Optional buyer Solana wallet public key (base58)."
                },
                payment_signature: {
                    type: "string",
                    description: `Optional confirmed Solana transaction signature paying ${X402_TREASURY} (0.026 SOL Option A or 0.0003 SOL Option B).`
                },
                pro_pass_token: {
                    type: "string",
                    description: "Optional X-Pro-Pass-Token from Option A ($1.99 / 0.026 SOL Unlimited Pro Pass)."
                }
            },
            required: ["mint"],
            additionalProperties: false
        }
    },
    {
        name: "simulate_solana_tx_drain",
        description: "Pre-sign Layer-9 Inner-CPI Solana transaction drainer check. Inspects base64 or base58 serialized transactions before wallet signing to block malicious inner CPI SOL drains, stealth SPL Approve/SetAuthority delegations, creator-vault rent traps, and unexpected balance deltas.",
        inputSchema: {
            type: "object",
            properties: {
                transaction: {
                    type: "string",
                    description: "Serialized Solana transaction (unsigned or signed) in base64 or base58."
                },
                wallet: {
                    type: "string",
                    description: "Optional fee-payer/signer Solana wallet public key (base58)."
                },
                encoding: {
                    type: "string",
                    enum: ["base64", "base58"],
                    default: "base64",
                    description: "Encoding of the serialized transaction ('base64' or 'base58')."
                },
                payment_signature: {
                    type: "string",
                    description: `Optional confirmed Solana transaction signature paying ${X402_TREASURY} for x402 retry.`
                },
                pro_pass_token: {
                    type: "string",
                    description: "Optional X-Pro-Pass-Token from Option A Unlimited Pro Pass."
                }
            },
            required: ["transaction"],
            additionalProperties: false
        }
    },
    {
        name: "scan_wallet_unclaimed_sol",
        description: "Read-only Solana wallet ATA and Token-2022 rent scanner. Identifies empty and dust token accounts holding reclaimable SOL rent without requiring private keys, returning exact lamport, SOL, and USD recovery breakdowns.",
        inputSchema: {
            type: "object",
            properties: {
                wallet: {
                    type: "string",
                    description: "Solana wallet public key (base58) to scan read-only for reclaimable ATA rent."
                },
                include_token_2022: {
                    type: "boolean",
                    default: true,
                    description: "Include Token-2022 accounts alongside SPL Token accounts (default: true)."
                },
                payment_signature: {
                    type: "string",
                    description: `Optional confirmed Solana transaction signature paying ${X402_TREASURY} for x402 retry.`
                },
                pro_pass_token: {
                    type: "string",
                    description: "Optional X-Pro-Pass-Token from Option A Unlimited Pro Pass."
                }
            },
            required: ["wallet"],
            additionalProperties: false
        }
    }
];
export function createMcpServer(options = {}) {
    const client = new RentShieldClient(options);
    const server = new Server({
        name: "@rentandrugshield/mcp-server",
        version: "1.0.0"
    }, {
        capabilities: {
            tools: {}
        }
    });
    server.setRequestHandler(ListToolsRequestSchema, async () => {
        return { tools: MCP_TOOLS };
    });
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
        const { name, arguments: rawArgs } = request.params;
        const args = rawArgs ?? {};
        try {
            if (name === "audit_solana_token_10_layer") {
                const parsed = AuditTokenArgsSchema.parse(args);
                const res = await client.auditSolanaToken10Layer(parsed);
                return formatEnvelopeAsToolResponse(res);
            }
            if (name === "simulate_solana_tx_drain") {
                const parsed = SimulateTxDrainArgsSchema.parse(args);
                const res = await client.simulateSolanaTxDrain(parsed);
                return formatEnvelopeAsToolResponse(res);
            }
            if (name === "scan_wallet_unclaimed_sol") {
                const parsed = ScanWalletUnclaimedSolArgsSchema.parse(args);
                const res = await client.scanWalletUnclaimedSol(parsed);
                return formatEnvelopeAsToolResponse(res);
            }
            throw new McpError(ErrorCode.MethodNotFound, `Unknown MCP tool: ${name}`);
        }
        catch (err) {
            if (err instanceof McpError) {
                throw err;
            }
            if (err instanceof z.ZodError) {
                return {
                    isError: true,
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify({
                                ok: false,
                                error: "Invalid tool arguments",
                                issues: err.issues
                            })
                        }
                    ]
                };
            }
            return {
                isError: true,
                content: [
                    {
                        type: "text",
                        text: JSON.stringify({
                            ok: false,
                            error: err instanceof Error ? err.message : String(err)
                        })
                    }
                ]
            };
        }
    });
    return { server, client };
}
function formatEnvelopeAsToolResponse(res) {
    if (res.paymentRequired && res.x402Challenge) {
        const challengePayload = {
            ok: false,
            status: 402,
            paymentRequired: true,
            payment_required: true,
            treasury: res.x402Challenge.treasury,
            freePingsLimit: res.x402Challenge.freePingsLimit,
            freePingsUsed: res.x402Challenge.freePingsUsed,
            freePingsRemaining: 0,
            options: res.x402Challenge.options,
            instructions: res.x402Challenge.instructions,
            x402Challenge: res.x402Challenge,
            quota: res.quota,
            latency_ms: res.latencyMs
        };
        return {
            isError: false,
            content: [
                {
                    type: "text",
                    text: JSON.stringify(challengePayload)
                }
            ]
        };
    }
    const mergedPayload = {
        ...res.data,
        ok: res.ok,
        status: res.status,
        latency_ms: res.latencyMs,
        quota: res.quota
    };
    if (res.x402AutoPaid) {
        mergedPayload.x402_auto_paid = res.x402AutoPaid;
        mergedPayload.x402AutoPaid = res.x402AutoPaid;
    }
    return {
        isError: !res.ok && res.status >= 500,
        content: [
            {
                type: "text",
                text: JSON.stringify(mergedPayload)
            }
        ]
    };
}
export async function runStdioServer(options = {}) {
    const created = createMcpServer(options);
    const transport = new StdioServerTransport();
    await created.server.connect(transport);
    return created;
}
//# sourceMappingURL=server.js.map