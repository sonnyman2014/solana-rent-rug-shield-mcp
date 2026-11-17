import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { type Tool } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { RentShieldClient } from "./client.js";
import { type RentShieldClientOptions } from "./types.js";
export declare const AuditTokenArgsSchema: z.ZodObject<{
    mint: z.ZodString;
    pool_address: z.ZodOptional<z.ZodString>;
    wallet: z.ZodOptional<z.ZodString>;
    payment_signature: z.ZodOptional<z.ZodString>;
    pro_pass_token: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    mint: string;
    wallet?: string | undefined;
    pool_address?: string | undefined;
    pro_pass_token?: string | undefined;
    payment_signature?: string | undefined;
}, {
    mint: string;
    wallet?: string | undefined;
    pool_address?: string | undefined;
    pro_pass_token?: string | undefined;
    payment_signature?: string | undefined;
}>;
export declare const SimulateTxDrainArgsSchema: z.ZodObject<{
    transaction: z.ZodString;
    wallet: z.ZodOptional<z.ZodString>;
    encoding: z.ZodDefault<z.ZodOptional<z.ZodEnum<["base64", "base58"]>>>;
    payment_signature: z.ZodOptional<z.ZodString>;
    pro_pass_token: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    encoding: "base64" | "base58";
    transaction: string;
    wallet?: string | undefined;
    pro_pass_token?: string | undefined;
    payment_signature?: string | undefined;
}, {
    transaction: string;
    encoding?: "base64" | "base58" | undefined;
    wallet?: string | undefined;
    pro_pass_token?: string | undefined;
    payment_signature?: string | undefined;
}>;
export declare const ScanWalletUnclaimedSolArgsSchema: z.ZodObject<{
    wallet: z.ZodString;
    include_token_2022: z.ZodDefault<z.ZodOptional<z.ZodBoolean>>;
    payment_signature: z.ZodOptional<z.ZodString>;
    pro_pass_token: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    wallet: string;
    include_token_2022: boolean;
    pro_pass_token?: string | undefined;
    payment_signature?: string | undefined;
}, {
    wallet: string;
    include_token_2022?: boolean | undefined;
    pro_pass_token?: string | undefined;
    payment_signature?: string | undefined;
}>;
export declare const MCP_TOOLS: Tool[];
export interface CreatedMcpServer {
    server: Server;
    client: RentShieldClient;
}
export declare function createMcpServer(options?: RentShieldClientOptions): CreatedMcpServer;
export declare function runStdioServer(options?: RentShieldClientOptions): Promise<CreatedMcpServer>;
//# sourceMappingURL=server.d.ts.map