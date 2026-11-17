#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { basename } from "node:path";
import { fileURLToPath } from "node:url";
import { runStdioServer } from "./server.js";

export {
  DEFAULT_API_URL,
  X402_FREE_PINGS_LIMIT,
  X402_TIERS,
  X402_TREASURY,
  type AuditSolanaTokenInput,
  type ClientQuotaState,
  type EndpointRoutesConfig,
  type RentShieldClientOptions,
  type ScanWalletUnclaimedSolInput,
  type SimulateSolanaTxDrainInput,
  type ToolCallResultEnvelope,
  type X402ChallengeOption,
  type X402OptionId,
  type X402PaymentChallenge,
  type X402PaymentEnvelope,
  type X402PaymentPayload,
  type X402PaymentSignerFn,
  type X402TierSpec
} from "./types.js";

export {
  X402SolanaAutoPayer,
  decodeBase64Json,
  encodeX402PaymentHeader,
  generateDeterministicMockSignature,
  normalizeX402Option,
  parseSolanaKeypair,
  parseX402Challenge
} from "./x402.js";

export {
  analyzeTransactionDrainFallback,
  decodeSerializedTx,
  type LocalTxDrainAnalysis
} from "./txSimulator.js";

export { RentShieldClient } from "./client.js";

export {
  AuditTokenArgsSchema,
  MCP_TOOLS,
  ScanWalletUnclaimedSolArgsSchema,
  SimulateTxDrainArgsSchema,
  createMcpServer,
  runStdioServer,
  type CreatedMcpServer
} from "./server.js";

function isDirectCliInvocation(): boolean {
  const argv1 = process.argv[1];
  if (!argv1) return false;
  try {
    const selfPath = realpathSync(fileURLToPath(import.meta.url));
    const targetPath = realpathSync(argv1);
    if (selfPath === targetPath) return true;
  } catch {
    // Fallback to binary name check if symlink resolution fails
  }
  const invokedBin = basename(argv1).replace(/\.(js|mjs|cjs|ts)$/i, "");
  return invokedBin === "rentandrugshield-mcp" || invokedBin === "mcp-server";
}

if (isDirectCliInvocation()) {
  runStdioServer().catch((err) => {
    process.stderr.write(
      `[@rentandrugshield/mcp-server] Fatal stdio server error: ${
        err instanceof Error ? err.stack ?? err.message : String(err)
      }\n`
    );
    process.exit(1);
  });
}
