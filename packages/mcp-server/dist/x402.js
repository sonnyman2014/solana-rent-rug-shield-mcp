import { createHash } from "node:crypto";
import { Connection, Keypair, PublicKey, SystemProgram, Transaction } from "@solana/web3.js";
import bs58 from "bs58";
import { X402_FREE_PINGS_LIMIT, X402_TIERS, X402_TREASURY } from "./types.js";
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function normalizeX402Option(raw) {
    const val = (raw ?? "").trim().toLowerCase();
    if (val === "option_b_single_scan" ||
        val === "option_b" ||
        val === "single_scan" ||
        val === "single" ||
        val === "b" ||
        val === "0.0003" ||
        val === "300000") {
        return "option_b_single_scan";
    }
    return "option_a_pro_pass";
}
export function generateDeterministicMockSignature(option, agentId, payer, nonce) {
    const prefix = option === "option_a_pro_pass" ? "5MockA" : "5MockB";
    const neededChars = 88 - prefix.length;
    let body = "";
    let round = 0;
    while (body.length < neededChars) {
        const digest = createHash("sha256")
            .update(`x402-mock-sig:${option}:${agentId}:${payer}:${nonce}:${round}`)
            .digest();
        for (const byte of digest) {
            body += BASE58_ALPHABET[byte % BASE58_ALPHABET.length];
            if (body.length >= neededChars)
                break;
        }
        round += 1;
    }
    return prefix + body.slice(0, neededChars);
}
export function parseSolanaKeypair(secret) {
    const trimmed = secret.trim();
    if (!trimmed) {
        throw new Error("Empty Solana private key provided.");
    }
    // 1. JSON byte array format: [12, 34, ...]
    if (trimmed.startsWith("[")) {
        let parsed;
        try {
            parsed = JSON.parse(trimmed);
        }
        catch (err) {
            throw new Error(`Invalid JSON byte array for SOLANA_PRIVATE_KEY: ${err.message}`);
        }
        if (!Array.isArray(parsed) || parsed.some((n) => typeof n !== "number" || n < 0 || n > 255)) {
            throw new Error("SOLANA_PRIVATE_KEY JSON array must contain byte integers (0..255).");
        }
        const bytes = Uint8Array.from(parsed);
        if (bytes.length === 64) {
            return Keypair.fromSecretKey(bytes);
        }
        if (bytes.length === 32) {
            return Keypair.fromSeed(bytes);
        }
        throw new Error(`Unexpected JSON keypair byte length ${bytes.length}; expected 64 or 32 bytes.`);
    }
    // 2. Hex string format (optional 0x prefix, 64 or 128 hex chars)
    const hexCandidate = trimmed.startsWith("0x") ? trimmed.slice(2) : trimmed;
    if (/^[0-9a-fA-F]+$/.test(hexCandidate) && (hexCandidate.length === 64 || hexCandidate.length === 128)) {
        const bytes = Uint8Array.from(Buffer.from(hexCandidate, "hex"));
        return bytes.length === 64 ? Keypair.fromSecretKey(bytes) : Keypair.fromSeed(bytes);
    }
    // 3. Base58 format
    let decoded;
    try {
        decoded = bs58.decode(trimmed);
    }
    catch (err) {
        throw new Error(`Invalid base58 SOLANA_PRIVATE_KEY: ${err.message}`);
    }
    if (decoded.length === 64) {
        return Keypair.fromSecretKey(decoded);
    }
    if (decoded.length === 32) {
        return Keypair.fromSeed(decoded);
    }
    throw new Error(`Unexpected base58 secret key byte length ${decoded.length}; expected 64 or 32 bytes.`);
}
export function encodeX402PaymentHeader(envelope) {
    return Buffer.from(JSON.stringify(envelope), "utf8").toString("base64");
}
export function decodeBase64Json(encoded) {
    const clean = encoded.trim();
    if (!clean)
        return null;
    try {
        const normalized = clean.replace(/-/g, "+").replace(/_/g, "/");
        const padLen = (4 - (normalized.length % 4)) % 4;
        const padded = normalized + "=".repeat(padLen);
        const jsonStr = Buffer.from(padded, "base64").toString("utf8");
        return JSON.parse(jsonStr);
    }
    catch {
        return null;
    }
}
function getHeaderValue(headers, targetName) {
    const lower = targetName.toLowerCase();
    for (const [k, v] of Object.entries(headers)) {
        if (k.toLowerCase() === lower && v !== undefined) {
            return Array.isArray(v) ? v[0] : v;
        }
    }
    return undefined;
}
export function parseX402Challenge(headers, body, fallbackUsedPings = X402_FREE_PINGS_LIMIT) {
    const headerB64 = getHeaderValue(headers, "payment-required") ??
        getHeaderValue(headers, "x-payment-required");
    const decodedHeader = headerB64 ? decodeBase64Json(headerB64) : null;
    const bodyObj = body && typeof body === "object" && !Array.isArray(body)
        ? body
        : {};
    const mergedSource = { ...(decodedHeader ?? {}), ...bodyObj };
    const headerTreasury = getHeaderValue(headers, "x-402-treasury");
    const wwwAuth = getHeaderValue(headers, "www-authenticate");
    const acceptsRaw = Array.isArray(mergedSource.accepts)
        ? mergedSource.accepts
        : Array.isArray(decodedHeader?.accepts)
            ? decodedHeader.accepts
            : [];
    let detectedTreasury = (typeof mergedSource.treasury === "string" && mergedSource.treasury) ||
        (typeof mergedSource.payTo === "string" && mergedSource.payTo) ||
        headerTreasury ||
        "";
    if (!detectedTreasury && acceptsRaw.length > 0) {
        const firstPayTo = acceptsRaw[0]?.payTo ?? acceptsRaw[0]?.treasury;
        if (typeof firstPayTo === "string") {
            detectedTreasury = firstPayTo;
        }
    }
    if (!detectedTreasury) {
        detectedTreasury = X402_TREASURY;
    }
    const treasuryVerified = detectedTreasury === X402_TREASURY;
    const freeLimitRaw = Number(mergedSource.freePingsLimit ??
        mergedSource.free_pings_limit ??
        getHeaderValue(headers, "x-free-pings-limit") ??
        X402_FREE_PINGS_LIMIT);
    const freePingsLimit = Number.isFinite(freeLimitRaw) && freeLimitRaw > 0 ? freeLimitRaw : X402_FREE_PINGS_LIMIT;
    const usedHeader = Number(getHeaderValue(headers, "x-free-pings-used"));
    const remHeader = Number(getHeaderValue(headers, "x-free-pings-remaining"));
    const freePingsUsed = Number.isFinite(usedHeader) ? usedHeader : fallbackUsedPings;
    const freePingsRemaining = Number.isFinite(remHeader) ? Math.max(0, remHeader) : 0;
    const optionADefault = {
        option: "option_a_pro_pass",
        scheme: "exact",
        network: "solana-mainnet",
        payTo: detectedTreasury,
        lamports: X402_TIERS.option_a_pro_pass.lamports,
        sol: X402_TIERS.option_a_pro_pass.sol,
        usd: X402_TIERS.option_a_pro_pass.usd,
        description: X402_TIERS.option_a_pro_pass.description
    };
    const optionBDefault = {
        option: "option_b_single_scan",
        scheme: "exact",
        network: "solana-mainnet",
        payTo: detectedTreasury,
        lamports: X402_TIERS.option_b_single_scan.lamports,
        sol: X402_TIERS.option_b_single_scan.sol,
        usd: X402_TIERS.option_b_single_scan.usd,
        description: X402_TIERS.option_b_single_scan.description
    };
    for (const item of acceptsRaw) {
        const optRaw = String(item.option ?? item.id ?? item.tier ?? "");
        const lamportsVal = Number(item.lamports ?? item.maxAmountRequired ?? item.amountLamports ?? item.amount_lamports ?? 0);
        if (optRaw.includes("option_a") || optRaw.includes("pro_pass") || lamportsVal === 26_000_000) {
            optionADefault.payTo = String(item.payTo ?? item.treasury ?? detectedTreasury);
            if (lamportsVal > 0) {
                optionADefault.lamports = lamportsVal;
                optionADefault.sol = Number((lamportsVal / 1e9).toFixed(9));
            }
            if (typeof item.description === "string") {
                optionADefault.description = item.description;
            }
        }
        else if (optRaw.includes("option_b") || optRaw.includes("single_scan") || lamportsVal === 300_000) {
            optionBDefault.payTo = String(item.payTo ?? item.treasury ?? detectedTreasury);
            if (lamportsVal > 0) {
                optionBDefault.lamports = lamportsVal;
                optionBDefault.sol = Number((lamportsVal / 1e9).toFixed(9));
            }
            if (typeof item.description === "string") {
                optionBDefault.description = item.description;
            }
        }
    }
    return {
        x402Version: Number(mergedSource.x402Version ?? 1) || 1,
        status: 402,
        treasury: detectedTreasury,
        treasuryVerified,
        freePingsLimit,
        freePingsUsed,
        freePingsRemaining,
        wwwAuthenticate: wwwAuth,
        options: {
            option_a_pro_pass: optionADefault,
            option_b_single_scan: optionBDefault
        },
        accepts: acceptsRaw,
        rawHeaderChallenge: decodedHeader,
        rawBody: body,
        instructions: {
            summary: `Free quota (${freePingsLimit} pings) exhausted. Upgrade via Solana x402 transfer to ${X402_TREASURY}: Option A = 0.026 SOL (26000000 lamports, $1.99 Unlimited Pro Pass) or Option B = 0.0003 SOL (300000 lamports, ~$0.02 single scan).`,
            manualRetry: `Send 0.026 SOL (Option A) or 0.0003 SOL (Option B) to ${X402_TREASURY} on Solana Mainnet, then retry this MCP tool call with payment_signature="<confirmed_tx_signature>" (or pro_pass_token="<X-Pro-Pass-Token>").`,
            autoPayEnv: `Set SOLANA_PRIVATE_KEY (base58 or JSON byte array) and optional X402_OPTION=option_a_pro_pass|option_b_single_scan so @rentandrugshield/mcp-server signs, pays, caches X-Pro-Pass-Token, and retries HTTP 402 transparently.`
        }
    };
}
export class X402SolanaAutoPayer {
    keypair;
    mockKeypair;
    mockSigner;
    solanaRpcUrl;
    agentId;
    customSigner;
    connection = null;
    mockNonce = 0;
    constructor(config) {
        this.mockSigner = Boolean(config.mockSigner);
        this.solanaRpcUrl = config.solanaRpcUrl || "https://api.mainnet-beta.solana.com";
        this.agentId = config.agentId;
        this.customSigner = config.paymentSigner;
        if (config.solanaPrivateKey && config.solanaPrivateKey.trim().length > 0) {
            this.keypair = parseSolanaKeypair(config.solanaPrivateKey);
        }
        else {
            this.keypair = null;
        }
        const deterministicSeed = createHash("sha256")
            .update(`rentandrugshield-x402-mock-signer:${this.agentId}`)
            .digest();
        this.mockKeypair = Keypair.fromSeed(Uint8Array.from(deterministicSeed));
    }
    canAutoPay() {
        return Boolean(this.customSigner || this.mockSigner || this.keypair);
    }
    getPayerPublicKey() {
        if (this.keypair)
            return this.keypair.publicKey.toBase58();
        if (this.mockSigner)
            return this.mockKeypair.publicKey.toBase58();
        return null;
    }
    buildManualPaymentEnvelope(signature, option, payerWallet) {
        const cleanSig = signature.trim();
        const inferredOption = cleanSig.startsWith("5MockB")
            ? "option_b_single_scan"
            : cleanSig.startsWith("5MockA")
                ? "option_a_pro_pass"
                : option;
        const tier = X402_TIERS[inferredOption];
        const payer = (payerWallet && payerWallet.trim()) ||
            this.getPayerPublicKey() ||
            this.mockKeypair.publicKey.toBase58();
        return {
            x402Version: 1,
            scheme: "exact",
            network: "solana-mainnet",
            payload: {
                signature: cleanSig,
                payer,
                option: inferredOption,
                lamports: tier.lamports,
                payTo: X402_TREASURY
            }
        };
    }
    async createAutoPayment(option, challenge) {
        if (!challenge.treasuryVerified || challenge.treasury !== X402_TREASURY) {
            throw new Error(`Refusing x402 auto-payment: upstream treasury "${challenge.treasury}" does not match locked Rent & Rug Shield treasury "${X402_TREASURY}".`);
        }
        const expectedTier = X402_TIERS[option];
        const challengeOption = challenge.options[option];
        if (challengeOption.payTo !== X402_TREASURY) {
            throw new Error(`Refusing x402 auto-payment: option ${option} payTo "${challengeOption.payTo}" does not match "${X402_TREASURY}".`);
        }
        if (challengeOption.lamports !== expectedTier.lamports) {
            throw new Error(`Refusing x402 auto-payment: option ${option} requested ${challengeOption.lamports} lamports, expected exact ${expectedTier.lamports} lamports.`);
        }
        const lamports = expectedTier.lamports;
        const payTo = X402_TREASURY;
        // 1. Custom pluggable paymentSigner callback
        if (this.customSigner) {
            const signed = await this.customSigner({ option, lamports, payTo, challenge });
            return {
                x402Version: 1,
                scheme: "exact",
                network: "solana-mainnet",
                payload: {
                    signature: signed.signature,
                    payer: signed.payer,
                    option,
                    lamports,
                    payTo
                }
            };
        }
        // 2. Deterministic offline/E2E mock signer (X402_MOCK_SIGNER=1)
        // Follows STRICT_CONTRACT_SPEC.json mock_signer_convention: 88-char base58 sigs starting with 5MockA / 5MockB
        if (this.mockSigner) {
            const signerKp = this.keypair ?? this.mockKeypair;
            const payerPubkey = signerKp.publicKey.toBase58();
            this.mockNonce += 1;
            // Also build & sign the transfer transaction in memory to verify keypair + transfer construction
            const pseudoBlockhashBytes = createHash("sha256")
                .update(`x402-mock-bh:${this.agentId}:${option}:${this.mockNonce}`)
                .digest();
            const tx = new Transaction({
                recentBlockhash: bs58.encode(Uint8Array.from(pseudoBlockhashBytes)),
                feePayer: signerKp.publicKey
            }).add(SystemProgram.transfer({
                fromPubkey: signerKp.publicKey,
                toPubkey: new PublicKey(payTo),
                lamports
            }));
            tx.sign(signerKp);
            const mockSig = generateDeterministicMockSignature(option, this.agentId, payerPubkey, this.mockNonce);
            return {
                x402Version: 1,
                scheme: "exact",
                network: "solana-mainnet",
                payload: {
                    signature: mockSig,
                    payer: payerPubkey,
                    option,
                    lamports,
                    payTo
                }
            };
        }
        // 3. Live @solana/web3.js SystemProgram.transfer broadcast
        if (!this.keypair) {
            throw new Error("No SOLANA_PRIVATE_KEY configured for automatic x402 payment.");
        }
        if (!this.connection) {
            this.connection = new Connection(this.solanaRpcUrl, "confirmed");
        }
        const latest = await this.connection.getLatestBlockhash("confirmed");
        const tx = new Transaction({
            recentBlockhash: latest.blockhash,
            feePayer: this.keypair.publicKey
        }).add(SystemProgram.transfer({
            fromPubkey: this.keypair.publicKey,
            toPubkey: new PublicKey(payTo),
            lamports
        }));
        tx.sign(this.keypair);
        const signature = await this.connection.sendRawTransaction(tx.serialize(), {
            skipPreflight: false,
            preflightCommitment: "confirmed"
        });
        await this.pollSignatureConfirmationHttp(signature);
        return {
            x402Version: 1,
            scheme: "exact",
            network: "solana-mainnet",
            payload: {
                signature,
                payer: this.keypair.publicKey.toBase58(),
                option,
                lamports,
                payTo
            }
        };
    }
    async pollSignatureConfirmationHttp(signature) {
        if (!this.connection)
            return;
        const isLocalRpc = this.solanaRpcUrl.includes("127.0.0.1") || this.solanaRpcUrl.includes("localhost");
        const maxAttempts = isLocalRpc ? 3 : 20;
        const delayMs = isLocalRpc ? 25 : 400;
        for (let attempt = 0; attempt < maxAttempts; attempt++) {
            try {
                const statusResp = await this.connection.getSignatureStatuses([signature], {
                    searchTransactionHistory: true
                });
                const status = statusResp?.value?.[0];
                if (status) {
                    if (status.err) {
                        throw new Error(`Solana x402 payment transaction failed on-chain: ${JSON.stringify(status.err)}`);
                    }
                    if (status.confirmationStatus === "confirmed" ||
                        status.confirmationStatus === "finalized" ||
                        isLocalRpc) {
                        return;
                    }
                }
            }
            catch (err) {
                if (err instanceof Error && err.message.includes("failed on-chain")) {
                    throw err;
                }
                if (isLocalRpc) {
                    return;
                }
            }
            await new Promise((r) => setTimeout(r, delayMs));
        }
    }
}
//# sourceMappingURL=x402.js.map