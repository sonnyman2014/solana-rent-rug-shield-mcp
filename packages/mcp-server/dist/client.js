import { randomBytes } from "node:crypto";
import http from "node:http";
import https from "node:https";
import { URL } from "node:url";
import { analyzeTransactionDrainFallback } from "./txSimulator.js";
import { DEFAULT_API_URL, X402_FREE_PINGS_LIMIT, X402_TIERS, X402_TREASURY } from "./types.js";
import { X402SolanaAutoPayer, encodeX402PaymentHeader, normalizeX402Option, parseX402Challenge } from "./x402.js";
const TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const DEFAULT_ROUTES = {
    auditToken: [
        "/api/v1/shield-check",
        "/api/scan-token",
        "/api/audit-mint",
        "/api/scan-mint",
        "/api/audit"
    ],
    simulateTx: [
        "/api/v1/simulate-tx",
        "/api/simulate-tx"
    ],
    scanWallet: [
        "/api/scan-wallet",
        "/api/v1/scan-wallet"
    ]
};
export class RentShieldClient {
    apiUrl;
    agentId;
    apiKey;
    auditTimeoutMs;
    requestTimeoutMs;
    routes;
    stickyRoute = new Map();
    httpAgent;
    httpsAgent;
    autoPayer;
    selectedOption;
    cachedProPassToken;
    freePingsUsed = 0;
    freePingsRemaining = X402_FREE_PINGS_LIMIT;
    paymentsExecuted = 0;
    lastPaymentSignature = null;
    solanaRpcUrl;
    constructor(options = {}) {
        const rawBase = options.apiUrl ??
            process.env.RENTSHIELD_API_URL ??
            DEFAULT_API_URL;
        this.apiUrl = rawBase.replace(/\/+$/, "");
        this.agentId =
            options.agentId ??
                process.env.X402_AGENT_ID ??
                process.env.RENTSHIELD_AGENT_ID ??
                process.env.X_AGENT_ID ??
                `mcp-agent-${randomBytes(6).toString("hex")}`;
        this.apiKey = options.apiKey ?? process.env.RENTSHIELD_API_KEY;
        this.cachedProPassToken =
            options.proPassToken ??
                process.env.X402_PRO_PASS_TOKEN ??
                process.env.RENTSHIELD_PRO_PASS_TOKEN ??
                process.env.X_PRO_PASS_TOKEN ??
                null;
        const envOption = options.x402Option ?? process.env.X402_OPTION ?? "option_a_pro_pass";
        this.selectedOption = normalizeX402Option(envOption);
        const envPrivKey = options.solanaPrivateKey ??
            process.env.SOLANA_PRIVATE_KEY ??
            process.env.X402_SOLANA_PRIVATE_KEY;
        const envMockRaw = (process.env.X402_MOCK_SIGNER ?? "").trim().toLowerCase();
        const mockSigner = options.mockSigner !== undefined
            ? options.mockSigner
            : envMockRaw === "1" || envMockRaw === "true" || envMockRaw === "yes";
        this.solanaRpcUrl =
            options.solanaRpcUrl ??
                process.env.SOLANA_RPC_URL ??
                "https://api.mainnet-beta.solana.com";
        const parsedAuditTimeout = Number(options.auditTimeoutMs ?? process.env.RENTSHIELD_AUDIT_TIMEOUT_MS ?? 3500);
        this.auditTimeoutMs =
            Number.isFinite(parsedAuditTimeout) && parsedAuditTimeout > 0
                ? parsedAuditTimeout
                : 3500;
        const parsedReqTimeout = Number(options.requestTimeoutMs ?? process.env.RENTSHIELD_TIMEOUT_MS ?? 8000);
        this.requestTimeoutMs =
            Number.isFinite(parsedReqTimeout) && parsedReqTimeout > 0
                ? parsedReqTimeout
                : 8000;
        this.routes = {
            auditToken: options.routes?.auditToken ?? [...DEFAULT_ROUTES.auditToken],
            simulateTx: options.routes?.simulateTx ?? [...DEFAULT_ROUTES.simulateTx],
            scanWallet: options.routes?.scanWallet ?? [...DEFAULT_ROUTES.scanWallet]
        };
        // Persistent keep-alive connection pools for <120ms pre-buy token audits
        this.httpAgent = new http.Agent({
            keepAlive: true,
            keepAliveMsecs: 30_000,
            maxSockets: 64,
            maxFreeSockets: 16
        });
        this.httpsAgent = new https.Agent({
            keepAlive: true,
            keepAliveMsecs: 30_000,
            maxSockets: 64,
            maxFreeSockets: 16
        });
        this.autoPayer = new X402SolanaAutoPayer({
            solanaPrivateKey: envPrivKey,
            solanaRpcUrl: this.solanaRpcUrl,
            mockSigner,
            agentId: this.agentId,
            paymentSigner: options.paymentSigner
        });
    }
    getQuotaState() {
        return {
            agentId: this.agentId,
            freePingsLimit: X402_FREE_PINGS_LIMIT,
            freePingsUsed: this.freePingsUsed,
            freePingsRemaining: this.freePingsRemaining,
            hasProPassToken: Boolean(this.cachedProPassToken),
            proPassToken: this.cachedProPassToken,
            autoPayEnabled: this.autoPayer.canAutoPay(),
            selectedOption: this.selectedOption,
            paymentsExecuted: this.paymentsExecuted,
            lastPaymentSignature: this.lastPaymentSignature
        };
    }
    setX402Option(option) {
        this.selectedOption = normalizeX402Option(option);
    }
    setProPassToken(token) {
        this.cachedProPassToken = token;
    }
    destroy() {
        this.httpAgent.destroy();
        this.httpsAgent.destroy();
    }
    async auditSolanaToken10Layer(input) {
        const mint = (input.mint ?? "").trim();
        if (!mint) {
            throw new Error("Parameter 'mint' is required for audit_solana_token_10_layer.");
        }
        const payload = {
            mint,
            user_initiated: false
        };
        if (input.pool_address)
            payload.pool_address = input.pool_address.trim();
        if (input.wallet)
            payload.wallet = input.wallet.trim();
        return this.executeGatewayCall({
            routeKey: "auditToken",
            payload,
            timeoutMs: this.auditTimeoutMs,
            manualPaymentSignature: input.payment_signature,
            manualProPassToken: input.pro_pass_token,
            payerHint: input.wallet
        });
    }
    async simulateSolanaTxDrain(input) {
        const transaction = (input.transaction ?? "").trim();
        if (!transaction) {
            throw new Error("Parameter 'transaction' is required for simulate_solana_tx_drain.");
        }
        const encoding = input.encoding ?? "base64";
        const payload = {
            transaction,
            encoding
        };
        if (input.wallet)
            payload.wallet = input.wallet.trim();
        return this.executeGatewayCall({
            routeKey: "simulateTx",
            payload,
            timeoutMs: this.requestTimeoutMs,
            manualPaymentSignature: input.payment_signature,
            manualProPassToken: input.pro_pass_token,
            payerHint: input.wallet,
            onAllRoutesNotFound: async () => {
                const fallback = await analyzeTransactionDrainFallback({
                    transaction,
                    wallet: input.wallet,
                    encoding,
                    solanaRpcUrl: this.solanaRpcUrl,
                    enableRpcSimulation: false
                });
                return fallback;
            }
        });
    }
    async scanWalletUnclaimedSol(input) {
        const wallet = (input.wallet ?? "").trim();
        if (!wallet) {
            throw new Error("Parameter 'wallet' is required for scan_wallet_unclaimed_sol.");
        }
        const includeToken2022 = input.include_token_2022 ?? true;
        const payload = {
            wallet,
            include_token_2022: includeToken2022,
            user_initiated: false,
            auto_collect: false
        };
        const res = await this.executeGatewayCall({
            routeKey: "scanWallet",
            payload,
            timeoutMs: this.requestTimeoutMs,
            manualPaymentSignature: input.payment_signature,
            manualProPassToken: input.pro_pass_token,
            payerHint: wallet
        });
        if (!includeToken2022 && res.ok && res.data && typeof res.data === "object") {
            res.data = filterToken2022Accounts(res.data);
        }
        return res;
    }
    getOrderedRoutes(routeKey) {
        const base = this.routes[routeKey];
        const sticky = this.stickyRoute.get(routeKey);
        if (!sticky)
            return base;
        return [sticky, ...base.filter((r) => r !== sticky)];
    }
    async executeGatewayCall(params) {
        const startNs = process.hrtime.bigint();
        const candidateRoutes = this.getOrderedRoutes(params.routeKey);
        const activeProPass = (params.manualProPassToken && params.manualProPassToken.trim()) ||
            this.cachedProPassToken;
        const baseHeaders = {
            "X-Agent-Id": this.agentId,
            "User-Agent": "@rentandrugshield/mcp-server/1.0.0",
            Accept: "application/json",
            "Content-Type": "application/json"
        };
        if (this.apiKey) {
            baseHeaders["X-API-Key"] = this.apiKey;
        }
        if (activeProPass) {
            baseHeaders["X-Pro-Pass-Token"] = activeProPass;
        }
        if (params.manualPaymentSignature && params.manualPaymentSignature.trim()) {
            const manualEnv = this.autoPayer.buildManualPaymentEnvelope(params.manualPaymentSignature, this.selectedOption, params.payerHint);
            const b64 = encodeX402PaymentHeader(manualEnv);
            baseHeaders["X-Payment"] = b64;
            baseHeaders["Payment-Signature"] = b64;
            baseHeaders["X-Solana-Tx-Signature"] = params.manualPaymentSignature.trim();
        }
        let lastResp = null;
        let matchedRoute = null;
        for (const route of candidateRoutes) {
            const resp = await this.rawPostJson(route, params.payload, baseHeaders, params.timeoutMs);
            lastResp = resp;
            // Fallback ONLY on 404 or 405; ALWAYS propagate 402 to x402 handler
            if (resp.status === 404 || resp.status === 405) {
                continue;
            }
            matchedRoute = route;
            this.stickyRoute.set(params.routeKey, route);
            break;
        }
        // All candidate routes returned 404/405 (e.g. unpatched upstream simulate route)
        if (!matchedRoute &&
            (lastResp?.status === 404 || lastResp?.status === 405) &&
            params.onAllRoutesNotFound) {
            const fallbackData = await params.onAllRoutesNotFound();
            const latencyMs = Number(process.hrtime.bigint() - startNs) / 1e6;
            return {
                ok: true,
                status: 200,
                latencyMs: Number(latencyMs.toFixed(2)),
                quota: {
                    agentId: this.agentId,
                    freePingsUsed: this.freePingsUsed,
                    freePingsRemaining: this.freePingsRemaining,
                    proPassActive: Boolean(this.cachedProPassToken)
                },
                data: fallbackData
            };
        }
        const effectiveResp = lastResp;
        const effectiveRoute = matchedRoute ?? candidateRoutes[0];
        this.updateQuotaFromHeaders(effectiveResp.headers, effectiveResp.status >= 200 &&
            effectiveResp.status < 300 &&
            !activeProPass &&
            !params.manualPaymentSignature);
        this.captureProPassToken(effectiveResp.headers, effectiveResp.bodyJson);
        // Handle HTTP 402 Payment Required -> Solana x402 Auto-Upgrade or Structured Challenge
        if (effectiveResp.status === 402) {
            const challenge = parseX402Challenge(effectiveResp.headers, effectiveResp.bodyJson, this.freePingsUsed || X402_FREE_PINGS_LIMIT);
            this.freePingsUsed = challenge.freePingsUsed;
            this.freePingsRemaining = challenge.freePingsRemaining;
            if (this.autoPayer.canAutoPay() && !params.manualPaymentSignature) {
                const option = this.selectedOption;
                const paymentEnvelope = await this.autoPayer.createAutoPayment(option, challenge);
                const encodedPayment = encodeX402PaymentHeader(paymentEnvelope);
                this.paymentsExecuted += 1;
                this.lastPaymentSignature = paymentEnvelope.payload.signature;
                const retryHeaders = {
                    ...baseHeaders,
                    "X-Payment": encodedPayment,
                    "Payment-Signature": encodedPayment,
                    "X-Solana-Tx-Signature": paymentEnvelope.payload.signature
                };
                const retryResp = await this.rawPostJson(effectiveRoute, params.payload, retryHeaders, params.timeoutMs);
                const tokenCachedBefore = this.cachedProPassToken;
                this.captureProPassToken(retryResp.headers, retryResp.bodyJson);
                const proPassTokenCached = Boolean(this.cachedProPassToken && this.cachedProPassToken !== tokenCachedBefore) ||
                    Boolean(this.cachedProPassToken && option === "option_a_pro_pass");
                const latencyMs = Number(process.hrtime.bigint() - startNs) / 1e6;
                const dataObj = this.normalizeBodyObject(retryResp.bodyJson, retryResp.bodyText, retryResp.status);
                return {
                    ok: retryResp.status >= 200 && retryResp.status < 300 && dataObj.ok !== false,
                    status: retryResp.status,
                    latencyMs: Number(latencyMs.toFixed(2)),
                    x402AutoPaid: {
                        option,
                        lamports: X402_TIERS[option].lamports,
                        sol: X402_TIERS[option].sol,
                        signature: paymentEnvelope.payload.signature,
                        payer: paymentEnvelope.payload.payer,
                        payTo: X402_TREASURY,
                        proPassTokenCached
                    },
                    quota: {
                        agentId: this.agentId,
                        freePingsUsed: this.freePingsUsed,
                        freePingsRemaining: this.freePingsRemaining,
                        proPassActive: Boolean(this.cachedProPassToken)
                    },
                    data: dataObj
                };
            }
            const latencyMs = Number(process.hrtime.bigint() - startNs) / 1e6;
            return {
                ok: false,
                status: 402,
                latencyMs: Number(latencyMs.toFixed(2)),
                paymentRequired: true,
                x402Challenge: challenge,
                quota: {
                    agentId: this.agentId,
                    freePingsUsed: this.freePingsUsed,
                    freePingsRemaining: 0,
                    proPassActive: false
                },
                data: {
                    ok: false,
                    status: 402,
                    payment_required: true,
                    treasury: challenge.treasury,
                    options: challenge.options,
                    instructions: challenge.instructions
                }
            };
        }
        const latencyMs = Number(process.hrtime.bigint() - startNs) / 1e6;
        const dataObj = this.normalizeBodyObject(effectiveResp.bodyJson, effectiveResp.bodyText, effectiveResp.status);
        return {
            ok: effectiveResp.status >= 200 && effectiveResp.status < 300 && dataObj.ok !== false,
            status: effectiveResp.status,
            latencyMs: Number(latencyMs.toFixed(2)),
            quota: {
                agentId: this.agentId,
                freePingsUsed: this.freePingsUsed,
                freePingsRemaining: this.freePingsRemaining,
                proPassActive: Boolean(this.cachedProPassToken)
            },
            data: dataObj
        };
    }
    updateQuotaFromHeaders(headers, incrementLocalIfMissing) {
        const usedHdr = headers["x-free-pings-used"];
        const remHdr = headers["x-free-pings-remaining"];
        const usedVal = Number(Array.isArray(usedHdr) ? usedHdr[0] : usedHdr);
        const remVal = Number(Array.isArray(remHdr) ? remHdr[0] : remHdr);
        if (Number.isFinite(usedVal)) {
            this.freePingsUsed = usedVal;
        }
        else if (incrementLocalIfMissing && this.freePingsUsed < X402_FREE_PINGS_LIMIT) {
            this.freePingsUsed += 1;
        }
        if (Number.isFinite(remVal)) {
            this.freePingsRemaining = Math.max(0, remVal);
        }
        else if (incrementLocalIfMissing) {
            this.freePingsRemaining = Math.max(0, X402_FREE_PINGS_LIMIT - this.freePingsUsed);
        }
    }
    captureProPassToken(headers, bodyJson) {
        const hdrToken = headers["x-pro-pass-token"];
        const tokenStr = Array.isArray(hdrToken) ? hdrToken[0] : hdrToken;
        if (tokenStr && tokenStr.trim()) {
            this.cachedProPassToken = tokenStr.trim();
            return;
        }
        if (bodyJson && typeof bodyJson === "object" && !Array.isArray(bodyJson)) {
            const obj = bodyJson;
            const bodyTok = obj.pro_pass_token ?? obj.proPassToken ?? obj.x_pro_pass_token;
            if (typeof bodyTok === "string" && bodyTok.trim()) {
                this.cachedProPassToken = bodyTok.trim();
            }
        }
    }
    normalizeBodyObject(bodyJson, bodyText, status) {
        if (bodyJson && typeof bodyJson === "object" && !Array.isArray(bodyJson)) {
            return bodyJson;
        }
        return {
            ok: status >= 200 && status < 300,
            status,
            raw: bodyText
        };
    }
    rawPostJson(routePath, payload, headers, timeoutMs) {
        return new Promise((resolve, reject) => {
            const targetUrl = new URL(routePath, `${this.apiUrl}/`);
            const isHttps = targetUrl.protocol === "https:";
            const bodyStr = JSON.stringify(payload);
            const bodyByteLen = Buffer.byteLength(bodyStr, "utf8");
            const reqOptions = {
                protocol: targetUrl.protocol,
                hostname: targetUrl.hostname,
                port: targetUrl.port || (isHttps ? 443 : 80),
                path: `${targetUrl.pathname}${targetUrl.search}`,
                method: "POST",
                headers: {
                    ...headers,
                    "Content-Length": String(bodyByteLen)
                },
                agent: isHttps ? this.httpsAgent : this.httpAgent,
                timeout: timeoutMs
            };
            const transport = isHttps ? https : http;
            const req = transport.request(reqOptions, (res) => {
                res.setEncoding("utf8");
                let raw = "";
                res.on("data", (chunk) => {
                    raw += chunk;
                });
                res.on("end", () => {
                    let parsed = null;
                    if (raw.length > 0) {
                        try {
                            parsed = JSON.parse(raw);
                        }
                        catch {
                            parsed = null;
                        }
                    }
                    resolve({
                        status: res.statusCode ?? 500,
                        headers: res.headers,
                        bodyText: raw,
                        bodyJson: parsed
                    });
                });
            });
            req.on("socket", (socket) => {
                socket.setNoDelay(true);
            });
            req.on("timeout", () => {
                req.destroy(new Error(`Rent & Rug Shield request timed out after ${timeoutMs}ms (${routePath})`));
            });
            req.on("error", (err) => {
                reject(err);
            });
            req.write(bodyStr);
            req.end();
        });
    }
}
function isToken2022Entry(row) {
    if (!row || typeof row !== "object")
        return false;
    const rec = row;
    const prog = String(rec.program_id ?? rec.programId ?? rec.token_program ?? "");
    return prog === TOKEN_2022_PROGRAM_ID || prog.toLowerCase() === "token-2022";
}
function sumRentLamports(rows) {
    let total = 0;
    for (const r of rows) {
        if (r && typeof r === "object") {
            const lam = Number(r.rent_lamports ?? 0);
            if (Number.isFinite(lam) && lam > 0)
                total += lam;
        }
    }
    return total;
}
function filterToken2022Accounts(data) {
    const clone = { ...data };
    const emptyList = Array.isArray(clone.empty_reclaimable)
        ? clone.empty_reclaimable.filter((x) => !isToken2022Entry(x))
        : null;
    const dustList = Array.isArray(clone.dust_reclaimable)
        ? clone.dust_reclaimable.filter((x) => !isToken2022Entry(x))
        : null;
    const activeList = Array.isArray(clone.active_holdings)
        ? clone.active_holdings.filter((x) => !isToken2022Entry(x))
        : null;
    const frozenList = Array.isArray(clone.frozen_traps)
        ? clone.frozen_traps.filter((x) => !isToken2022Entry(x))
        : null;
    if (!emptyList && !dustList) {
        return clone;
    }
    const finalEmpty = emptyList ?? [];
    const finalDust = dustList ?? [];
    if (emptyList)
        clone.empty_reclaimable = finalEmpty;
    if (dustList)
        clone.dust_reclaimable = finalDust;
    if (activeList) {
        clone.active_holdings = activeList;
        clone.active_count = activeList.length;
    }
    if (frozenList)
        clone.frozen_traps = frozenList;
    const instantLamports = sumRentLamports(finalEmpty);
    const dustLamports = sumRentLamports(finalDust);
    const totalLamports = instantLamports + dustLamports;
    const totalSol = Number((totalLamports / 1e9).toFixed(6));
    const solUsd = Number(clone.sol_usd ?? 0);
    clone.empty_count = finalEmpty.length;
    clone.empty_accounts = finalEmpty.length;
    clone.dust_count = finalDust.length;
    clone.reclaimable_count = finalEmpty.length + finalDust.length;
    clone.instant_reclaimable_lamports = instantLamports;
    clone.instant_reclaimable_sol = Number((instantLamports / 1e9).toFixed(6));
    clone.dust_reclaimable_lamports = dustLamports;
    clone.dust_reclaimable_sol = Number((dustLamports / 1e9).toFixed(6));
    clone.total_reclaimable_lamports = totalLamports;
    clone.total_reclaimable_sol = totalSol;
    if (Number.isFinite(solUsd) && solUsd > 0) {
        clone.total_reclaimable_usd = Number((totalSol * solUsd).toFixed(2));
    }
    clone.include_token_2022 = false;
    return clone;
}
//# sourceMappingURL=client.js.map