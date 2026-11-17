import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { describe, it } from "node:test";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction
} from "@solana/web3.js";
import bs58 from "bs58";
import {
  RentShieldClient,
  X402_TREASURY,
  analyzeTransactionDrainFallback,
  decodeBase64Json,
  generateDeterministicMockSignature,
  parseSolanaKeypair,
  type X402PaymentEnvelope
} from "../src/index.js";

function createMockX402Gateway() {
  const agentCounts = new Map<string, number>();
  const usedSignatures = new Set<string>();
  const validProTokens = new Set<string>();
  let totalPaidOptionA = 0;
  let totalPaidOptionB = 0;

  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const url = req.url ?? "/";
      const body = raw ? JSON.parse(raw) : {};
      const agentId = String(req.headers["x-agent-id"] ?? "anon");
      const proToken = String(req.headers["x-pro-pass-token"] ?? "");
      const xPayment = String(req.headers["x-payment"] ?? "");

      // Route check
      const supported = new Set([
        "/api/v1/shield-check",
        "/api/v1/simulate-tx",
        "/api/scan-wallet"
      ]);
      if (!supported.has(url)) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: "Not found" }));
        return;
      }

      let authorizedViaPro = proToken && validProTokens.has(proToken);
      let issuedProToken = "";

      if (!authorizedViaPro && xPayment) {
        const decoded = decodeBase64Json<X402PaymentEnvelope>(xPayment);
        if (
          !decoded ||
          decoded.x402Version !== 1 ||
          decoded.scheme !== "exact" ||
          decoded.payload.payTo !== X402_TREASURY
        ) {
          res.writeHead(402, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: false, error: "Invalid X-Payment header" }));
          return;
        }
        const sig = decoded.payload.signature;
        if (usedSignatures.has(sig)) {
          res.writeHead(409, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: false, code: "TX_REPLAY_BLOCKED" }));
          return;
        }
        usedSignatures.add(sig);

        if (
          decoded.payload.option === "option_a_pro_pass" &&
          decoded.payload.lamports >= 26_000_000
        ) {
          totalPaidOptionA += 1;
          issuedProToken = `pro_live_${totalPaidOptionA}_${agentId}`;
          validProTokens.add(issuedProToken);
        } else if (
          decoded.payload.option === "option_b_single_scan" &&
          decoded.payload.lamports >= 300_000
        ) {
          totalPaidOptionB += 1;
        } else {
          res.writeHead(402, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: false, error: "Underpayment" }));
          return;
        }
      } else if (!authorizedViaPro) {
        const used = agentCounts.get(agentId) ?? 0;
        if (used >= 10) {
          const challengeObj = {
            ok: false,
            code: "PAYMENT_REQUIRED",
            x402Version: 1,
            treasury: X402_TREASURY,
            freePingsLimit: 10,
            freePingsUsed: 10,
            freePingsRemaining: 0,
            accepts: [
              {
                option: "option_a_pro_pass",
                scheme: "exact",
                network: "solana-mainnet",
                payTo: X402_TREASURY,
                lamports: 26_000_000
              },
              {
                option: "option_b_single_scan",
                scheme: "exact",
                network: "solana-mainnet",
                payTo: X402_TREASURY,
                lamports: 300_000
              }
            ]
          };
          const b64Challenge = Buffer.from(JSON.stringify(challengeObj), "utf8").toString("base64");
          res.writeHead(402, {
            "Content-Type": "application/json",
            "WWW-Authenticate": `x402 network="solana:mainnet-beta", treasury="${X402_TREASURY}", option_a_sol="0.026", option_b_sol="0.0003"`,
            "Payment-Required": b64Challenge,
            "X-Payment-Required": b64Challenge,
            "X-402-Treasury": X402_TREASURY,
            "X-Free-Pings-Used": "10",
            "X-Free-Pings-Remaining": "0"
          });
          res.end(JSON.stringify(challengeObj));
          return;
        }
        const nextUsed = used + 1;
        agentCounts.set(agentId, nextUsed);
        res.setHeader("X-Free-Pings-Limit", "10");
        res.setHeader("X-Free-Pings-Used", String(nextUsed));
        res.setHeader("X-Free-Pings-Remaining", String(10 - nextUsed));
      }

      if (issuedProToken) {
        res.setHeader("X-Pro-Pass-Token", issuedProToken);
      }

      res.setHeader("Content-Type", "application/json");
      if (url === "/api/v1/shield-check") {
        res.writeHead(200);
        res.end(
          JSON.stringify({
            ok: true,
            mint: body.mint,
            symbol: "$BONK",
            score: 96,
            safe_to_buy: true,
            verdict: "SAFE",
            layers_checked: 10,
            layers_passed: 10,
            audit_ms: 5
          })
        );
      } else if (url === "/api/v1/simulate-tx") {
        res.writeHead(200);
        res.end(
          JSON.stringify({
            ok: true,
            safe: true,
            drain_detected: false,
            inner_cpi_drain: false,
            risk_level: "SAFE",
            verdict: "SAFE"
          })
        );
      } else {
        res.writeHead(200);
        res.end(
          JSON.stringify({
            ok: true,
            wallet: body.wallet,
            user_initiated_received: body.user_initiated,
            auto_collect_received: body.auto_collect,
            sol_usd: 150,
            empty_count: 2,
            dust_count: 0,
            reclaimable_count: 2,
            total_reclaimable_lamports: 4_078_560,
            total_reclaimable_sol: 0.004079,
            empty_reclaimable: [
              {
                ata: "AtaSpl1111111111111111111111111111111111111",
                program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                rent_lamports: 2_039_280
              },
              {
                ata: "AtaT221111111111111111111111111111111111111",
                program_id: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
                rent_lamports: 2_039_280
              }
            ],
            dust_reclaimable: []
          })
        );
      }
    });
  });

  return {
    server,
    getStats: () => ({ totalPaidOptionA, totalPaidOptionB, usedCount: usedSignatures.size })
  };
}

describe("x402 Keypair, Mock Signer, and RentShieldClient Unit Suite", () => {
  it("parses base58, JSON byte array, and 32-byte seed Solana private keys", () => {
    const kp = Keypair.generate();
    const fromB58 = parseSolanaKeypair(bs58.encode(kp.secretKey));
    assert.equal(fromB58.publicKey.toBase58(), kp.publicKey.toBase58());

    const fromJson64 = parseSolanaKeypair(JSON.stringify(Array.from(kp.secretKey)));
    assert.equal(fromJson64.publicKey.toBase58(), kp.publicKey.toBase58());

    const fromJson32 = parseSolanaKeypair(JSON.stringify(Array.from(kp.secretKey.slice(0, 32))));
    assert.equal(fromJson32.publicKey.toBase58(), kp.publicKey.toBase58());
  });

  it("generates 88-char base58 mock signatures with 5MockA / 5MockB prefixes", () => {
    const sigA1 = generateDeterministicMockSignature("option_a_pro_pass", "ag1", "payer1", 1);
    const sigA2 = generateDeterministicMockSignature("option_a_pro_pass", "ag1", "payer1", 2);
    const sigB1 = generateDeterministicMockSignature("option_b_single_scan", "ag1", "payer1", 1);

    assert.equal(sigA1.length, 88);
    assert.equal(sigB1.length, 88);
    assert.ok(sigA1.startsWith("5MockA"));
    assert.ok(sigB1.startsWith("5MockB"));
    assert.notEqual(sigA1, sigA2);
    assert.equal(/[0OIl]/.test(sigA1), false);
  });

  it("completes 10 free pings, returns structured 402 when unpaid, and accepts manual payment_signature", async () => {
    const { server } = createMockX402Gateway();
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as AddressInfo).port;
    const client = new RentShieldClient({
      apiUrl: `http://127.0.0.1:${port}`,
      agentId: "unpaid-agent-test",
      mockSigner: false,
      solanaPrivateKey: ""
    });

    try {
      for (let i = 1; i <= 10; i++) {
        const res = await client.auditSolanaToken10Layer({
          mint: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"
        });
        assert.equal(res.ok, true);
        assert.equal(res.status, 200);
        assert.equal(res.quota.freePingsUsed, i);
        assert.equal(res.quota.freePingsRemaining, 10 - i);
      }

      // 11th ping without key -> structured 402 challenge
      const ch = await client.auditSolanaToken10Layer({
        mint: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"
      });
      assert.equal(ch.ok, false);
      assert.equal(ch.status, 402);
      assert.equal(ch.paymentRequired, true);
      assert.equal(ch.x402Challenge?.treasury, X402_TREASURY);
      assert.equal(ch.x402Challenge?.options.option_a_pro_pass.lamports, 26_000_000);
      assert.equal(ch.x402Challenge?.options.option_b_single_scan.lamports, 300_000);

      // Manual retry with payment_signature
      const manualSig = generateDeterministicMockSignature("option_b_single_scan", "manual", "w1", 99);
      const retry = await client.auditSolanaToken10Layer({
        mint: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
        payment_signature: manualSig
      });
      assert.equal(retry.ok, true);
      assert.equal(retry.status, 200);
    } finally {
      client.destroy();
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it("auto-pays Option A (0.026 SOL) via real @solana/web3.js RPC transfer and caches X-Pro-Pass-Token", async () => {
    const { server, getStats } = createMockX402Gateway();
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const apiPort = (server.address() as AddressInfo).port;

    // Spin up a local mock Solana JSON-RPC server verifying the actual SystemProgram.transfer tx!
    let broadcastedLamports = 0;
    let broadcastedRecipient = "";
    const validBlockhash = Keypair.generate().publicKey.toBase58();
    const rpcServer = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const rpc = JSON.parse(body);
        res.setHeader("Content-Type", "application/json");
        if (rpc.method === "getLatestBlockhash") {
          res.end(
            JSON.stringify({
              jsonrpc: "2.0",
              id: rpc.id,
              result: {
                context: { slot: 100 },
                value: { blockhash: validBlockhash, lastValidBlockHeight: 999999 }
              }
            })
          );
          return;
        }
        if (rpc.method === "sendTransaction") {
          const rawTxB64 = rpc.params[0];
          const txBuf = Buffer.from(rawTxB64, "base64");
          const tx = Transaction.from(txBuf);
          assert.equal(tx.verifySignatures(), true);
          const ix = tx.instructions[0];
          broadcastedRecipient = ix.keys[1].pubkey.toBase58();
          const view = new DataView(ix.data.buffer, ix.data.byteOffset, ix.data.byteLength);
          broadcastedLamports = Number(view.getBigUint64(4, true));
          const sig = bs58.encode(Uint8Array.from(tx.signature!));
          res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result: sig }));
          return;
        }
        if (rpc.method === "getSignatureStatuses" || rpc.method === "confirmTransaction") {
          res.end(
            JSON.stringify({
              jsonrpc: "2.0",
              id: rpc.id,
              result: {
                context: { slot: 101 },
                value: [{ confirmationStatus: "confirmed", err: null }]
              }
            })
          );
          return;
        }
        res.statusCode = 400;
        res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, error: { code: -32601, message: "Unsupported" } }));
      });
    });

    await new Promise<void>((r) => rpcServer.listen(0, "127.0.0.1", r));
    const rpcPort = (rpcServer.address() as AddressInfo).port;
    const payerKeypair = Keypair.generate();

    const client = new RentShieldClient({
      apiUrl: `http://127.0.0.1:${apiPort}`,
      agentId: "live-web3-option-a",
      solanaPrivateKey: bs58.encode(payerKeypair.secretKey),
      solanaRpcUrl: `http://127.0.0.1:${rpcPort}`,
      x402Option: "option_a_pro_pass",
      mockSigner: false
    });

    try {
      for (let i = 0; i < 10; i++) {
        const r = await client.auditSolanaToken10Layer({
          mint: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"
        });
        assert.equal(r.ok, true);
      }

      // 11th call triggers 402 -> real @solana/web3.js tx build + send + retry -> caches X-Pro-Pass-Token
      const upgraded = await client.auditSolanaToken10Layer({
        mint: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"
      });
      assert.equal(upgraded.ok, true);
      assert.equal(upgraded.status, 200);
      assert.equal(upgraded.x402AutoPaid?.option, "option_a_pro_pass");
      assert.equal(upgraded.x402AutoPaid?.lamports, 26_000_000);
      assert.equal(upgraded.x402AutoPaid?.proPassTokenCached, true);
      assert.equal(broadcastedRecipient, X402_TREASURY);
      assert.equal(broadcastedLamports, 26_000_000);

      // Calls 12..15 reuse cached X-Pro-Pass-Token with 0 extra payments!
      for (let i = 0; i < 4; i++) {
        const sub = await client.auditSolanaToken10Layer({
          mint: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"
        });
        assert.equal(sub.ok, true);
        assert.equal(sub.x402AutoPaid, undefined);
      }
      assert.equal(getStats().totalPaidOptionA, 1);
      assert.equal(client.getQuotaState().paymentsExecuted, 1);
    } finally {
      client.destroy();
      await new Promise<void>((r) => server.close(() => r()));
      await new Promise<void>((r) => rpcServer.close(() => r()));
    }
  });

  it("enforces read-only flags and filters Token-2022 accounts when include_token_2022=false", async () => {
    const { server } = createMockX402Gateway();
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as AddressInfo).port;
    const client = new RentShieldClient({
      apiUrl: `http://127.0.0.1:${port}`,
      agentId: "wallet-filter-test"
    });

    try {
      const wallet = Keypair.generate().publicKey.toBase58();
      const filtered = await client.scanWalletUnclaimedSol({
        wallet,
        include_token_2022: false
      });
      assert.equal(filtered.ok, true);
      assert.equal(filtered.data.user_initiated_received, false);
      assert.equal(filtered.data.auto_collect_received, false);
      assert.equal(filtered.data.empty_count, 1);
      assert.equal(filtered.data.reclaimable_count, 1);
      assert.equal(filtered.data.total_reclaimable_lamports, 2_039_280);
    } finally {
      client.destroy();
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it("detects malicious SetAuthority drainer in local Layer-9 fallback simulator", async () => {
    const victim = Keypair.generate();
    const attacker = Keypair.generate();
    const bh = Keypair.generate().publicKey.toBase58();

    // Build malicious SPL Token SetAuthority (opcode 6) instruction
    const maliciousTx = new Transaction({
      recentBlockhash: bh,
      feePayer: victim.publicKey
    }).add({
      programId: new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
      keys: [
        { pubkey: victim.publicKey, isSigner: true, isWritable: true },
        { pubkey: attacker.publicKey, isSigner: false, isWritable: false }
      ],
      data: Buffer.from([6, 2, 1])
    });
    const b64Malicious = maliciousTx
      .serialize({ requireAllSignatures: false, verifySignatures: false })
      .toString("base64");

    const report = await analyzeTransactionDrainFallback({
      transaction: b64Malicious,
      wallet: victim.publicKey.toBase58(),
      encoding: "base64"
    });
    assert.equal(report.ok, true);
    assert.equal(report.safe, false);
    assert.equal(report.drain_detected, true);
    assert.equal(report.risk_level, "CRITICAL");
    assert.ok(report.drainer_indicators.some((x) => x.includes("SetAuthority")));
  });
});
