import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Keypair, SystemProgram, Transaction } from "@solana/web3.js";
import { X402_TREASURY, decodeBase64Json, type X402PaymentEnvelope } from "../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DIST_ENTRY = path.resolve(__dirname, "../dist/index.js");

function startLocalGatewayServer() {
  const freeQuota = new Map<string, number>();
  const seenSigs = new Set<string>();
  const proTokens = new Set<string>();

  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const agentId = String(req.headers["x-agent-id"] ?? "stdio-agent");
      const proTok = String(req.headers["x-pro-pass-token"] ?? "");
      const xPay = String(req.headers["x-payment"] ?? "");
      const body = raw ? JSON.parse(raw) : {};

      let hasPro = Boolean(proTok && proTokens.has(proTok));
      let newProTok = "";

      if (!hasPro && xPay) {
        const env = decodeBase64Json<X402PaymentEnvelope>(xPay);
        if (
          !env ||
          env.payload.payTo !== X402_TREASURY ||
          seenSigs.has(env.payload.signature)
        ) {
          res.writeHead(402, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: false, error: "Invalid or replayed payment" }));
          return;
        }
        seenSigs.add(env.payload.signature);
        if (env.payload.option === "option_a_pro_pass" && env.payload.lamports === 26_000_000) {
          newProTok = `pro_stdio_${seenSigs.size}`;
          proTokens.add(newProTok);
        } else if (
          env.payload.option === "option_b_single_scan" &&
          env.payload.lamports === 300_000
        ) {
          // Valid single scan
        } else {
          res.writeHead(402, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: false, error: "Wrong option/lamports" }));
          return;
        }
      } else if (!hasPro) {
        const count = freeQuota.get(agentId) ?? 0;
        if (count >= 10) {
          const ch = {
            x402Version: 1,
            treasury: X402_TREASURY,
            freePingsLimit: 10,
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
          const b64 = Buffer.from(JSON.stringify(ch), "utf8").toString("base64");
          res.writeHead(402, {
            "Content-Type": "application/json",
            "Payment-Required": b64,
            "X-Payment-Required": b64,
            "X-402-Treasury": X402_TREASURY
          });
          res.end(JSON.stringify(ch));
          return;
        }
        freeQuota.set(agentId, count + 1);
        res.setHeader("X-Free-Pings-Used", String(count + 1));
        res.setHeader("X-Free-Pings-Remaining", String(10 - (count + 1)));
      }

      if (newProTok) {
        res.setHeader("X-Pro-Pass-Token", newProTok);
      }

      res.writeHead(200, { "Content-Type": "application/json" });
      if (req.url === "/api/v1/shield-check") {
        res.end(
          JSON.stringify({
            ok: true,
            mint: body.mint,
            symbol: "$JUP",
            score: 95,
            safe_to_buy: true,
            verdict: "SAFE"
          })
        );
      } else if (req.url === "/api/v1/simulate-tx") {
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
      } else if (req.url === "/api/scan-wallet") {
        res.end(
          JSON.stringify({
            ok: true,
            wallet: body.wallet,
            reclaimable_count: 3,
            total_reclaimable_sol: 0.006118
          })
        );
      } else {
        res.end(JSON.stringify({ ok: false }));
      }
    });
  });

  return { server, seenSigs };
}

describe("MCP Stdio JSON-RPC 2.0 Integration Suite (dist/index.js)", () => {
  it("runs initialize, tools/list, <120ms warm audit, all 3 tools, and 10 free pings -> x402 Option A & B upgrades", async () => {
    const { server, seenSigs } = startLocalGatewayServer();
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as AddressInfo).port;

    // 1. Test Option A Pro Pass flow over live MCP stdio
    const transportA = new StdioClientTransport({
      command: process.execPath,
      args: [DIST_ENTRY],
      env: {
        ...process.env,
        RENTSHIELD_API_URL: `http://127.0.0.1:${port}`,
        X402_AGENT_ID: "stdio-e2e-option-a",
        X402_MOCK_SIGNER: "1",
        X402_OPTION: "option_a_pro_pass"
      }
    });

    const mcpClientA = new Client(
      { name: "mcp-stdio-tester", version: "1.0.0" },
      { capabilities: {} }
    );

    try {
      await mcpClientA.connect(transportA);

      // Verify tools/list
      const listed = await mcpClientA.listTools();
      const toolNames = listed.tools.map((t) => t.name);
      assert.deepEqual(toolNames, [
        "audit_solana_token_10_layer",
        "simulate_solana_tx_drain",
        "scan_wallet_unclaimed_sol"
      ]);

      // Call 1 (warm up keep-alive socket)
      const firstCall = await mcpClientA.callTool({
        name: "audit_solana_token_10_layer",
        arguments: { mint: "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN" }
      });
      const firstJson = JSON.parse((firstCall.content as Array<{ text: string }>)[0].text);
      assert.equal(firstJson.ok, true);
      assert.equal(firstJson.safe_to_buy, true);

      // Call 2: Measure warm round-trip latency (<120ms requirement)
      const t0 = performance.now();
      const warmCall = await mcpClientA.callTool({
        name: "audit_solana_token_10_layer",
        arguments: { mint: "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN" }
      });
      const warmRoundTripMs = performance.now() - t0;
      const warmJson = JSON.parse((warmCall.content as Array<{ text: string }>)[0].text);
      assert.equal(warmJson.ok, true);
      assert.ok(
        warmRoundTripMs < 120,
        `Expected warm MCP stdio + HTTP keep-alive audit <120ms, got ${warmRoundTripMs.toFixed(2)}ms`
      );

      // Call 3: simulate_solana_tx_drain
      const kp = Keypair.generate();
      const tx = new Transaction({
        recentBlockhash: Keypair.generate().publicKey.toBase58(),
        feePayer: kp.publicKey
      }).add(
        SystemProgram.transfer({
          fromPubkey: kp.publicKey,
          toPubkey: kp.publicKey,
          lamports: 1000
        })
      );
      const b64Tx = tx
        .serialize({ requireAllSignatures: false, verifySignatures: false })
        .toString("base64");

      const simCall = await mcpClientA.callTool({
        name: "simulate_solana_tx_drain",
        arguments: { transaction: b64Tx, wallet: kp.publicKey.toBase58(), encoding: "base64" }
      });
      const simJson = JSON.parse((simCall.content as Array<{ text: string }>)[0].text);
      assert.equal(simJson.ok, true);
      assert.equal(simJson.drain_detected, false);

      // Call 4: scan_wallet_unclaimed_sol
      const scanCall = await mcpClientA.callTool({
        name: "scan_wallet_unclaimed_sol",
        arguments: { wallet: kp.publicKey.toBase58(), include_token_2022: true }
      });
      const scanJson = JSON.parse((scanCall.content as Array<{ text: string }>)[0].text);
      assert.equal(scanJson.ok, true);
      assert.equal(scanJson.reclaimable_count, 3);

      // Calls 5..10 finish the 10 free pings
      for (let i = 5; i <= 10; i++) {
        const res = await mcpClientA.callTool({
          name: "audit_solana_token_10_layer",
          arguments: { mint: "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN" }
        });
        const parsed = JSON.parse((res.content as Array<{ text: string }>)[0].text);
        assert.equal(parsed.ok, true);
        assert.equal(parsed.x402_auto_paid, undefined);
      }

      // Call 11 triggers HTTP 402 -> auto-upgrades via Option A (0.026 SOL) -> caches X-Pro-Pass-Token
      const call11 = await mcpClientA.callTool({
        name: "audit_solana_token_10_layer",
        arguments: { mint: "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN" }
      });
      const json11 = JSON.parse((call11.content as Array<{ text: string }>)[0].text);
      assert.equal(json11.ok, true);
      assert.equal(json11.x402_auto_paid.option, "option_a_pro_pass");
      assert.equal(json11.x402_auto_paid.lamports, 26_000_000);
      assert.equal(json11.x402_auto_paid.proPassTokenCached, true);
      assert.ok(String(json11.x402_auto_paid.signature).startsWith("5MockA"));

      // Call 12 uses cached X-Pro-Pass-Token with zero new signatures
      const sigCountAfter11 = seenSigs.size;
      const call12 = await mcpClientA.callTool({
        name: "audit_solana_token_10_layer",
        arguments: { mint: "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN" }
      });
      const json12 = JSON.parse((call12.content as Array<{ text: string }>)[0].text);
      assert.equal(json12.ok, true);
      assert.equal(json12.x402_auto_paid, undefined);
      assert.equal(seenSigs.size, sigCountAfter11);
    } finally {
      await mcpClientA.close();
    }

    // 2. Test Option B Single Scan flow over live MCP stdio
    const transportB = new StdioClientTransport({
      command: process.execPath,
      args: [DIST_ENTRY],
      env: {
        ...process.env,
        RENTSHIELD_API_URL: `http://127.0.0.1:${port}`,
        X402_AGENT_ID: "stdio-e2e-option-b",
        X402_MOCK_SIGNER: "1",
        X402_OPTION: "option_b_single_scan"
      }
    });
    const mcpClientB = new Client(
      { name: "mcp-stdio-tester-b", version: "1.0.0" },
      { capabilities: {} }
    );

    try {
      await mcpClientB.connect(transportB);
      for (let i = 1; i <= 10; i++) {
        await mcpClientB.callTool({
          name: "audit_solana_token_10_layer",
          arguments: { mint: "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN" }
        });
      }
      // Call 11 & Call 12 each pay a unique 0.0003 SOL (300000 lamports) 5MockB... signature
      const b11 = await mcpClientB.callTool({
        name: "audit_solana_token_10_layer",
        arguments: { mint: "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN" }
      });
      const b12 = await mcpClientB.callTool({
        name: "audit_solana_token_10_layer",
        arguments: { mint: "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN" }
      });
      const jb11 = JSON.parse((b11.content as Array<{ text: string }>)[0].text);
      const jb12 = JSON.parse((b12.content as Array<{ text: string }>)[0].text);

      assert.equal(jb11.ok, true);
      assert.equal(jb12.ok, true);
      assert.equal(jb11.x402_auto_paid.option, "option_b_single_scan");
      assert.equal(jb11.x402_auto_paid.lamports, 300_000);
      assert.ok(String(jb11.x402_auto_paid.signature).startsWith("5MockB"));
      assert.notEqual(jb11.x402_auto_paid.signature, jb12.x402_auto_paid.signature);
    } finally {
      await mcpClientB.close();
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});
