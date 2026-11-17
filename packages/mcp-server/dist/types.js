export const DEFAULT_API_URL = "https://rentandrugshield.com";
export const X402_TREASURY = "89Sv5FvnMNRid1bn8y2Ti1vJPSxWxgiW9GSLsPpBnKK1";
export const X402_FREE_PINGS_LIMIT = 10;
export const X402_TIERS = {
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
//# sourceMappingURL=types.js.map