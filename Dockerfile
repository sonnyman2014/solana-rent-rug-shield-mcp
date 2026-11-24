# Multi-stage Node >=20 container build for Smithery & Glama MCP inspection
FROM node:20-alpine AS builder

WORKDIR /build/packages/mcp-server

COPY packages/mcp-server/package*.json packages/mcp-server/tsconfig.json ./
RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund

COPY packages/mcp-server/ ./
RUN npm run build && npm prune --omit=dev

FROM node:20-alpine AS runtime

LABEL org.opencontainers.image.title="Solana Rent & Rug Shield MCP Server"
LABEL org.opencontainers.image.description="Solana <120ms 12-layer token rug audit, Layer 9 Inner CPI tx drain simulator, and read-only ATA rent scanner with x402 auto-pay."
LABEL org.opencontainers.image.url="https://rentandrugshield.com"
LABEL org.opencontainers.image.source="https://github.com/sonnyman2014/solana-rent-rug-shield-mcp"
LABEL org.opencontainers.image.licenses="MIT"
LABEL io.modelcontextprotocol.server.name="io.github.sonnyman2014/solana-rent-rug-shield-mcp"

WORKDIR /app

COPY --from=builder /build/packages/mcp-server /app/packages/mcp-server

RUN chmod +x /app/packages/mcp-server/dist/index.js && \
    mkdir -p /app/node_modules/@rentandrugshield /app/node_modules/.bin && \
    ln -s /app/packages/mcp-server /app/node_modules/@rentandrugshield/mcp-server && \
    ln -s /app/packages/mcp-server/dist/index.js /app/node_modules/.bin/rentandrugshield-mcp && \
    ln -s /app/packages/mcp-server/dist/index.js /app/node_modules/.bin/mcp-server && \
    ln -s /app/packages/mcp-server/dist/index.js /usr/local/bin/rentandrugshield-mcp && \
    ln -s /app/packages/mcp-server/dist/index.js /usr/local/bin/mcp-server && \
    chown -R node:node /app

ENV NODE_ENV=production
ENV RENTSHIELD_API_URL=https://rentandrugshield.com

USER node

ENTRYPOINT ["node", "/app/packages/mcp-server/dist/index.js"]
