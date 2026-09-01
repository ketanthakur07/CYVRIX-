FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files first for better caching
COPY apps/web/package.json apps/web/package-lock.json ./

# Use npm ci for deterministic installs
RUN npm ci

# Copy the rest of the app
COPY apps/web/ .

# Build for production
ARG API_BACKEND_URL=http://localhost:8000
ENV API_BACKEND_URL=${API_BACKEND_URL}
RUN npm run build

# ── Production stage ──────────────────────────────────────────────

FROM node:20-alpine AS production

RUN addgroup -g 1001 -S cyvrix && adduser -S cyvrix -u 1001

WORKDIR /app

# Copy only production artifacts
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/next.config.js ./next.config.js

ENV NODE_ENV=production
ENV PORT=3000

USER cyvrix

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:3000/ || exit 1

CMD ["npm", "start"]
