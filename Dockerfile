# ---- Build stage ----
FROM node:20-slim AS builder
WORKDIR /app

# Prisma needs OpenSSL
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# Install dependencies (postinstall runs `prisma generate`)
COPY package.json package-lock.json ./
COPY prisma ./prisma
RUN npm ci

# Build the Next.js app
COPY . .
RUN npm run build

# ---- Run stage ----
FROM node:20-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000

RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app ./

EXPOSE 3000
CMD ["npm", "run", "start"]
