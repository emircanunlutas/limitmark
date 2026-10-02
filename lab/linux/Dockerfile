# Linux parity image: the repository built exactly as CI-style tooling would on Linux.
# Context: repository root (see Dockerfile.dockerignore). LOCAL USE ONLY: no secrets are copied in,
# and the image is never pushed. Container parity does NOT prove VM, kernel or network parity.
FROM node:22-bookworm

ENV CI=true \
    NEXT_TELEMETRY_DISABLED=1
WORKDIR /app

COPY package.json package-lock.json .npmrc ./
RUN npm ci --no-audit --no-fund

COPY . .
RUN npm run build

LABEL limitmark.lab="disposable"
