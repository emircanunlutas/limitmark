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
# The host's .git/config is deliberately NOT in the build context (it can carry a remote URL with a token). Repository tests still
# ask git whether files differ from HEAD, and files copied from a Windows checkout have no meaningful executable bits, so the one
# non-secret setting that config contributed is restated here.
RUN git config --system core.filemode false && git config --system --add safe.directory /app
RUN npm run build

LABEL limitmark.lab="disposable"
