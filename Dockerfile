FROM node:20-slim

# Install system dependencies (git, curl, SSL certs)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git curl ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    update-ca-certificates

# Install Claude Code CLI globally
RUN npm install -g @anthropic-ai/claude-code

# Create non-root user for running the application
RUN useradd -m -s /bin/bash auditor

# Create working directories and assign ownership
RUN mkdir -p /workdir /data/failed-submissions && \
    chown -R auditor:auditor /workdir /data/failed-submissions

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi

# Copy application code
COPY . .

# Ensure app files are readable by auditor
RUN chown -R auditor:auditor /app

# Switch to non-root user
USER auditor

# Default environment
ENV NODE_ENV=production
ENV PORT=3000
ENV WORK_DIR=/workdir
ENV FAILED_SUBMISSIONS_DIR=/data/failed-submissions

EXPOSE 3000

CMD ["node", "src/server.js"]
