FROM node:20-slim

# Install git (needed for cloning repos) and curl (for health checks)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install Claude Code CLI globally
RUN npm install -g @anthropic-ai/claude-code

# Create working directories
RUN mkdir -p /workdir /data/failed-submissions

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi

# Copy application code
COPY . .

# Default environment
ENV NODE_ENV=production
ENV PORT=3000
ENV WORK_DIR=/workdir
ENV FAILED_SUBMISSIONS_DIR=/data/failed-submissions

EXPOSE 3000

# Start both the API server and the worker
CMD ["node", "src/server.js"]
