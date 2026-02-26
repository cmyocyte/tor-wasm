FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy server code + hardening modules
COPY server-collector.js ./
COPY cover-site.js ./
COPY health-auth.js ./
COPY logger.js ./
COPY dns-safe.js ./
COPY traffic-monitor.js ./

# Expose main port
EXPOSE 8080

# Health check via management port (not exposed externally)
# Falls back to cover site check if MANAGEMENT_PORT not set
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:${MANAGEMENT_PORT:-9091}/health || \
      wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

# Default env: enable management port and quiet mode
ENV MANAGEMENT_PORT=9091
ENV QUIET_MODE=1

# Start server
CMD ["node", "server-collector.js"]
