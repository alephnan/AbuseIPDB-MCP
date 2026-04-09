# Multi-stage build for MCP AbuseIPDB server
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements
COPY pyproject.toml /tmp/
COPY README.md /tmp/
COPY src/ /tmp/src/
WORKDIR /tmp

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e .

# Production stage
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r mcp && useradd -r -g mcp -s /bin/false mcp

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY src/ /app/src/
COPY pyproject.toml /app/
COPY README.md /app/

# Set working directory
WORKDIR /app

# Install the application
RUN pip install --no-cache-dir -e .

# Create directories for cache and logs
RUN mkdir -p /app/cache /app/logs \
    && chown -R mcp:mcp /app

# Switch to non-root user
USER mcp

# Set environment variables
ENV PYTHONPATH=/app/src
ENV CACHE_DB_PATH=/app/cache/cache.db
ENV LOG_LEVEL=INFO

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Expose stdio interface (MCP default)
CMD ["python", "-m", "mcp_abuseipdb.server"]
