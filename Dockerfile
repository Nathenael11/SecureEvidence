# SecureEvidence: Multi-Stage Production Container
# Author: Nathenael Ermias nathenaelermias13@gmail.com

FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim

WORKDIR /app

# Install curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Copy installed dependencies into standard /usr/local
COPY --from=builder /install /usr/local

# Security: Create non-root user and pre-create data directory with correct ownership
RUN useradd -u 10001 -m -s /bin/bash appuser && \
    mkdir -p /app/data && \
    chown -R appuser:appuser /app

# Copy application files with appuser ownership
COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 8000

ENV PORT=8000
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/health || exit 1

CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
