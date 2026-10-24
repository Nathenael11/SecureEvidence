# SecureEvidence: Multi-Stage Production Container
# Author: Nathenael Ermias nathenaelermias13@gmail.com

FROM python:3.11-slim as builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.11-slim

WORKDIR /app

# Copy installed wheels
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Application code and pre-trained model artifacts
COPY . .

EXPOSE 8000

ENV PORT=8000
ENV PYTHONUNBUFFERED=1
ENV DEMO_MODE=true
ENV JWT_SECRET=render-demo-secret-key-32-chars-long-2026

CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
