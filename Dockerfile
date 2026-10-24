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
ENV PATH=/root/.local/bin:

# Application code and pre-trained model artifacts
COPY . .

EXPOSE 8000

ENV PORT=8000
ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
