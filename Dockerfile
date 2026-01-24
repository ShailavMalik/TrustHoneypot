# Production-ready image for FastAPI + Uvicorn on Railway
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

# Install system deps (if future libs need build tools, add here)
RUN apt-get update \ 
    && apt-get install -y --no-install-recommends build-essential \ 
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Default command; Railway will expose PORT env
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
