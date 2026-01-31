FROM python:3.10-slim

WORKDIR /app

# ─────────────────────────────────────────────
# System dependencies (existing + Playwright)
# ─────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    build-essential \
    libgomp1 \
    \
    # Playwright system deps
    wget \
    gnupg \
    ca-certificates \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpangocairo-1.0-0 \
    libgtk-3-0 \
    libxshmfence1 \
    libxdamage1 \
    fonts-liberation \
    \
    && rm -rf /var/lib/apt/lists/*

# ─────────────────────────────────────────────
# Python deps
# ─────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ─────────────────────────────────────────────
# 🔥 Playwright browsers (Chromium only)
# ─────────────────────────────────────────────
RUN playwright install chromium --with-deps

# ─────────────────────────────────────────────
# App code
# ─────────────────────────────────────────────
COPY . .

ENV PYTHONPATH=/app

EXPOSE 8003
CMD ["uvicorn", "models.uri_inference:app", "--host", "0.0.0.0", "--port", "8003"]
