# Stage 1: Model Downloader 
FROM python:3.10-slim AS loader
WORKDIR /loader

COPY download_model.py ./
RUN pip install --no-cache-dir gdown requests && python download_model.py

# ... (Stage 1 remains same)

# Stage 2: runtime image
FROM python:3.10-slim
WORKDIR /app

# Install system dependencies (needed for PyTorch/Transformers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    curl \ 
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
# Ensure sacremoses is in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy model weights
COPY --from=loader /loader/model /app/model

# Copy application code
COPY ./app /app/app

# Point the MODEL_DIR environment variable to the nested folder
ENV PORT=8001 \
    MODEL_DIR=/app/model/xlm-r-phishing-final-4 \
    PYTHONPATH=/app \
    HF_HUB_DISABLE_SYMLINKS_WARNING=1

EXPOSE 8001

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]