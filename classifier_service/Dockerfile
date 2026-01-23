FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONPATH=/app
# Ensure uvicorn is in your requirements.txt

EXPOSE 8003
CMD ["uvicorn", "models.uri_inference:app", "--host", "0.0.0.0", "--port", "8003"]

