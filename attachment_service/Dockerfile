FROM python:3.10-slim

# Install system dependencies for python-magic and curl for health checks
RUN apt-get update && apt-get install -y \
    libmagic1 \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose the service port
EXPOSE 8004

# Start the FastAPI application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8004"]