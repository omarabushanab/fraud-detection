# Stage 1: Downloader
FROM python:3.10-slim AS loader
WORKDIR /loader
RUN pip install gdown
COPY download_model.py .
# This runs and leaves the /loader/model folder ready
RUN python download_model.py 

# Stage 2: Final Runtime
FROM python:3.10-slim
WORKDIR /app

# Install only what's needed for the API
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the model from the loader stage
COPY --from=loader /loader/model ./model
COPY ./app ./app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]