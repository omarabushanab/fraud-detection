FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# We use 8001 here because the detector is on 8000
CMD ["uvicorn", "gmail:app", "--host", "0.0.0.0", "--port", "8002"]