FROM python:3.10-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Gmail credentials and token
COPY credentials.json .
COPY token.pickle .

# Copy application code
COPY . .

# Expose the UI port
EXPOSE 8000

# Start BOTH the API and the Listener (using a process manager or simple script)
# For simplicity in a hackathon, we'll start the API
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]