# Use a slim Python image for a smaller footprint
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy only the requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies (FastAPI and HTTPX are crucial here)
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your UI code (main.py)
COPY . .

# Expose the port the UI will run on internally
EXPOSE 8000

# Command to start the UI service
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]