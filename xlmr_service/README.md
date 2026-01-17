## XLM-R phishing inference service

### Build the image (model downloaded once at build time)

Provide a URL (S3/Blob/etc) or Google Drive file id to a zip that contains the model files (config.json, tokenizer files, weights).

```
# Using a direct URL to a zip
docker build -t xlmr-inference \
	--build-arg MODEL_ZIP_URL="https://my-bucket/model_weights.zip" \
	.

# Or using a Google Drive file id
docker build -t xlmr-inference \
	--build-arg MODEL_ZIP_ID="<drive-file-id>" \
	.
```

The model is baked into the image at /app/model. No download happens at container start.

### Run

```
docker run --rm -p 8000:8000 xlmr-inference
```

### API

- Health: `GET /health`
- Predict: `POST /predict` with body `{ "text": "..." }`

Example:

```
curl -X POST http://localhost:8000/predict \
	-H "content-type: application/json" \
	-d '{"text": "Please reset your password here"}'
```

### Using from other services

Treat this container as an HTTP microservice. Other services can call the predict endpoint directly or through an internal load balancer. If you want to mount a model volume instead of baking it, start the container with `-v /path/to/model:/app/model:ro` or set `MODEL_DIR` to the mounted path.
