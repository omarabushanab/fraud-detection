import os
import shutil
import zipfile
from typing import Optional

import gdown
import requests

# DEFAULT_GDRIVE_ZIP_ID = "1g1aEJ4wqqBBH3wy0Cp0Z1lSPEXAGAxVk"
DEFAULT_GDRIVE_ZIP_ID = "18AqDg8lmPMbl3XHVIxyKjQ--7r6Dxcri"
ZIP_NAME = "model_weights.zip"
MODEL_DIR = "model/xlm-r-phishing-final-4"


def _download_to_file(url: str, dest: str):
    # Stream download to avoid holding the whole zip in memory
    with requests.get(url, stream=True) as r:  # type: ignore[call-arg]
        r.raise_for_status()
        with open(dest, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)


def prepare_model(zip_url: Optional[str] = None, zip_id: Optional[str] = None):
    if os.path.exists(os.path.join(MODEL_DIR, "config.json")):
        print("Model files already present; skipping download.")
        return

    zip_source_url = zip_url or os.getenv("MODEL_ZIP_URL")
    zip_source_id = zip_id or os.getenv("MODEL_ZIP_ID") or DEFAULT_GDRIVE_ZIP_ID

    # Ensure clean download target
    if os.path.exists(ZIP_NAME):
        os.remove(ZIP_NAME)

    os.makedirs(MODEL_DIR, exist_ok=True)

    if zip_source_url:
        print(f"Downloading model zip from {zip_source_url} ...")
        _download_to_file(zip_source_url, ZIP_NAME)
    else:
        print(f"Downloading model zip from Google Drive id={zip_source_id} ...")
        gdown.download(id=zip_source_id, output=ZIP_NAME, quiet=False)

    print("Extracting model...")
    with zipfile.ZipFile(ZIP_NAME, "r") as zip_ref:
        zip_ref.extractall("temp_extract")

    # The actual files are at: temp_extract/content/drive/MyDrive/xlm-r-phishing-final-4/
    source_path = os.path.join("temp_extract", "content", "drive", "MyDrive", "xlm-r-phishing-final-4")
    
    if os.path.exists(source_path):
        os.makedirs(MODEL_DIR, exist_ok=True)
        for item in os.listdir(source_path):
            s = os.path.join(source_path, item)
            d = os.path.join(MODEL_DIR, item)
            shutil.move(s, d)
        print(f"Successfully moved files to {MODEL_DIR}")
    else:
        print(f"Error: Could not find model files at {source_path}")

    # Cleanup
    shutil.rmtree("temp_extract")
    os.remove(ZIP_NAME)

if __name__ == "__main__":
    prepare_model()