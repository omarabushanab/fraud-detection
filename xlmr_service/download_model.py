# import gdown
# import os

# MODEL_DIR = "model"
# # 🔴 Use the FOLDER ID from the URL (the part after /folders/)
# GDRIVE_FOLDER_ID = "1x507Fs2GpRNcZXoBsd7NiSFQv_6mQ200"

# def download_model_folder():
#     if not os.path.exists(MODEL_DIR):
#         os.makedirs(MODEL_DIR)
    
#     # Check if the directory is already populated (e.g., config.json exists)
#     if os.path.exists(os.path.join(MODEL_DIR, "config.json")):
#         print("Model files already exist, skipping download.")
#         return

#     print("Downloading XLM-R model folder from Google Drive...")
#     # This downloads all files inside the folder directly into MODEL_DIR
#     gdown.download_folder(id=GDRIVE_FOLDER_ID, output=MODEL_DIR, quiet=False)
#     print("Model files ready.")

# if __name__ == "__main__":
#     download_model_folder()


## this code down is for the zipped file 

import os
import shutil
import zipfile
from typing import Optional

import gdown
import requests

DEFAULT_GDRIVE_ZIP_ID = "1g1aEJ4wqqBBH3wy0Cp0Z1lSPEXAGAxVk"
ZIP_NAME = "model_weights.zip"
MODEL_DIR = "model"


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
        zip_ref.extractall(MODEL_DIR)

    # Cleanup archive and macOS metadata
    os.remove(ZIP_NAME)
    macosx_dir = os.path.join(MODEL_DIR, "__MACOSX")
    if os.path.exists(macosx_dir):
        shutil.rmtree(macosx_dir)

    print(f"Model ready in {os.path.abspath(MODEL_DIR)}")


if __name__ == "__main__":
    prepare_model()