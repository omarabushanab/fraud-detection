import gdown
import os

MODEL_DIR = "model"
# 🔴 Use the FOLDER ID from the URL (the part after /folders/)
GDRIVE_FOLDER_ID = "1x507Fs2GpRNcZXoBsd7NiSFQv_6mQ200"

def download_model_folder():
    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR)
    
    # Check if the directory is already populated (e.g., config.json exists)
    if os.path.exists(os.path.join(MODEL_DIR, "config.json")):
        print("Model files already exist, skipping download.")
        return

    print("Downloading XLM-R model folder from Google Drive...")
    # This downloads all files inside the folder directly into MODEL_DIR
    gdown.download_folder(id=GDRIVE_FOLDER_ID, output=MODEL_DIR, quiet=False)
    print("Model files ready.")

if __name__ == "__main__":
    download_model_folder()


## this code down is for the zipped file 

# import gdown
# import zipfile
# import os
# import shutil

# # 🔴 Use the FILE ID of the .zip file in Google Drive
# GDRIVE_ZIP_ID = "YOUR_ZIP_FILE_ID_HERE"
# ZIP_NAME = "model_weights.zip"
# MODEL_DIR = "model"

# def prepare_model():
#     # 1. Download
#     if not os.path.exists(ZIP_NAME):
#         print("Downloading zipped model...")
#         gdown.download(id=GDRIVE_ZIP_ID, output=ZIP_NAME, quiet=False)

#     # 2. Extract
#     print("Extracting model...")
#     with zipfile.ZipFile(ZIP_NAME, 'r') as zip_ref:
#         zip_ref.extractall(MODEL_DIR)
    
#     # 3. Cleanup: Remove the zip and any __MACOSX folders if they exist
#     os.remove(ZIP_NAME)
#     macosx_dir = os.path.join(MODEL_DIR, "__MACOSX")
#     if os.path.exists(macosx_dir):
#         shutil.rmtree(macosx_dir)
        
#     print("Model ready in /app/model")

# if __name__ == "__main__":
#     prepare_model()