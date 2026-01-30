# attachment_service/main.py
import io
import magic
from fastapi import FastAPI, UploadFile, File, HTTPException, status
from oletools.olevba import VBA_Parser
import clamd
import os

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
cd = clamd.ClamdNetworkSocket(host=os.getenv("CLAMAV_HOST", "clamav"), port=int(os.getenv("CLAMD_PORT", "3310")))
app = FastAPI()

@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    if file.size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size exceeds maximum limit of {MAX_FILE_SIZE / (1024 * 1024)} MB"
        )
    contents = await file.read()
    
    # 1. Identify true file type (ignoring extension)
    mime = magic.from_buffer(contents, mime=True)
    
    # 2. Check for Malicious Office Macros (olevba)
    is_malicious = False
    findings = []
    
    if "officedocument" in mime or "msword" in mime or "excel" in mime:
        vba_parser = VBA_Parser(filename=file.filename, data=contents)
        if vba_parser.detect_macros():
            results = vba_parser.analyze_macros()
            for (type, keyword, description) in results:
                if type == 'Suspicious' or type == 'AutoExec':
                    is_malicious = True
                    findings.append(f"{type}: {keyword} ({description})")
    
    # 3. Future: Add ClamAV or VirusTotal here
    try:
        scan_result = cd.instream(io.BytesIO(contents))
        if scan_result and scan_result['stream'][0] == 'FOUND':
            is_malicious = True
            findings.append(f"ClamAV: {scan_result['stream'][1]}")
    except Exception as e:  
        print(f"ClamAV scan failed: {e}")
    return {
        "filename": file.filename,
        "mime_type": mime,
        "is_malicious": is_malicious,
        "findings": findings
    }

@app.get("/health")
def health(): return {"status": "ok"}