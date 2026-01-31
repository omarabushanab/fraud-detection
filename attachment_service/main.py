# attachment_service/main.py
import io
import magic
from fastapi import FastAPI, UploadFile, File, HTTPException, status
from oletools.olevba import VBA_Parser
import clamd
import os
import time
import zipfile

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB

async def analyze_bytes(filename, contents):
    """The logic moved here so it can be called recursively"""
    is_malicious = False
    findings = []
    
    # 1. Detect MIME
    try:
        mime = magic.from_buffer(contents, mime=True)
    except:
        mime = "application/octet-stream"
    
    # 2. ClamAV Scan
    try:
        cd = get_clamd()
        scan_result = cd.instream(io.BytesIO(contents))
        if scan_result and scan_result.get('stream', [None])[0] == 'FOUND':
            is_malicious = True
            findings.append(f"ClamAV: {scan_result['stream'][1]}")
    except Exception as e:
        print(f"ClamAV failed: {e}")

    # 3. VBA Macro Scan
    office_mimes = ["officedocument", "msword", "excel", "ms-office", "powerpoint"]
    if any(m in mime for m in office_mimes):
        try:
            vba_parser = VBA_Parser(filename=filename, data=contents)
            if vba_parser.detect_macros():
                for (kw_type, keyword, description) in vba_parser.analyze_macros():
                    if kw_type in ['Suspicious', 'AutoExec']:
                        is_malicious = True
                        findings.append(f"{kw_type}: {keyword} ({description})")
            vba_parser.close()
        except:
            pass

    return is_malicious, findings, mime

def get_clamd():
    """
    Get ClamAV daemon connection with retry logic
    """
    max_retries = 5
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            cd = clamd.ClamdNetworkSocket(
                host=os.getenv("CLAMAV_HOST", "clamav"), 
                port=int(os.getenv("CLAMD_PORT", "3310"))
            )
            cd.ping()
            return cd
        except Exception as e:
            if attempt < max_retries - 1:
                print(f"ClamAV connection attempt {attempt + 1} failed: {e}. Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
            else:
                raise Exception(f"Failed to connect to ClamAV after {max_retries} attempts: {e}")

async def analyze_recursive(filename, contents, depth = 0):
    if depth > 5:
        return False, [f"Max recursion depth reached for {filename}"], "application/octet-stream"
    findings = []
    is_malicious = False

    try:
        mime = magic.from_buffer(contents, mime=True)
    except:
        mime = "application/octet-stream"
    if mime == "application/zip" or filename.endswith(".zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(contents)) as z:
                for zinfo in z.infolist():
                    if zinfo.is_dir():
                        continue
                    with z.open(zinfo) as f:
                        child_contents = f.read()
                        child_malicious, child_findings, _ = await analyze_recursive(zinfo.filename, child_contents, depth + 1)

                        if child_malicious:
                            is_malicious = True
                            findings.extend([f"[{zinfo.filename}] {found}" for found in child_findings])
            return is_malicious, list(set(findings)), mime # Use set to avoid duplicates
        except Exception as e:
            return False, [f"Zip Error: {str(e)}"], mime
    try:
        cd = get_clamd()
        scan_result = cd.instream(io.BytesIO(contents))
        if scan_result and scan_result.get('stream', [None])[0] == 'FOUND':
            is_malicious = True
            findings.append(f"ClamAV: {scan_result['stream'][1]}")
    except Exception as e:
        print(f"ClamAV failed: {e}")

    office_mimes = ["officedocument", "msword", "excel", "ms-office", "powerpoint"]
    if any(m in mime for m in office_mimes):
        try:
            vba_parser = VBA_Parser(filename=filename, data=contents)
            if vba_parser.detect_macros():
                for (kw_type, keyword, description) in vba_parser.analyze_macros():
                    if kw_type in ['Suspicious', 'AutoExec']:
                        is_malicious = True
                        findings.append(f"{kw_type}: {keyword} ({description})")
            vba_parser.close()
        except:
            pass
    return is_malicious, findings, mime

app = FastAPI()

@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    """
    Scan uploaded file for malware and malicious macros
    """
    # Check file size
    if file.size and file.size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size exceeds maximum limit of {MAX_FILE_SIZE / (1024 * 1024)} MB"
        )
    
    # Read file contents
    contents = await file.read()
    is_malicious, findings, mime = await analyze_recursive(file.filename, contents)
    return {
        "filename": file.filename,
        "mime_type": mime,
        "is_malicious": is_malicious,
        "findings": findings
    }

    # Verify we actually have content
async def perform_analysis(filename, contents):
    if not contents:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty file uploaded"
        )
    
    is_malicious = False
    findings = []
    
    # 1. Identify true file type (ignoring extension)
    try:
        mime = magic.from_buffer(contents, mime=True)
    except Exception as e:
        print(f"Magic type detection failed: {e}")
        mime = "application/octet-stream"
    
    # 2. Check for Malicious Office Macros (olevba)
    if "officedocument" in mime or "msword" in mime or "excel" in mime or "ms-office" in mime:
        try:
            vba_parser = VBA_Parser(filename=filename, data=contents)
            if vba_parser.detect_macros():
                results = vba_parser.analyze_macros()
                for (kw_type, keyword, description) in results:
                    if kw_type == 'Suspicious' or kw_type == 'AutoExec':
                        is_malicious = True
                        findings.append(f"{kw_type}: {keyword} ({description})")
            vba_parser.close()
        except Exception as e:
            print(f"VBA macro analysis failed: {e}")
    
    # 3. ClamAV Virus Scan
    try:
        cd = get_clamd()
        scan_result = cd.instream(io.BytesIO(contents))
        
        # Check scan result
        if scan_result and 'stream' in scan_result:
            status_code, virus_name = scan_result['stream']
            if status_code == 'FOUND':
                is_malicious = True
                findings.append(f"ClamAV: {virus_name}")
    except Exception as e:
        print(f"ClamAV scan failed: {e}")
        # Don't fail the whole request if ClamAV is temporarily unavailable
        # Just log it and continue
    
    return {
        "filename": filename,
        "mime_type": mime,
        "is_malicious": is_malicious,
        "findings": findings
    }

@app.get("/health")
def health():
    """
    Health check endpoint - verifies ClamAV connectivity
    """
    try:
        cd = get_clamd()
        cd.ping()
        return {"status": "ok", "clamav": "connected"}
    except Exception as e:
        # Return 503 if ClamAV is not available
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"ClamAV unavailable: {str(e)}"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)