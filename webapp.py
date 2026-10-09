from pathlib import Path
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from fastapi import FastAPI, HTTPException, Query, Request
import socket
import re
import hashlib
import string
import secrets
from pydantic import BaseModel

class HashRequest(BaseModel):
    text: str

app = FastAPI()

@app.get('/api/health')
def health_check():
    return {'status': 'ok'}

@app.post('/api/hash')
def hash_text(request: HashRequest):
    try:
        text = request.text
        if not text:
            raise HTTPException(status_code=400, detail='Missing text field')
        return {'hash': hashlib.sha256(text.encode()).hexdigest()}
    except ValueError:
        raise HTTPException(status_code=400, detail='Invalid JSON body')

@app.get('/api/dns')
def dns_lookup(domain: str = Query(..., pattern=r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')):
    try:
        # Validate domain name
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            raise HTTPException(status_code=400, detail='Invalid domain name')
        
        # Perform DNS lookup using socket
        addresses = socket.getaddrinfo(domain, None)
        ip_addresses = sorted({info[4][0] for info in addresses})
        
        if not ip_addresses:
            raise HTTPException(status_code=404, detail='No IP addresses found for this domain')
        
        return {'status': 'success', 'domain': domain, 'ip_addresses': ip_addresses}
    except socket.gaierror as e:
        raise HTTPException(status_code=500, detail=f'DNS lookup failed: {e}')

@app.get('/api/password')
def generate_password(length: int = Query(..., ge=8)):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return {'password': password}


# CyberToolkit web dashboard
BASE_DIR = Path(__file__).resolve().parent

app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "static"),
    name="static",
)

@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(BASE_DIR / "templates" / "index.html")
