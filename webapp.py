from fastapi import FastAPI, HTTPException, Query, Request
import httpx
import secrets
import hashlib
import string
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
def dns_lookup(domain: str = Query(..., regex=r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')):
    try:
        response = httpx.get(f'https://{domain}')
        return {'status': 'success', 'domain': domain, 'status_code': response.status_code}
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f'DNS lookup failed: {e}')

@app.get('/api/password')
def generate_password(length: int = Query(..., ge=8)):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return {'password': password}
