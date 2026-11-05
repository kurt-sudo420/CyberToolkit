"""CyberToolkit web dashboard.

A small FastAPI app that puts three of the CLI's utilities behind a local
web interface: SHA-256 hashing, DNS lookup, and password generation. File
hashing happens entirely in the browser with Web Crypto; the server only
ever sees text you choose to hash.

The port scanner and banner grabber are deliberately left out. Exposing
outbound network probes through an HTTP endpoint turns the server into a
proxy for scanning other hosts, which is not something a dashboard needs.

Run locally:
    uvicorn webapp:app --host 127.0.0.1 --port 8000
"""

import hashlib
import ipaddress
import re
import secrets
import socket
import string
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent

MAX_TEXT_CHARS = 1_000_000
PASSWORD_MIN, PASSWORD_MAX, PASSWORD_DEFAULT = 8, 256, 20
# Same symbol set as the CLI, which avoids quotes and backslashes that are
# awkward to paste into shells and config files.
SYMBOLS = "!@#$%^&*()-_=+"

# RFC 1123 hostname: dot-separated labels of 1-63 letters, digits or hyphens,
# not starting or ending with a hyphen, and a final label that is not numeric.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
HOSTNAME_RE = re.compile(rf"^(?:{_LABEL}\.)+(?!\d+$){_LABEL}\.?$")

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "font-src 'self'; img-src 'self' data:; connect-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

app = FastAPI(
    title="CyberToolkit",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if request.url.path.startswith("/api/"):
        # Generated passwords and lookups should never sit in a cache.
        response.headers["Cache-Control"] = "no-store"
    return response


class HashRequest(BaseModel):
    text: str = Field(..., max_length=MAX_TEXT_CHARS)


@app.get("/api/health")
def health_check():
    return {"status": "ok"}


@app.post("/api/hash")
def hash_text(request: HashRequest):
    data = request.text.encode("utf-8")
    return {
        "algorithm": "SHA-256",
        "bytes": len(data),
        "hash": hashlib.sha256(data).hexdigest(),
    }


def is_valid_hostname(name: str) -> bool:
    return len(name.rstrip(".")) <= 253 and bool(HOSTNAME_RE.match(name))


@app.get("/api/dns")
def dns_lookup(domain: str = Query(..., min_length=1, max_length=254)):
    domain = domain.strip().lower()
    if not is_valid_hostname(domain):
        raise HTTPException(status_code=422, detail="Enter a valid domain name, such as example.com.")

    try:
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        raise HTTPException(status_code=404, detail="No DNS records found for that domain.")

    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise HTTPException(status_code=404, detail="No DNS records found for that domain.")

    ipv4 = [a for a in addresses if ipaddress.ip_address(a).version == 4]
    ipv6 = [a for a in addresses if ipaddress.ip_address(a).version == 6]
    return {"status": "success", "domain": domain, "ip_addresses": addresses, "ipv4": ipv4, "ipv6": ipv6}


@app.get("/api/password")
def generate_password(length: int = Query(PASSWORD_DEFAULT, ge=PASSWORD_MIN, le=PASSWORD_MAX)):
    # Guarantee one character from each class, fill the rest from the full
    # alphabet, then shuffle so the guaranteed characters aren't predictable.
    classes = (string.ascii_lowercase, string.ascii_uppercase, string.digits, SYMBOLS)
    alphabet = "".join(classes)
    chars = [secrets.choice(c) for c in classes]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return {"password": "".join(chars), "length": length}


app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(BASE_DIR / "templates" / "index.html")
