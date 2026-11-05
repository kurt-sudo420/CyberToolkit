# CyberToolkit

A hands-on defensive security toolkit with two entry points. The browser lab fingerprints a local file and compares it with a trusted SHA-256 digest. The Python CLI adds network inspection, streaming hashes for large files, and cryptographically random passwords.

![The browser lab showing the SHA-256 fingerprint of the sample bytes abc](preview.png)

## Try the file integrity lab

From the repository root, run:

```sh
python -m http.server 8000 --bind 127.0.0.1 --directory docs
```

Open [the local lab](http://127.0.0.1:8000/) and select **Try sample**. The three ASCII bytes `abc` produce the following SHA-256 digest:

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

Paste that value into **Expected SHA-256** and rerun the sample to see a match. Change one digit to see a mismatch. To check an actual download, select the file, enter the digest from its publisher and choose **Hash file**. The page processes files up to 32 MiB in memory. It loads its assets locally and its content security policy blocks outbound script connections.

## Run the CLI

```sh
python cybertoolkit.py
```

| Menu | Tool | Behavior |
| --- | --- | --- |
| 1 | Port scanner | Checks TCP connections to one IPv4 target with bounded concurrency. Port labels suggest common services. |
| 2 | File hash | Reads a file in chunks and prints its SHA-256 digest. |
| 3 | Password generator | Uses Python’s `secrets` module. Defaults to 20 characters and supports 8–256. |
| 4 | DNS lookup | Lists the addresses returned by the system resolver. |
| 5 | Banner grabber | Reads up to 1,024 bytes with a timeout and escapes terminal control characters. |

## Run the web dashboard

The dashboard puts SHA-256 hashing, DNS lookup and password generation behind a local web interface styled to match [my portfolio](https://kurt-sudo420.github.io/portfolio/). It needs FastAPI and Uvicorn:

```sh
python -m pip install -r requirements.txt
uvicorn webapp:app --host 127.0.0.1 --port 8000
```

Then open [http://127.0.0.1:8000](http://127.0.0.1:8000). Text is hashed by the API; files are hashed in the browser with Web Crypto and never uploaded. Paste a publisher's digest into **Expected SHA-256** to compare, and any differing characters are highlighted. The port scanner and banner grabber are intentionally CLI-only so the server can't be used to probe other hosts.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/health` | Liveness check |
| `POST /api/hash` | SHA-256 of `{"text": "..."}` (up to 1,000,000 characters) |
| `GET /api/dns?domain=` | IPv4 and IPv6 addresses for a validated hostname |
| `GET /api/password?length=` | Password of 8–256 characters, default 20 |

Responses carry a strict content security policy, `X-Frame-Options: DENY` and `Cache-Control: no-store` on API routes. Fonts are self-hosted under the SIL Open Font License, so the page makes no third-party requests.

Use network probes only on systems you own or have explicit permission to test. For a reproducible exercise, leave the local lab server running and scan `127.0.0.1` on port `8000` from a second terminal. An open port shows that a connection succeeded. It does not establish a vulnerability.

## Verification

Run `python -m unittest discover -v` from the repository root. The tests use local inputs, a simulated remote banner and a mocked resolver. The CLI and its tests require Python 3.8+ and use the standard library; the web tests are skipped unless the packages in `requirements.txt` are installed. The web lab requires a modern browser with Web Crypto on HTTPS or localhost.
