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

Use network probes only on systems you own or have explicit permission to test. For a reproducible exercise, leave the local lab server running and scan `127.0.0.1` on port `8000` from a second terminal. An open port shows that a connection succeeded. It does not establish a vulnerability.

## Verification

Run `python -m unittest discover -v` from the repository root. The tests use local inputs and a simulated remote banner. The CLI and tests require Python 3.8+ and use the standard library. The web lab requires a modern browser with Web Crypto on HTTPS or localhost.
