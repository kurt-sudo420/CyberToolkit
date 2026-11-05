"use strict";
const byId = id => document.getElementById(id);
let revision = 0;

function report(state, detail, digest = "") {
  byId("state").textContent = state;
  byId("detail").textContent = detail;
  byId("digest").textContent = digest;
}

function resetReport() {
  revision++;
  report("Awaiting input", "Hash a file or run the sample to see its digest.");
}

async function fingerprint(sample) {
  const current = ++revision;
  const file = byId("file").files[0];
  const expected = byId("expected").value.trim().toLowerCase();
  if (!sample && !file) return report("File needed", "Choose a file first.");
  if (!sample && file.size > 32 * 1024 * 1024)
    return report("File too large", "Use the Python CLI for files over 32 MiB.");
  if (expected && !/^[a-f0-9]{64}$/.test(expected))
    return report("Invalid reference", "Enter exactly 64 hexadecimal characters or clear the reference.");
  if (!globalThis.crypto?.subtle)
    return report("Secure context required", "Open this lab over HTTPS or localhost.");
  report("Hashing…", sample ? "Sample bytes: abc" : file.name);
  try {
    const bytes = sample ? new TextEncoder().encode("abc") : await file.arrayBuffer();
    const buffer = await crypto.subtle.digest("SHA-256", bytes);
    if (revision !== current) return;
    const digest = Array.from(new Uint8Array(buffer), byte => byte.toString(16).padStart(2, "0")).join("");
    const status = !expected ? "Fingerprint ready" : digest === expected ? "Digests match" : "Digests differ";
    report(status, sample ? "Sample • abc (3 bytes)" : file.name, digest);
  } catch {
    if (current === revision) report("Unable to hash", "Select the file again and retry.");
  }
}

byId("file").addEventListener("change", resetReport);
byId("expected").addEventListener("input", resetReport);
byId("hash").addEventListener("click", () => fingerprint(false));
byId("sample").addEventListener("click", () => fingerprint(true));
