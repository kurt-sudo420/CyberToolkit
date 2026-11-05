"use strict";

/*
 * CyberToolkit web dashboard.
 *
 * Runs as a static page (GitHub Pages) or behind webapp.py. Hashing and
 * password generation always happen in the browser, so nothing you type
 * or drop here is sent anywhere. DNS needs a resolver: the local API's
 * system resolver when webapp.py is running, otherwise Cloudflare's
 * DNS-over-HTTPS JSON endpoint.
 */

document.documentElement.classList.remove("no-js");

const $ = (id) => document.getElementById(id);
const MAX_FILE_BYTES = 256 * 1024 * 1024;
const MAX_TEXT_CHARS = 1_000_000;
const DOH_URL = "https://cloudflare-dns.com/dns-query";

// Same character classes as webapp.py and the CLI. The symbols avoid
// quotes and backslashes, which are awkward in shells and config files.
const PW_CLASSES = ["abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789", "!@#$%^&*()-_=+"];
const PW_ALPHABET = PW_CLASSES.join("");

// RFC 1123 hostname, mirroring the server-side check in webapp.py.
const HOSTNAME_RE = /^(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+(?!\d+\.?$)(?!-)[a-z0-9-]{1,63}(?<!-)\.?$/i;

let apiAvailable = false;

/* ---------- Shared helpers ---------- */

let toastTimer;
function toast(message) {
  const el = $("toast");
  el.textContent = message;
  el.classList.add("is-visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("is-visible"), 1800);
}

async function copy(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${label} copied`);
  } catch {
    toast("Copy is unavailable here. Select the text instead.");
  }
}

// FastAPI returns `detail` as a string for HTTPException and as a list
// for request validation errors.
async function errorMessage(response, fallback) {
  try {
    const body = await response.json();
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail) && body.detail[0]?.msg) return body.detail[0].msg;
  } catch { /* not JSON */ }
  return fallback;
}

function formatBytes(n) {
  if (n < 1024) return `${n} byte${n === 1 ? "" : "s"}`;
  const units = ["KB", "MB", "GB"];
  let value = n / 1024, i = 0;
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i++; }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`;
}

function el(tag, attrs = {}, text) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (text !== undefined) node.textContent = text;
  return node;
}

const toHex = (buffer) => Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join("");

/* ---------- Header ---------- */

const header = $("siteHeader");
const onScroll = () => header.classList.toggle("is-scrolled", window.scrollY > 8);
window.addEventListener("scroll", onScroll, { passive: true });
onScroll();

const navLinks = [...document.querySelectorAll(".nav-links a")];
if ("IntersectionObserver" in window) {
  const io = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      navLinks.forEach((a) => a.classList.toggle("active", a.hash === `#${entry.target.id}`));
    }
  }, { rootMargin: "-45% 0px -50% 0px" });
  ["top", "hash", "dns", "password"].forEach((id) => io.observe($(id)));
}

// Relative path, so it resolves to /api/health under webapp.py and to a
// harmless 404 on GitHub Pages.
async function detectApi() {
  // GitHub Pages never has the API, so don't make a request that can only 404.
  const staticHost = location.hostname.endsWith(".github.io");
  try {
    if (staticHost) throw new Error("static host");
    const response = await fetch("api/health", { cache: "no-store" });
    const body = response.ok ? await response.json() : null;
    apiAvailable = body?.status === "ok";
  } catch {
    apiAvailable = false;
  }
  const status = $("apiStatus");
  status.className = "nav-status is-online";
  status.querySelector(".nav-status-text").textContent = apiAvailable ? "Local API" : "Browser mode";
  status.title = apiAvailable
    ? "DNS lookups use your system resolver through webapp.py."
    : "Everything runs in this page. DNS lookups use Cloudflare DNS-over-HTTPS.";
  $("dnsBlurb").textContent = apiAvailable
    ? "List the IPv4 and IPv6 addresses your system resolver returns."
    : "List the IPv4 and IPv6 addresses for a domain, looked up over encrypted DNS through Cloudflare.";
}

/* ---------- Fingerprint ---------- */

const signature = $("signature");
const bars = Array.from({ length: 32 }, (_, n) => {
  const bar = document.createElement("i");
  bar.style.setProperty("--n", n);
  bar.style.setProperty("--h", 0.06);
  signature.appendChild(bar);
  return bar;
});
signature.classList.add("is-idle");

const hashState = { digest: "", revision: 0 };
const expectedInput = $("expected");

function normalizedExpected() {
  return expectedInput.value.replace(/\s+/g, "").toLowerCase();
}

function renderDigest() {
  const out = $("digest");
  const verdict = $("verdict");
  const copyBtn = $("copyDigest");
  const { digest } = hashState;
  out.replaceChildren();

  if (!digest) {
    signature.classList.add("is-idle");
    verdict.className = "state state--muted";
    verdict.textContent = "Waiting";
    copyBtn.disabled = true;
    return;
  }

  const expected = normalizedExpected();
  const expectedValid = /^[0-9a-f]{64}$/.test(expected);
  expectedInput.setAttribute("aria-invalid", String(Boolean(expected) && !expectedValid));

  for (let g = 0; g < 8; g++) {
    const group = el("span", { class: "grp" });
    for (let c = g * 8; c < g * 8 + 8; c++) {
      const ch = digest[c];
      if (expectedValid && expected[c] !== ch) group.appendChild(el("span", { class: "diff" }, ch));
      else group.append(ch);
    }
    out.appendChild(group);
  }

  signature.classList.remove("is-idle");
  for (let i = 0; i < 32; i++) {
    bars[i].style.setProperty("--h", (parseInt(digest.slice(i * 2, i * 2 + 2), 16) / 255).toFixed(3));
  }

  copyBtn.disabled = false;
  if (!expected) {
    verdict.className = "state";
    verdict.textContent = "Digest ready";
  } else if (!expectedValid) {
    verdict.className = "state state--amber";
    verdict.textContent = "Check reference";
  } else if (expected === digest) {
    verdict.className = "state";
    verdict.textContent = "Digests match";
  } else {
    verdict.className = "state state--danger";
    verdict.textContent = "Digests differ";
  }
}

function setMeta(text) { $("digestMeta").textContent = text; }

function secureContextMissing() {
  if (globalThis.crypto?.subtle) return false;
  hashState.digest = "";
  setMeta("Hashing needs a secure context. Open this page over HTTPS or on localhost.");
  renderDigest();
  return true;
}

async function hashText() {
  const revision = ++hashState.revision;
  if (secureContextMissing()) return;
  const text = $("hashText").value;
  if (text.length > MAX_TEXT_CHARS) {
    hashState.digest = "";
    setMeta("That text is over 1,000,000 characters. Save it to a file and use the File tab.");
    return renderDigest();
  }
  const bytes = new TextEncoder().encode(text);
  const buffer = await crypto.subtle.digest("SHA-256", bytes);
  if (revision !== hashState.revision) return;
  hashState.digest = toHex(buffer);
  setMeta(`SHA-256 of ${formatBytes(bytes.length)} of UTF-8 text, hashed in this browser`);
  renderDigest();
}

let textTimer;
$("hashText").addEventListener("input", () => {
  clearTimeout(textTimer);
  textTimer = setTimeout(hashText, 120);
});

async function hashFile(file) {
  const revision = ++hashState.revision;
  $("dropTitle").textContent = file.name;
  if (file.size > MAX_FILE_BYTES) {
    hashState.digest = "";
    setMeta(`${formatBytes(file.size)} is over the 256 MB browser limit. Use the CLI for large files.`);
    return renderDigest();
  }
  if (secureContextMissing()) return;
  setMeta(`Hashing ${file.name}`);
  try {
    const buffer = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
    if (revision !== hashState.revision) return;
    hashState.digest = toHex(buffer);
    setMeta(`${file.name}, ${formatBytes(file.size)}, hashed locally`);
  } catch {
    if (revision !== hashState.revision) return;
    hashState.digest = "";
    setMeta("The browser could not read that file. Choose it again.");
  }
  renderDigest();
}

$("hashFile").addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (file) hashFile(file);
});

const dropZone = $("dropZone");
["dragenter", "dragover"].forEach((type) => dropZone.addEventListener(type, (e) => {
  e.preventDefault();
  dropZone.classList.add("is-over");
}));
["dragleave", "drop"].forEach((type) => dropZone.addEventListener(type, () => dropZone.classList.remove("is-over")));
dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  const file = e.dataTransfer.files[0];
  if (file) hashFile(file);
});

expectedInput.addEventListener("input", renderDigest);
$("copyDigest").addEventListener("click", () => hashState.digest && copy(hashState.digest, "Digest"));

// Tabs: Text | File, with arrow-key support per the ARIA tabs pattern.
const tabs = [$("tabText"), $("tabFile")];
function selectTab(tab) {
  tabs.forEach((t) => {
    const selected = t === tab;
    t.setAttribute("aria-selected", String(selected));
    t.tabIndex = selected ? 0 : -1;
    $(t.getAttribute("aria-controls")).hidden = !selected;
  });
  hashState.revision++;
  hashState.digest = "";
  if (tab.id === "tabText") {
    hashText();
  } else {
    const file = $("hashFile").files[0];
    if (file) hashFile(file);
    else { setMeta("Choose a file to fingerprint."); renderDigest(); }
  }
}
tabs.forEach((tab, i) => {
  tab.addEventListener("click", () => selectTab(tab));
  tab.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const next = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
    next.focus();
    selectTab(next);
  });
});

hashText();

/* ---------- DNS ---------- */

class LookupError extends Error {}

async function resolveWithApi(domain) {
  const response = await fetch(`api/dns?domain=${encodeURIComponent(domain)}`);
  if (!response.ok) throw new LookupError(await errorMessage(response, "The lookup failed. Try again."));
  const body = await response.json();
  return { domain: body.domain, ipv4: body.ipv4, ipv6: body.ipv6 };
}

async function resolveWithDoh(domain) {
  const query = async (type) => {
    const url = `${DOH_URL}?name=${encodeURIComponent(domain)}&type=${type}`;
    const response = await fetch(url, { headers: { accept: "application/dns-json" } });
    if (!response.ok) throw new LookupError("The DNS service did not answer. Try again in a moment.");
    return response.json();
  };
  const [a, aaaa] = await Promise.all([query("A"), query("AAAA")]);
  if (a.Status === 3) throw new LookupError("No DNS records found for that domain.");
  // Answers include CNAMEs on the way to the address; keep only A (1) and AAAA (28).
  const pick = (res, type) => [...new Set((res.Answer || []).filter((r) => r.type === type).map((r) => r.data))].sort();
  return { domain, ipv4: pick(a, 1), ipv6: pick(aaaa, 28) };
}

function recordGroup(title, addresses) {
  const group = el("div", { class: "rec-group" });
  group.appendChild(el("h3", {}, `${title} (${addresses.length})`));
  const list = el("ul", { class: "rec-list" });
  for (const address of addresses) {
    const item = el("li");
    item.appendChild(el("span", {}, address));
    const button = el("button", { type: "button", class: "icon-btn", "aria-label": `Copy ${address}` });
    button.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/></svg>';
    button.addEventListener("click", () => copy(address, "Address"));
    item.appendChild(button);
    list.appendChild(item);
  }
  group.appendChild(list);
  return group;
}

async function lookup(domain) {
  const result = $("dnsResult");
  const button = $("dnsButton");
  const input = $("dnsInput");
  domain = domain.trim().toLowerCase();

  const fail = (message, invalid) => {
    input.setAttribute("aria-invalid", String(invalid));
    result.replaceChildren(el("p", { class: "error" }, message));
  };
  if (!domain) { fail("Enter a domain to look up, such as example.com.", true); return input.focus(); }
  if (domain.length > 253 || !HOSTNAME_RE.test(domain)) return fail("Enter a valid domain name, such as example.com.", true);

  input.setAttribute("aria-invalid", "false");
  button.disabled = true;
  button.textContent = "Looking up";
  const started = performance.now();
  try {
    const records = apiAvailable ? await resolveWithApi(domain) : await resolveWithDoh(domain);
    const total = records.ipv4.length + records.ipv6.length;
    if (!total) throw new LookupError("No DNS records found for that domain.");
    const ms = Math.round(performance.now() - started);
    const head = el("div", { class: "rec-head" });
    head.appendChild(el("b", {}, records.domain));
    head.appendChild(el("span", { class: "meta" }, `${total} address${total === 1 ? "" : "es"} in ${ms} ms`));
    const parts = [head];
    if (records.ipv4.length) parts.push(recordGroup("IPv4", records.ipv4));
    if (records.ipv6.length) parts.push(recordGroup("IPv6", records.ipv6));
    result.replaceChildren(...parts);
  } catch (err) {
    if (err instanceof LookupError) fail(err.message, true);
    else fail("Couldn't reach a DNS service. Check your connection and try again.", false);
  } finally {
    button.disabled = false;
    button.textContent = "Look up";
  }
}

$("dnsForm").addEventListener("submit", (e) => {
  e.preventDefault();
  lookup($("dnsInput").value);
});
$("dnsInput").addEventListener("input", (e) => e.target.setAttribute("aria-invalid", "false"));
document.querySelectorAll("[data-domain]").forEach((b) => b.addEventListener("click", () => {
  $("dnsInput").value = b.dataset.domain;
  lookup(b.dataset.domain);
}));

/* ---------- Password ---------- */

// Unbiased index in [0, n) from the CSPRNG, by rejecting values that
// would make the modulo favour low indexes.
function randomIndex(n) {
  const limit = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
  return buf[0] % n;
}

function makePassword(length) {
  const chars = PW_CLASSES.map((set) => set[randomIndex(set.length)]);
  while (chars.length < length) chars.push(PW_ALPHABET[randomIndex(PW_ALPHABET.length)]);
  for (let i = chars.length - 1; i > 0; i--) { // Fisher-Yates
    const j = randomIndex(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

const range = $("pwLength");
const number = $("pwLengthNum");
const pwOut = $("pwOutput");
const reveal = $("pwReveal");
let currentPassword = "";

function clampLength(value) {
  const n = Number.parseInt(value, 10);
  if (Number.isNaN(n)) return 20;
  return Math.min(256, Math.max(8, n));
}

function syncRangeFill() {
  const pct = ((Number(range.value) - Number(range.min)) / (Number(range.max) - Number(range.min))) * 100;
  range.style.setProperty("--fill", `${pct}%`);
}

function strengthLabel(bits) {
  if (bits >= 128) return "Excellent";
  if (bits >= 96) return "Very strong";
  if (bits >= 72) return "Strong";
  return "Fair";
}

function renderPassword() {
  const masked = reveal.getAttribute("aria-pressed") === "false";
  pwOut.classList.toggle("is-masked", masked);
  pwOut.textContent = masked ? "•".repeat(Math.min(currentPassword.length, 48)) : currentPassword;
}

function generatePassword() {
  const length = clampLength(number.value);
  if (!globalThis.crypto?.getRandomValues) {
    currentPassword = "";
    $("pwMeta").textContent = "This browser has no secure random source, so no password was generated.";
    $("strengthBar").style.width = "0%";
    return renderPassword();
  }
  currentPassword = makePassword(length);
  const bits = Math.floor(length * Math.log2(PW_ALPHABET.length));
  $("pwMeta").textContent = `${length} characters, about ${bits} bits of entropy. ${strengthLabel(bits)}.`;
  $("strengthBar").style.width = `${Math.min(100, (bits / 160) * 100)}%`;
  renderPassword();
}

range.addEventListener("input", () => {
  number.value = range.value;
  syncRangeFill();
  generatePassword();
});
number.addEventListener("change", () => {
  const length = clampLength(number.value);
  number.value = length;
  range.value = Math.min(length, Number(range.max));
  syncRangeFill();
  generatePassword();
});
$("pwGenerate").addEventListener("click", generatePassword);
$("pwCopy").addEventListener("click", () => currentPassword && copy(currentPassword, "Password"));
reveal.addEventListener("click", () => {
  const showing = reveal.getAttribute("aria-pressed") === "true";
  reveal.setAttribute("aria-pressed", String(!showing));
  reveal.setAttribute("aria-label", showing ? "Show password" : "Hide password");
  renderPassword();
});

syncRangeFill();
generatePassword();
detectApi();
