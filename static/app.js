"use strict";

document.documentElement.classList.remove("no-js");

const $ = (id) => document.getElementById(id);
const MAX_FILE_BYTES = 256 * 1024 * 1024;
const PASSWORD_ALPHABET = 76; // 26 lower + 26 upper + 10 digits + 14 symbols

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
  ["hash", "dns", "password"].forEach((id) => io.observe($(id)));
}

async function checkHealth() {
  const status = $("apiStatus");
  const text = status.querySelector(".nav-status-text");
  try {
    const response = await fetch("/api/health", { cache: "no-store" });
    if (!response.ok) throw new Error();
    status.className = "nav-status is-online";
    text.textContent = "API online";
  } catch {
    status.className = "nav-status is-offline";
    text.textContent = "API offline";
  }
}
checkHealth();
setInterval(checkHealth, 30000);

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

const hashState = { digest: "", source: "", revision: 0 };
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

async function hashText() {
  const text = $("hashText").value;
  const revision = ++hashState.revision;
  try {
    const response = await fetch("/api/hash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    if (revision !== hashState.revision) return;
    if (!response.ok) throw new Error(await errorMessage(response, "The server could not hash that text."));
    const body = await response.json();
    hashState.digest = body.hash;
    setMeta(`SHA-256 of ${formatBytes(body.bytes)} of UTF-8 text`);
  } catch (err) {
    if (revision !== hashState.revision) return;
    hashState.digest = "";
    setMeta(err instanceof TypeError ? "Cannot reach the API. Is the server running?" : err.message);
  }
  renderDigest();
}

let textTimer;
$("hashText").addEventListener("input", () => {
  clearTimeout(textTimer);
  textTimer = setTimeout(hashText, 180);
});

async function hashFile(file) {
  const revision = ++hashState.revision;
  $("dropTitle").textContent = file.name;
  if (file.size > MAX_FILE_BYTES) {
    hashState.digest = "";
    setMeta(`${formatBytes(file.size)} is over the 256 MB browser limit. Use the CLI for large files.`);
    return renderDigest();
  }
  if (!globalThis.crypto?.subtle) {
    hashState.digest = "";
    setMeta("File hashing needs a secure context. Open the dashboard on localhost or HTTPS.");
    return renderDigest();
  }
  setMeta(`Hashing ${file.name}`);
  try {
    const buffer = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
    if (revision !== hashState.revision) return;
    hashState.digest = Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join("");
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
  domain = domain.trim();
  if (!domain) {
    input.setAttribute("aria-invalid", "true");
    result.replaceChildren(el("p", { class: "error" }, "Enter a domain to look up, such as example.com."));
    return input.focus();
  }
  input.setAttribute("aria-invalid", "false");
  button.disabled = true;
  button.textContent = "Looking up";
  const started = performance.now();
  try {
    const response = await fetch(`/api/dns?domain=${encodeURIComponent(domain)}`);
    if (!response.ok) throw new Error(await errorMessage(response, "The lookup failed. Try again."));
    const body = await response.json();
    const ms = Math.round(performance.now() - started);
    const head = el("div", { class: "rec-head" });
    head.appendChild(el("b", {}, body.domain));
    head.appendChild(el("span", { class: "meta" }, `${body.ip_addresses.length} address${body.ip_addresses.length === 1 ? "" : "es"} in ${ms} ms`));
    const parts = [head];
    if (body.ipv4.length) parts.push(recordGroup("IPv4", body.ipv4));
    if (body.ipv6.length) parts.push(recordGroup("IPv6", body.ipv6));
    result.replaceChildren(...parts);
  } catch (err) {
    const message = err instanceof TypeError ? "Cannot reach the API. Is the server running?" : err.message;
    if (!(err instanceof TypeError)) input.setAttribute("aria-invalid", "true");
    result.replaceChildren(el("p", { class: "error" }, message));
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

let pwRevision = 0;
async function generatePassword() {
  const length = clampLength(number.value);
  const revision = ++pwRevision;
  try {
    const response = await fetch(`/api/password?length=${length}`, { cache: "no-store" });
    if (!response.ok) throw new Error(await errorMessage(response, "Could not generate a password."));
    const body = await response.json();
    if (revision !== pwRevision) return;
    currentPassword = body.password;
    const bits = Math.floor(length * Math.log2(PASSWORD_ALPHABET));
    $("pwMeta").textContent = `${length} characters, about ${bits} bits of entropy. ${strengthLabel(bits)}.`;
    $("strengthBar").style.width = `${Math.min(100, (bits / 160) * 100)}%`;
  } catch (err) {
    if (revision !== pwRevision) return;
    currentPassword = "";
    $("pwMeta").textContent = err instanceof TypeError ? "Cannot reach the API. Is the server running?" : err.message;
    $("strengthBar").style.width = "0%";
  }
  renderPassword();
}

let pwTimer;
range.addEventListener("input", () => {
  number.value = range.value;
  syncRangeFill();
  clearTimeout(pwTimer);
  pwTimer = setTimeout(generatePassword, 120);
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
