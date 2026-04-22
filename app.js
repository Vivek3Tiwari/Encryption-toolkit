const techs = [
  { id: "caesar", label: "Caesar" },
  { id: "vigenere", label: "Vigenere" },
  { id: "aes", label: "AES-GCM" },
  { id: "des", label: "DES/3DES" },
  { id: "sha256", label: "SHA-256" },
  { id: "hill", label: "Hill" },
  { id: "playfair", label: "Playfair" },
  { id: "columnar", label: "Columnar" },
  { id: "railfence", label: "Rail Fence" },
  { id: "rsa", label: "RSA" },
  { id: "file", label: "File Cipher" },
];

const HISTORY_KEY = "crypto-toolkit-history";
const THEME_KEY = "crypto-toolkit-theme";
const WORKSPACE_KEY = "crypto-toolkit-workspace";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const navEl = document.getElementById("techNav");
const panels = [...document.querySelectorAll(".panel")];
const historyListEl = document.getElementById("historyList");
const toastContainer = document.getElementById("toastContainer");
const securityBadge = document.getElementById("securityBadge");
let history = [];

const fieldsToPersist = [
  "caesarInput", "caesarShift", "caesarOutput", "vigenereInput", "vigenereKey", "vigenereOutput",
  "aesInput", "aesPassphrase", "aesOutput", "desInput", "desKey", "desMode", "desOutput",
  "hashInput", "hashOutput", "hillInput", "hillKey", "hillOutput", "playfairInput", "playfairKey",
  "playfairOutput", "columnarInput", "columnarKey", "columnarOutput", "railInput", "railKey",
  "railOutput", "rsaPublicKey", "rsaPrivateKey", "rsaMessage", "rsaCipher", "rsaSignature",
  "rsaOutput", "fileStatus"
];

function showToast(message) {
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = message;
  toastContainer.appendChild(el);
  setTimeout(() => el.remove(), 2500);
}

function activateTech(techId) {
  panels.forEach((panel) => panel.classList.toggle("active", panel.dataset.tech === techId));
  [...navEl.children].forEach((tab) => tab.classList.toggle("active", tab.dataset.tech === techId));
}

function appendHistory(action, detail) {
  history.unshift({ action, detail, time: new Date().toLocaleString() });
  history = history.slice(0, 40);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  renderHistory();
  updateSecurityScore();
}

function renderHistory() {
  historyListEl.innerHTML = "";
  if (!history.length) {
    const li = document.createElement("li");
    li.textContent = "No operations yet.";
    historyListEl.appendChild(li);
    return;
  }
  history.forEach((entry) => {
    const li = document.createElement("li");
    li.textContent = `[${entry.time}] ${entry.action} - ${entry.detail}`;
    historyListEl.appendChild(li);
  });
}

function loadHistory() {
  try {
    history = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
  } catch (_) {
    history = [];
  }
  renderHistory();
}

function updateSecurityScore() {
  let score = 0;
  const used = new Set(history.map((h) => h.action.toLowerCase()));
  if ([...used].some((a) => a.includes("aes"))) score += 40;
  if ([...used].some((a) => a.includes("rsa"))) score += 35;
  if ([...used].some((a) => a.includes("sha-256"))) score += 15;
  if ([...used].some((a) => a.includes("des"))) score -= 10;
  const label = score >= 60 ? "Strong" : score >= 25 ? "Moderate" : "Basic";
  securityBadge.textContent = `Security: ${label}`;
}

function rotateChar(ch, shift) {
  const code = ch.charCodeAt(0);
  if (code >= 65 && code <= 90) return String.fromCharCode(((code - 65 + shift + 26) % 26) + 65);
  if (code >= 97 && code <= 122) return String.fromCharCode(((code - 97 + shift + 26) % 26) + 97);
  return ch;
}

const caesarTransform = (text, shift) => text.split("").map((c) => rotateChar(c, shift)).join("");

function normalizeKey(key) {
  return key.toLowerCase().split("").filter((c) => c >= "a" && c <= "z").map((c) => c.charCodeAt(0) - 97);
}

function vigenereTransform(text, key, decrypt = false) {
  const shifts = normalizeKey(key);
  if (!shifts.length) return "";
  let idx = 0;
  return text.split("").map((ch) => {
    const code = ch.charCodeAt(0);
    if (!((code >= 65 && code <= 90) || (code >= 97 && code <= 122))) return ch;
    const shift = shifts[idx % shifts.length] * (decrypt ? -1 : 1);
    idx += 1;
    return rotateChar(ch, shift);
  }).join("");
}

function bytesToBase64(bytes) {
  let b = "";
  bytes.forEach((x) => { b += String.fromCharCode(x); });
  return btoa(b);
}

function base64ToBytes(base64) {
  const b = atob(base64);
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i += 1) out[i] = b.charCodeAt(i);
  return out;
}

async function deriveAesKey(passphrase, saltBytes, iterations = 100000) {
  const mat = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    mat,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function mod(n, m) {
  return ((n % m) + m) % m;
}
const sanitizeLetters = (t) => t.toUpperCase().replace(/[^A-Z]/g, "");

function parseHillKey(text) {
  const parts = text.split(",").map((n) => Number(n.trim()));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return null;
  return parts.map((n) => mod(n, 26));
}

function modInv26(v) {
  for (let i = 1; i < 26; i += 1) if (mod(v * i, 26) === 1) return i;
  return null;
}

function hillEncryptText(text, key) {
  let src = sanitizeLetters(text);
  if (src.length % 2) src += "X";
  const [a, b, c, d] = key;
  let out = "";
  for (let i = 0; i < src.length; i += 2) {
    const x = src.charCodeAt(i) - 65;
    const y = src.charCodeAt(i + 1) - 65;
    out += String.fromCharCode(mod(a * x + b * y, 26) + 65);
    out += String.fromCharCode(mod(c * x + d * y, 26) + 65);
  }
  return out;
}

function hillDecryptText(text, key) {
  const src = sanitizeLetters(text);
  if (src.length % 2) return "Input must have even letter count.";
  const [a, b, c, d] = key;
  const invDet = modInv26(mod(a * d - b * c, 26));
  if (invDet === null) return "Invalid matrix determinant.";
  const inv = [mod(d * invDet, 26), mod(-b * invDet, 26), mod(-c * invDet, 26), mod(a * invDet, 26)];
  return hillEncryptText(src, inv);
}

function buildPlayfairSquare(keyword) {
  const used = new Set();
  const chars = [];
  const seed = `${keyword.toUpperCase().replace(/J/g, "I")}ABCDEFGHIKLMNOPQRSTUVWXYZ`;
  for (const ch of seed) {
    if (ch < "A" || ch > "Z" || ch === "J" || used.has(ch)) continue;
    used.add(ch);
    chars.push(ch);
  }
  const pos = {};
  chars.forEach((ch, i) => { pos[ch] = { r: Math.floor(i / 5), c: i % 5 }; });
  return { chars, pos };
}

function playfairPairs(text, decrypt) {
  const src = sanitizeLetters(text).replace(/J/g, "I");
  const pairs = [];
  if (decrypt) {
    for (let i = 0; i < src.length; i += 2) pairs.push([src[i], src[i + 1] || "X"]);
    return pairs;
  }
  let i = 0;
  while (i < src.length) {
    const a = src[i];
    let b = src[i + 1];
    if (!b) { b = "X"; i += 1; } else if (a === b) { b = "X"; i += 1; } else i += 2;
    pairs.push([a, b]);
  }
  return pairs;
}

function playfairTransform(text, keyword, decrypt = false) {
  const { chars, pos } = buildPlayfairSquare(keyword);
  const d = decrypt ? -1 : 1;
  return playfairPairs(text, decrypt).map(([a, b]) => {
    const pa = pos[a];
    const pb = pos[b];
    if (pa.r === pb.r) return chars[pa.r * 5 + mod(pa.c + d, 5)] + chars[pb.r * 5 + mod(pb.c + d, 5)];
    if (pa.c === pb.c) return chars[mod(pa.r + d, 5) * 5 + pa.c] + chars[mod(pb.r + d, 5) * 5 + pb.c];
    return chars[pa.r * 5 + pb.c] + chars[pb.r * 5 + pa.c];
  }).join("");
}

function columnOrder(key) {
  return key.toUpperCase().split("").map((ch, i) => ({ ch, i })).sort((a, b) => (a.ch === b.ch ? a.i - b.i : a.ch.localeCompare(b.ch)));
}

function columnarEncrypt(text, key) {
  if (!key.trim()) return "Keyword required.";
  const cols = key.length;
  const rows = Math.ceil(text.length / cols);
  const data = text.padEnd(rows * cols, "X");
  let out = "";
  columnOrder(key).forEach(({ i }) => { for (let r = 0; r < rows; r += 1) out += data[r * cols + i]; });
  return out;
}

function columnarDecrypt(text, key) {
  if (!key.trim()) return "Keyword required.";
  const cols = key.length;
  const rows = Math.ceil(text.length / cols);
  const total = rows * cols;
  const src = text.padEnd(total, "X");
  const grid = Array(total).fill("X");
  let p = 0;
  columnOrder(key).forEach(({ i }) => {
    for (let r = 0; r < rows; r += 1) {
      grid[r * cols + i] = src[p];
      p += 1;
    }
  });
  return grid.join("");
}

function railFenceEncrypt(text, rails) {
  if (rails < 2) return text;
  const rows = Array.from({ length: rails }, () => []);
  let row = 0;
  let dir = 1;
  for (const ch of text) {
    rows[row].push(ch);
    if (row === 0) dir = 1;
    if (row === rails - 1) dir = -1;
    row += dir;
  }
  return rows.map((r) => r.join("")).join("");
}

function railFenceDecrypt(text, rails) {
  if (rails < 2) return text;
  const pattern = [];
  let row = 0;
  let dir = 1;
  for (let i = 0; i < text.length; i += 1) {
    pattern.push(row);
    if (row === 0) dir = 1;
    if (row === rails - 1) dir = -1;
    row += dir;
  }
  const counts = Array(rails).fill(0);
  pattern.forEach((r) => { counts[r] += 1; });
  const bucket = Array.from({ length: rails }, () => []);
  let ptr = 0;
  for (let r = 0; r < rails; r += 1) {
    bucket[r] = text.slice(ptr, ptr + counts[r]).split("");
    ptr += counts[r];
  }
  return pattern.map((r) => bucket[r].shift()).join("");
}

function railFencePattern(text, rails) {
  if (rails < 2) return text;
  const grid = Array.from({ length: rails }, () => Array(text.length).fill(" "));
  let row = 0;
  let dir = 1;
  for (let i = 0; i < text.length; i += 1) {
    grid[row][i] = text[i];
    if (row === 0) dir = 1;
    if (row === rails - 1) dir = -1;
    row += dir;
  }
  return grid.map((r) => r.join("")).join("\n");
}

function downloadBlob(blob, filename) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
}

async function exportKeyToBase64(key, format) {
  const buffer = await crypto.subtle.exportKey(format, key);
  return bytesToBase64(new Uint8Array(buffer));
}

async function importPublicKey(base64Key, algorithm) {
  return crypto.subtle.importKey("spki", base64ToBytes(base64Key), algorithm, true, algorithm.name === "RSA-OAEP" ? ["encrypt"] : ["verify"]);
}

async function importPrivateKey(base64Key, algorithm) {
  return crypto.subtle.importKey("pkcs8", base64ToBytes(base64Key), algorithm, true, algorithm.name === "RSA-OAEP" ? ["decrypt"] : ["sign"]);
}

function setValue(id, value) {
  const el = document.getElementById(id);
  if (el) el.value = value;
}

function wireTechTabs() {
  techs.forEach((tech, i) => {
    const tab = document.createElement("button");
    tab.className = "tech-tab";
    tab.dataset.tech = tech.id;
    tab.textContent = tech.label;
    if (i === 0) tab.classList.add("active");
    tab.addEventListener("click", () => activateTech(tech.id));
    navEl.appendChild(tab);
  });
}

function wireThemeToggle() {
  const btn = document.getElementById("themeToggle");
  const theme = localStorage.getItem(THEME_KEY) || "dark";
  document.body.dataset.theme = theme;
  btn.textContent = theme === "dark" ? "Light Theme" : "Dark Theme";
  btn.addEventListener("click", () => {
    const next = document.body.dataset.theme === "dark" ? "light" : "dark";
    document.body.dataset.theme = next;
    localStorage.setItem(THEME_KEY, next);
    btn.textContent = next === "dark" ? "Light Theme" : "Dark Theme";
    appendHistory("Theme changed", next);
    showToast(`Switched to ${next} theme`);
  });
}

function wireSearchFilter() {
  document.getElementById("cipherSearch").addEventListener("input", (e) => {
    const q = e.target.value.toLowerCase().trim();
    let firstMatch = null;
    panels.forEach((panel) => {
      const text = panel.textContent.toLowerCase();
      const match = !q || text.includes(q) || panel.dataset.tech.includes(q);
      panel.style.opacity = match ? "1" : "0.38";
      if (match && !firstMatch) firstMatch = panel.dataset.tech;
    });
    if (firstMatch) activateTech(firstMatch);
  });
}

function wireCopyButtons() {
  document.querySelectorAll("[data-copy-target]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const target = document.getElementById(btn.dataset.copyTarget);
      if (!target?.value?.trim()) return;
      await navigator.clipboard.writeText(target.value);
      appendHistory("Copied output", btn.dataset.copyTarget);
      showToast("Copied to clipboard");
    });
  });
}

function validateRequired(ids) {
  return ids.every((id) => (document.getElementById(id)?.value || "").trim());
}

function wireClassic() {
  document.getElementById("caesarEncrypt").addEventListener("click", () => {
    setValue("caesarOutput", caesarTransform(document.getElementById("caesarInput").value, Number(document.getElementById("caesarShift").value) || 0));
    appendHistory("Caesar encrypt", "Completed");
  });
  document.getElementById("caesarDecrypt").addEventListener("click", () => {
    setValue("caesarOutput", caesarTransform(document.getElementById("caesarInput").value, -(Number(document.getElementById("caesarShift").value) || 0)));
    appendHistory("Caesar decrypt", "Completed");
  });
  document.getElementById("vigenereEncrypt").addEventListener("click", () => {
    const key = document.getElementById("vigenereKey").value.trim();
    setValue("vigenereOutput", key ? vigenereTransform(document.getElementById("vigenereInput").value, key, false) : "Keyword required");
    appendHistory("Vigenere encrypt", key || "invalid key");
  });
  document.getElementById("vigenereDecrypt").addEventListener("click", () => {
    const key = document.getElementById("vigenereKey").value.trim();
    setValue("vigenereOutput", key ? vigenereTransform(document.getElementById("vigenereInput").value, key, true) : "Keyword required");
    appendHistory("Vigenere decrypt", key || "invalid key");
  });
}

function wireAesHashDes() {
  document.getElementById("aesEncrypt").addEventListener("click", async () => {
    if (!validateRequired(["aesPassphrase"])) return showToast("Passphrase required");
    try {
      const input = document.getElementById("aesInput").value;
      const passphrase = document.getElementById("aesPassphrase").value;
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveAesKey(passphrase, salt);
      const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(input));
      setValue("aesOutput", btoa(JSON.stringify({ salt: bytesToBase64(salt), iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(ct)) })));
      appendHistory("AES encrypt", "PBKDF2 + AES-GCM");
    } catch (e) {
      setValue("aesOutput", `Error: ${e.message}`);
    }
  });
  document.getElementById("aesDecrypt").addEventListener("click", async () => {
    if (!validateRequired(["aesPassphrase", "aesInput"])) return showToast("Input + passphrase required");
    try {
      const payload = JSON.parse(atob(document.getElementById("aesInput").value.trim()));
      const key = await deriveAesKey(document.getElementById("aesPassphrase").value, base64ToBytes(payload.salt));
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64ToBytes(payload.iv) }, key, base64ToBytes(payload.data));
      setValue("aesOutput", decoder.decode(pt));
      appendHistory("AES decrypt", "Completed");
    } catch (_) {
      setValue("aesOutput", "Error: invalid encrypted bundle or passphrase.");
    }
  });

  document.getElementById("hashGenerate").addEventListener("click", async () => {
    const input = document.getElementById("hashInput").value;
    const h = await crypto.subtle.digest("SHA-256", encoder.encode(input));
    setValue("hashOutput", [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join(""));
    appendHistory("SHA-256", `Hashed ${input.length} chars`);
  });

  document.getElementById("desEncrypt").addEventListener("click", () => {
    if (!validateRequired(["desKey"])) return showToast("DES key required");
    const key = document.getElementById("desKey").value;
    const input = document.getElementById("desInput").value;
    const alg = document.getElementById("desMode").value;
    const out = alg === "TripleDES" ? CryptoJS.TripleDES.encrypt(input, key).toString() : CryptoJS.DES.encrypt(input, key).toString();
    setValue("desOutput", out);
    appendHistory(`${alg} encrypt`, "Completed");
  });
  document.getElementById("desDecrypt").addEventListener("click", () => {
    if (!validateRequired(["desKey", "desInput"])) return showToast("Cipher + key required");
    try {
      const key = document.getElementById("desKey").value;
      const input = document.getElementById("desInput").value;
      const alg = document.getElementById("desMode").value;
      const out = alg === "TripleDES"
        ? CryptoJS.TripleDES.decrypt(input, key).toString(CryptoJS.enc.Utf8)
        : CryptoJS.DES.decrypt(input, key).toString(CryptoJS.enc.Utf8);
      setValue("desOutput", out || "Decryption failed.");
      appendHistory(`${alg} decrypt`, "Completed");
    } catch (_) {
      setValue("desOutput", "Decryption failed.");
    }
  });
}

function wireAdditionalCiphers() {
  document.getElementById("hillEncrypt").addEventListener("click", () => {
    const key = parseHillKey(document.getElementById("hillKey").value);
    if (!key) return setValue("hillOutput", "Invalid key: use a,b,c,d");
    setValue("hillOutput", hillEncryptText(document.getElementById("hillInput").value, key));
    appendHistory("Hill encrypt", "2x2");
  });
  document.getElementById("hillDecrypt").addEventListener("click", () => {
    const key = parseHillKey(document.getElementById("hillKey").value);
    if (!key) return setValue("hillOutput", "Invalid key: use a,b,c,d");
    setValue("hillOutput", hillDecryptText(document.getElementById("hillInput").value, key));
    appendHistory("Hill decrypt", "2x2");
  });
  document.getElementById("playfairEncrypt").addEventListener("click", () => {
    const key = document.getElementById("playfairKey").value.trim();
    setValue("playfairOutput", key ? playfairTransform(document.getElementById("playfairInput").value, key, false) : "Keyword required");
    appendHistory("Playfair encrypt", key || "invalid key");
  });
  document.getElementById("playfairDecrypt").addEventListener("click", () => {
    const key = document.getElementById("playfairKey").value.trim();
    setValue("playfairOutput", key ? playfairTransform(document.getElementById("playfairInput").value, key, true) : "Keyword required");
    appendHistory("Playfair decrypt", key || "invalid key");
  });
  document.getElementById("columnarEncrypt").addEventListener("click", () => {
    setValue("columnarOutput", columnarEncrypt(document.getElementById("columnarInput").value, document.getElementById("columnarKey").value));
    appendHistory("Columnar encrypt", "Completed");
  });
  document.getElementById("columnarDecrypt").addEventListener("click", () => {
    setValue("columnarOutput", columnarDecrypt(document.getElementById("columnarInput").value, document.getElementById("columnarKey").value));
    appendHistory("Columnar decrypt", "Completed");
  });
  document.getElementById("railEncrypt").addEventListener("click", () => {
    const text = document.getElementById("railInput").value;
    const rails = Number(document.getElementById("railKey").value) || 2;
    setValue("railOutput", railFenceEncrypt(text, rails));
    document.getElementById("railPattern").textContent = railFencePattern(text, rails);
    appendHistory("Rail Fence encrypt", `rails=${rails}`);
  });
  document.getElementById("railDecrypt").addEventListener("click", () => {
    const text = document.getElementById("railInput").value;
    const rails = Number(document.getElementById("railKey").value) || 2;
    setValue("railOutput", railFenceDecrypt(text, rails));
    document.getElementById("railPattern").textContent = railFencePattern(text, rails);
    appendHistory("Rail Fence decrypt", `rails=${rails}`);
  });
}

function wireRsa() {
  document.getElementById("rsaGenerate").addEventListener("click", async () => {
    const pair = await crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["encrypt", "decrypt"]);
    setValue("rsaPublicKey", await exportKeyToBase64(pair.publicKey, "spki"));
    setValue("rsaPrivateKey", await exportKeyToBase64(pair.privateKey, "pkcs8"));
    setValue("rsaOutput", "Generated key pair");
    appendHistory("RSA", "Generated keys");
  });
  document.getElementById("rsaEncrypt").addEventListener("click", async () => {
    try {
      const key = await importPublicKey(document.getElementById("rsaPublicKey").value.trim(), { name: "RSA-OAEP", hash: "SHA-256" });
      const ct = await crypto.subtle.encrypt("RSA-OAEP", key, encoder.encode(document.getElementById("rsaMessage").value));
      setValue("rsaCipher", bytesToBase64(new Uint8Array(ct)));
      setValue("rsaOutput", "Encrypted");
      appendHistory("RSA encrypt", "Completed");
    } catch (_) {
      setValue("rsaOutput", "Invalid public key.");
    }
  });
  document.getElementById("rsaDecrypt").addEventListener("click", async () => {
    try {
      const key = await importPrivateKey(document.getElementById("rsaPrivateKey").value.trim(), { name: "RSA-OAEP", hash: "SHA-256" });
      const pt = await crypto.subtle.decrypt("RSA-OAEP", key, base64ToBytes(document.getElementById("rsaCipher").value.trim()));
      setValue("rsaOutput", decoder.decode(pt));
      appendHistory("RSA decrypt", "Completed");
    } catch (_) {
      setValue("rsaOutput", "Invalid private key/cipher.");
    }
  });
  document.getElementById("rsaSign").addEventListener("click", async () => {
    try {
      const key = await importPrivateKey(document.getElementById("rsaPrivateKey").value.trim(), { name: "RSA-PSS", hash: "SHA-256" });
      const sign = await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, key, encoder.encode(document.getElementById("rsaMessage").value));
      setValue("rsaSignature", bytesToBase64(new Uint8Array(sign)));
      setValue("rsaOutput", "Signature created");
      appendHistory("RSA sign", "Completed");
    } catch (_) {
      setValue("rsaOutput", "Sign failed.");
    }
  });
  document.getElementById("rsaVerify").addEventListener("click", async () => {
    try {
      const key = await importPublicKey(document.getElementById("rsaPublicKey").value.trim(), { name: "RSA-PSS", hash: "SHA-256" });
      const ok = await crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, key, base64ToBytes(document.getElementById("rsaSignature").value.trim()), encoder.encode(document.getElementById("rsaMessage").value));
      setValue("rsaOutput", ok ? "Signature valid" : "Signature invalid");
      appendHistory("RSA verify", ok ? "valid" : "invalid");
    } catch (_) {
      setValue("rsaOutput", "Verify failed.");
    }
  });
}

function wireFileCrypto() {
  document.getElementById("fileEncrypt").addEventListener("click", async () => {
    try {
      const file = document.getElementById("fileInput").files[0];
      const passphrase = document.getElementById("filePassphrase").value;
      if (!file || !passphrase.trim()) throw new Error("file + passphrase required");
      const raw = new Uint8Array(await file.arrayBuffer());
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveAesKey(passphrase, salt);
      const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, raw);
      const payload = { name: file.name, type: file.type || "application/octet-stream", salt: bytesToBase64(salt), iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(ct)) };
      downloadBlob(new Blob([JSON.stringify(payload)], { type: "application/json" }), `${file.name}.enc.json`);
      setValue("fileStatus", "Encrypted file downloaded.");
      appendHistory("File encrypt", file.name);
    } catch (e) {
      setValue("fileStatus", `Error: ${e.message}`);
    }
  });
  document.getElementById("fileDecrypt").addEventListener("click", async () => {
    try {
      const file = document.getElementById("fileInput").files[0];
      const passphrase = document.getElementById("filePassphrase").value;
      if (!file || !passphrase.trim()) throw new Error("file + passphrase required");
      const payload = JSON.parse(await file.text());
      const key = await deriveAesKey(passphrase, base64ToBytes(payload.salt));
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64ToBytes(payload.iv) }, key, base64ToBytes(payload.data));
      downloadBlob(new Blob([pt], { type: payload.type || "application/octet-stream" }), payload.name || "decrypted-file");
      setValue("fileStatus", "Decrypted file downloaded.");
      appendHistory("File decrypt", payload.name || file.name);
    } catch (_) {
      setValue("fileStatus", "Error: Decryption failed.");
    }
  });
}

function captureWorkspace() {
  const data = {};
  fieldsToPersist.forEach((id) => {
    const el = document.getElementById(id);
    if (el) data[id] = el.value;
  });
  data.theme = document.body.dataset.theme;
  data.history = history;
  return data;
}

function applyWorkspace(data) {
  fieldsToPersist.forEach((id) => {
    if (Object.prototype.hasOwnProperty.call(data, id)) setValue(id, data[id]);
  });
  if (data.theme) {
    document.body.dataset.theme = data.theme;
    localStorage.setItem(THEME_KEY, data.theme);
  }
  if (Array.isArray(data.history)) {
    history = data.history.slice(0, 40);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    renderHistory();
  }
}

function wireWorkspaceTools() {
  document.getElementById("exportWorkspace").addEventListener("click", () => {
    const snapshot = captureWorkspace();
    localStorage.setItem(WORKSPACE_KEY, JSON.stringify(snapshot));
    downloadBlob(new Blob([JSON.stringify(snapshot, null, 2)], { type: "application/json" }), "crypto-workspace.json");
    showToast("Workspace exported");
  });
  document.getElementById("importWorkspace").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      const data = JSON.parse(await file.text());
      applyWorkspace(data);
      showToast("Workspace imported");
      appendHistory("Workspace", "Imported");
      updateSecurityScore();
    } catch (_) {
      showToast("Invalid workspace file");
    }
  });
}

function wireSelfTests() {
  const out = document.getElementById("selfTestOutput");
  document.getElementById("runSelfTest").addEventListener("click", async () => {
    const logs = [];
    const ok = (name, pass) => logs.push(`${pass ? "PASS" : "FAIL"}: ${name}`);
    ok("Caesar", caesarTransform("ABC", 3) === "DEF");
    ok("Vigenere", vigenereTransform("ATTACKATDAWN", "LEMON") === "LXFOPVEFRNHR");
    ok("Rail Fence", railFenceEncrypt("WEAREDISCOVEREDFLEEATONCE", 3) === "WECRLTEERDSOEEFEAOCAIVDEN");
    ok("Columnar roundtrip", columnarDecrypt(columnarEncrypt("HELLOWORLD", "ZEBRA"), "ZEBRA").startsWith("HELLOWORLD"));
    try {
      const h = await crypto.subtle.digest("SHA-256", encoder.encode("abc"));
      ok("SHA-256", [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("") === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    } catch (_) {
      ok("SHA-256", false);
    }
    out.value = logs.join("\n");
    appendHistory("Self test", "Executed");
    showToast("Self test complete");
  });
}

function wireHistory() {
  document.getElementById("clearHistory").addEventListener("click", () => {
    history = [];
    localStorage.removeItem(HISTORY_KEY);
    renderHistory();
    updateSecurityScore();
  });
}

function autosaveWorkspace() {
  localStorage.setItem(WORKSPACE_KEY, JSON.stringify(captureWorkspace()));
}

function wireAutosave() {
  document.querySelectorAll("input, textarea, select").forEach((el) => {
    el.addEventListener("input", autosaveWorkspace);
    el.addEventListener("change", autosaveWorkspace);
  });
}

function loadWorkspace() {
  try {
    const data = JSON.parse(localStorage.getItem(WORKSPACE_KEY) || "null");
    if (data) applyWorkspace(data);
  } catch (_) {}
}

function init() {
  wireTechTabs();
  wireThemeToggle();
  wireSearchFilter();
  wireCopyButtons();
  wireClassic();
  wireAesHashDes();
  wireAdditionalCiphers();
  wireRsa();
  wireFileCrypto();
  wireWorkspaceTools();
  wireSelfTests();
  wireHistory();
  wireAutosave();
  loadHistory();
  loadWorkspace();
  updateSecurityScore();
}

init();
