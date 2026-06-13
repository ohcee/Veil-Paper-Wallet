import { getPublicKey, utils as secpUtils } from "@noble/secp256k1";
import { sha256 } from "@noble/hashes/sha2";

function getParamValue(param) {
  const m = new RegExp("[?&]" + param + "=([^&;#]+)").exec(location.search);
  return m ? decodeURIComponent(m[1].replace(/\+/g, "%20")) : null;
}
const isTestNet = (getParamValue("testnet") === "true");

const NET = isTestNet
  ? { name: "testnet", stealthHrp: "tps", wif: 0xEF }
  : { name: "mainnet", stealthHrp: "sv",  wif: 0x80 };

// -------------------------
// Helpers
// -------------------------
function concatBytes(...arrs) {
  const len = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
function utf8Bytes(s) {
  return new TextEncoder().encode(s);
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// -------------------------
// Base58 (for WIF)
// -------------------------
const B58_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58encode(bytes) {
  let x = 0n;
  for (const b of bytes) x = (x << 8n) + BigInt(b);
  let out = "";
  while (x > 0n) {
    const mod = x % 58n;
    out = B58_ALPH[Number(mod)] + out;
    x = x / 58n;
  }
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) out = "1" + out;
  return out || "1";
}

function base58decode(str) {
  let x = 0n;
  for (const ch of str) {
    const v = B58_ALPH.indexOf(ch);
    if (v === -1) throw new Error("Invalid base58 character");
    x = x * 58n + BigInt(v);
  }
  let bytes = [];
  while (x > 0n) {
    bytes.push(Number(x & 0xffn));
    x >>= 8n;
  }
  bytes.reverse();
  for (let i = 0; i < str.length && str[i] === "1"; i++) bytes.unshift(0);
  return new Uint8Array(bytes);
}

// -------------------------
// WIF encode/decode
// -------------------------
function wifFromPrivkey(priv32, wifPrefix) {
  if (priv32.length !== 32) throw new Error("privkey must be 32 bytes");
  const payload = concatBytes(new Uint8Array([wifPrefix]), priv32, new Uint8Array([0x01]));
  const checksum = sha256(sha256(payload)).slice(0, 4);
  return base58encode(concatBytes(payload, checksum));
}

function privFromWif(wif) {
  const raw = base58decode(wif);
  if (raw.length < 4 + 1 + 32) throw new Error("WIF too short");
  const body = raw.slice(0, -4);
  const chk = raw.slice(-4);
  const chk2 = sha256(sha256(body)).slice(0, 4);
  for (let i = 0; i < 4; i++) if (chk[i] !== chk2[i]) throw new Error("Bad WIF checksum");
  const key = body.slice(1, 33);
  return key;
}

// -------------------------
// Bech32 encode (no witness version — raw data only)
// -------------------------
const BECH32_ALPH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function bech32Polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >>> i) & 1) chk ^= GEN[i];
    }
  }
  return chk;
}
function bech32HrpExpand(hrp) {
  const ret = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >>> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}
function bech32CreateChecksum(hrp, data) {
  const values = bech32HrpExpand(hrp).concat(data).concat([0,0,0,0,0,0]);
  const mod = bech32Polymod(values) ^ 1;
  const ret = [];
  for (let p = 0; p < 6; p++) ret.push((mod >>> (5 * (5 - p))) & 31);
  return ret;
}
function bech32Encode(hrp, data) {
  const combined = data.concat(bech32CreateChecksum(hrp, data));
  let s = hrp + "1";
  for (const d of combined) s += BECH32_ALPH[d];
  return s;
}
function convertBits(data, from, to, pad) {
  let acc = 0;
  let bits = 0;
  const ret = [];
  const maxv = (1 << to) - 1;
  for (const value of data) {
    if (value < 0 || (value >> from) !== 0) throw new Error("convertBits: invalid value");
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits) ret.push((acc << (to - bits)) & maxv);
  } else {
    if (bits >= from) throw new Error("convertBits: excess padding");
    if ((acc << (to - bits)) & maxv) throw new Error("convertBits: non-zero padding");
  }
  return ret;
}

// -------------------------
// Stealth address encoding
// Raw format: [options:1][scan_pub:33][N:1][spend_pub:33][nsigs:1][prefix_bits:1] = 70 bytes
// Bech32 with HRP "sv" (mainnet) or "tps" (testnet), NO witness version
// -------------------------
function buildStealthRaw(scanPub, spendPub) {
  const raw = new Uint8Array(70);
  let o = 0;
  raw[o] = 0x00; o++;                          // options
  raw.set(scanPub, o); o += 33;                // scan pubkey (33 bytes compressed)
  raw[o] = 0x01; o++;                          // N = 1 spend key
  raw.set(spendPub, o); o += 33;               // spend pubkey (33 bytes compressed)
  raw[o] = 0x00; o++;                          // number_signatures = 0 (matches wallet default)
  raw[o] = 0x00;                               // prefix_bits = 0
  return raw;
}

function encodeStealthAddress(hrp, rawBytes) {
  const data5bit = convertBits(Array.from(rawBytes), 8, 5, true);
  return bech32Encode(hrp, data5bit);
}

function decodeStealthAddress(addr) {
  // Find HRP by looking for the last "1"
  const sepIdx = addr.lastIndexOf("1");
  if (sepIdx < 1) throw new Error("Invalid bech32: no separator");
  const hrp = addr.slice(0, sepIdx);
  const dataChars = addr.slice(sepIdx + 1);

  // Decode 5-bit values
  const data5 = [];
  for (const ch of dataChars) {
    const v = BECH32_ALPH.indexOf(ch);
    if (v === -1) throw new Error("Invalid bech32 character: " + ch);
    data5.push(v);
  }

  // Verify checksum
  const values = bech32HrpExpand(hrp).concat(data5);
  if (bech32Polymod(values) !== 1) throw new Error("Invalid bech32 checksum");

  // Strip checksum (last 6)
  const payload5 = data5.slice(0, -6);

  // Convert back to 8-bit
  const raw = convertBits(payload5, 5, 8, false);

  if (raw.length < 70) throw new Error("Stealth address too short: " + raw.length + " bytes");

  return {
    hrp,
    options: raw[0],
    scanPub: new Uint8Array(raw.slice(1, 34)),
    nSpendKeys: raw[34],
    spendPub: new Uint8Array(raw.slice(35, 68)),
    nSigs: raw[68],
    prefixBits: raw[69],
  };
}

// -------------------------
// UI
// -------------------------
const $ = (id) => document.getElementById(id);

function setNetBadge() {
  $("netBadge").textContent = `Network: ${NET.name} (${NET.stealthHrp}1… stealth addresses)`;
}
setNetBadge();

// Entropy
let seed = null;
let progress = 0;
let done = false;
const TARGET = 220;

const SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

function isValidPrivkey32(priv) {
  if (!(priv instanceof Uint8Array) || priv.length !== 32) return false;
  let x = 0n;
  for (const b of priv) x = (x << 8n) + BigInt(b);
  return x > 0n && x < SECP_N;
}

function deriveValidKey(baseSeed, label) {
  let priv = sha256(concatBytes(baseSeed, utf8Bytes(label)));
  for (let i = 0; i < 1000; i++) {
    if (isValidPrivkey32(priv)) return priv;
    priv = sha256(concatBytes(priv, new Uint8Array([i & 255])));
  }
  throw new Error("Failed to derive valid private key for: " + label);
}

function resetAll() {
  seed = null;
  progress = 0;
  done = false;
  $("entropyCard").style.display = "none";
  $("barFill").style.width = "0%";
  $("barText").textContent = "0%";
  $("outAddr").textContent = "—";
  $("outScanWif").textContent = "—";
  $("outSpendWif").textContent = "—";
  $("outScanPub").textContent = "";
  $("outSpendPub").textContent = "";
  $("verifyOut").textContent = "";
}

function startEntropy() {
  resetAll();
  $("entropyCard").style.display = "block";

  const r = new Uint8Array(32);
  crypto.getRandomValues(r);
  seed = sha256(r);

  const box = $("entropyBox");

  const onMove = (evt) => {
    if (!seed || done) return;
    const x = Math.floor(evt.clientX || 0);
    const y = Math.floor(evt.clientY || 0);
    const t = Math.floor(performance.now());
    seed = sha256(concatBytes(seed, utf8Bytes(`${x},${y},${t},${progress}`)));

    progress++;
    const pct = Math.min(100, Math.floor((progress / TARGET) * 100));
    $("barFill").style.width = pct + "%";
    $("barText").textContent = pct + "%";

    if (progress >= TARGET) {
      done = true;
      box.removeEventListener("mousemove", onMove);
      $("outAddr").textContent = "Generating…";
      $("outScanWif").textContent = "Generating…";
      $("outSpendWif").textContent = "Generating…";

      try {
        finishGenerate();
      } catch (e) {
        console.error(e);
        $("outAddr").textContent = "ERROR";
        $("outScanWif").textContent = "ERROR: " + (e?.message || e);
        $("outSpendWif").textContent = "ERROR";
        seed = null;
        progress = 0;
        done = false;
      }
    }
  };

  box.addEventListener("mousemove", onMove, { passive: true });
}

function finishGenerate() {
  // Derive two independent keys from the seed
  const scanPriv = deriveValidKey(seed, "veil-stealth-scan-v1");
  const spendPriv = deriveValidKey(sha256(concatBytes(seed, utf8Bytes("split"))), "veil-stealth-spend-v1");

  const scanPub = getPublicKey(scanPriv, true);   // 33 bytes compressed
  const spendPub = getPublicKey(spendPriv, true); // 33 bytes compressed

  // Build stealth address
  const raw = buildStealthRaw(scanPub, spendPub);
  const addr = encodeStealthAddress(NET.stealthHrp, raw);

  // WIF encode both private keys
  const scanWif = wifFromPrivkey(scanPriv, NET.wif);
  const spendWif = wifFromPrivkey(spendPriv, NET.wif);

  // Display
  $("outAddr").textContent = addr;
  $("outScanWif").textContent = scanWif;
  $("outSpendWif").textContent = spendWif;
  $("outScanPub").textContent = bytesToHex(scanPub);
  $("outSpendPub").textContent = bytesToHex(spendPub);

  // Hide entropy card
  $("entropyCard").style.display = "none";

  // Wipe seed
  seed = null;
  progress = 0;
}

function verifyKeys() {
  const scanWif = $("verifyScanWif").value.trim();
  const spendWif = $("verifySpendWif").value.trim();
  if (!scanWif || !spendWif) {
    $("verifyOut").textContent = "Please enter both WIF keys.";
    return;
  }

  try {
    const scanPriv = privFromWif(scanWif);
    const spendPriv = privFromWif(spendWif);

    const scanPub = getPublicKey(scanPriv, true);
    const spendPub = getPublicKey(spendPriv, true);

    const raw = buildStealthRaw(scanPub, spendPub);
    const addr = encodeStealthAddress(NET.stealthHrp, raw);

    $("verifyOut").textContent = `Derived stealth address: ${addr}`;
    $("verifyOut").style.color = "#2d8a2d";
  } catch (e) {
    $("verifyOut").textContent = `Error: ${e.message}`;
    $("verifyOut").style.color = "#c44";
  }
}

function decodeAddr() {
  const addr = $("decodeInput").value.trim();
  if (!addr) return;

  try {
    const decoded = decodeStealthAddress(addr);
    $("decodeOut").innerHTML =
      `<b>HRP:</b> ${decoded.hrp}<br>` +
      `<b>Options:</b> 0x${decoded.options.toString(16).padStart(2, '0')}<br>` +
      `<b>Scan pubkey:</b> ${bytesToHex(decoded.scanPub)}<br>` +
      `<b>Spend pubkey:</b> ${bytesToHex(decoded.spendPub)}<br>` +
      `<b>Spend keys:</b> ${decoded.nSpendKeys}<br>` +
      `<b>Required sigs:</b> ${decoded.nSigs}<br>` +
      `<b>Prefix bits:</b> ${decoded.prefixBits}`;
    $("decodeOut").style.color = "#111";
  } catch (e) {
    $("decodeOut").textContent = `Error: ${e.message}`;
    $("decodeOut").style.color = "#c44";
  }
}

// Wire buttons
$("btnStart").addEventListener("click", startEntropy);
$("btnReset").addEventListener("click", resetAll);
$("btnVerify").addEventListener("click", verifyKeys);
$("btnDecode").addEventListener("click", decodeAddr);
