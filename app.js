import { getPublicKey, utils as secpUtils } from "@noble/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { ripemd160 } from "@noble/hashes/legacy";

function getParamValue(param) {
  const m = new RegExp("[?&]" + param + "=([^&;#]+)").exec(location.search);
  return m ? decodeURIComponent(m[1].replace(/\+/g, "%20")) : null;
}
const isTestNet = (getParamValue("testnet") === "true");

const NET = isTestNet
  ? { name: "testnet", hrp: "tv", wif: 0xEF } // Veil testnet WIF prefix = 239
  : { name: "mainnet", hrp: "bv", wif: 0x80 }; // Veil mainnet WIF prefix = 128

// -------------------------
// Helpers: bytes / concat
// -------------------------
const u8 = (n) => new Uint8Array(n);
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

// -------------------------
// Base58 (for WIF)
// -------------------------
const B58_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58encode(bytes) {
  // Big-int style base58
  let x = 0n;
  for (const b of bytes) x = (x << 8n) + BigInt(b);

  let out = "";
  while (x > 0n) {
    const mod = x % 58n;
    out = B58_ALPH[Number(mod)] + out;
    x = x / 58n;
  }
  // leading zeros
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) out = "1" + out;
  return out || "1";
}

// -------------------------
// Bech32 (BIP173) encode
// witness v0 P2WPKH
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
function encodeWitnessV0Address(hrp, programBytes20) {
  if (programBytes20.length !== 20) throw new Error("P2WPKH program must be 20 bytes");
  const version = 0; // witness v0
  const data = [version].concat(convertBits(programBytes20, 8, 5, true));
  return bech32Encode(hrp, data);
}

// -------------------------
// HASH160(pubkey) = RIPEMD160(SHA256(pubkey))
// -------------------------
function hash160(bytes) {
  return ripemd160(sha256(bytes));
}

// -------------------------
// WIF encode (compressed)
// prefix + privkey32 + 0x01 + checksum(4)
// checksum = SHA256(SHA256(payload))
// -------------------------
function wifFromPrivkey(priv32, wifPrefix) {
  if (priv32.length !== 32) throw new Error("privkey must be 32 bytes");
  const payload = concatBytes(new Uint8Array([wifPrefix]), priv32, new Uint8Array([0x01]));
  const checksum = sha256(sha256(payload)).slice(0, 4);
  return base58encode(concatBytes(payload, checksum));
}

// -------------------------
// Decode WIF (for verify)
// (We only need privkey32 out)
// -------------------------
function base58decode(str) {
  let x = 0n;
  for (const ch of str) {
    const v = B58_ALPH.indexOf(ch);
    if (v === -1) throw new Error("Invalid base58 character");
    x = x * 58n + BigInt(v);
  }
  // to bytes
  let bytes = [];
  while (x > 0n) {
    bytes.push(Number(x & 0xffn));
    x >>= 8n;
  }
  bytes.reverse();
  // leading zeros
  for (let i = 0; i < str.length && str[i] === "1"; i++) bytes.unshift(0);
  return new Uint8Array(bytes);
}

function privFromWif(wif) {
  const raw = base58decode(wif);
  if (raw.length < 4 + 1 + 32) throw new Error("WIF too short");
  const body = raw.slice(0, -4);
  const chk = raw.slice(-4);
  const chk2 = sha256(sha256(body)).slice(0, 4);
  for (let i = 0; i < 4; i++) if (chk[i] !== chk2[i]) throw new Error("Bad WIF checksum");

  const prefix = body[0];
  const key = body.slice(1, 33);
  const hasComp = (body.length === 34 && body[33] === 0x01);

  if (!hasComp) throw new Error("This tool expects compressed WIF (has trailing 0x01).");
  return { prefix, priv32: key };
}

// -------------------------
// UI
// -------------------------
const $ = (id) => document.getElementById(id);

function setNetBadge() {
  $("netBadge").textContent = `Network: ${NET.name} (${NET.hrp}1… addresses)`;
}

setNetBadge();

// Entropy mixer:
// Start with secure randomness, then repeatedly hash in mouse movements.
let seed = null;
let progress = 0;
let done = false;
const TARGET = 220; // mouse events required (tweak)

function resetAll() {
  seed = null;
  progress = 0;
  done = false;
  $("entropyCard").style.display = "none";
  $("barFill").style.width = "0%";
  $("barText").textContent = "0%";
  $("outAddr").textContent = "—";
  $("outWif").textContent = "—";
  $("verifyWif").value = "";
  $("verifyOut").textContent = "";
}

function startEntropy() {
  resetAll();
  $("entropyCard").style.display = "block";

  // seed from crypto
  const r = new Uint8Array(32);
  crypto.getRandomValues(r);
  seed = sha256(r);

  const box = $("entropyBox");

  const onMove = (evt) => {
    if (!seed || done) return;

    // Mix in mouse coordinates + time
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

        // UI feedback immediately
        $("outAddr").textContent = "Generating…";
        $("outWif").textContent = "Generating…";

        try {
        finishGenerate();
        } catch (e) {
        console.error(e);
        $("verifyOut").textContent = `Generate error: ${e?.message || e}`;
        $("outAddr").textContent = "ERROR";
        $("outWif").textContent = "ERROR";
        // Let user try again without refresh
        seed = null;
        progress = 0;
        done = false;
        }
    }
  };


  box.addEventListener("mousemove", onMove, { passive: true });
}

// secp256k1 curve order
const SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

function finishGenerate() {
  // Derive initial private key from seed
  let priv = sha256(concatBytes(seed, utf8Bytes("veil-basecoin-v1")));

  // Rehash until it's a valid secp256k1 private key
  for (let i = 0; i < 1000; i++) {
    if (isValidPrivkey32(priv)) break;
    priv = sha256(concatBytes(priv, new Uint8Array([i & 255])));
  }

  if (!isValidPrivkey32(priv)) {
    throw new Error("Failed to derive a valid private key (unexpected).");
  }

  const pub = getPublicKey(priv, true);      // compressed pubkey
  const pkh = hash160(pub);                  // 20 bytes
  const addr = encodeWitnessV0Address(NET.hrp, pkh);
  const wif = wifFromPrivkey(priv, NET.wif);

  $("outAddr").textContent = addr;
  $("outWif").textContent = wif;

  // Hide entropy card
  $("entropyCard").style.display = "none";

  // wipe seed in memory as best-effort
  seed = null;
  progress = 0;
}

function isValidPrivkey32(priv) {
  if (!(priv instanceof Uint8Array) || priv.length !== 32) return false;
  let x = 0n;
  for (const b of priv) x = (x << 8n) + BigInt(b);
  return x > 0n && x < SECP_N;
}

function verifyWif() {
  const wif = $("verifyWif").value.trim();
  if (!wif) return;

  try {
    const { prefix, priv32 } = privFromWif(wif);

    // Determine network HRP based on prefix match
    const hrp = (prefix === 0xEF) ? "tv" : (prefix === 0x80 ? "bv" : null);
    if (!hrp) throw new Error("WIF prefix not recognized for Veil (expected 0x80 or 0xEF).");

    const pub = getPublicKey(priv32, true);
    const pkh = hash160(pub);
    const addr = encodeWitnessV0Address(hrp, pkh);

    $("verifyOut").textContent = `Derived address: ${addr}`;
  } catch (e) {
    $("verifyOut").textContent = `Error: ${e.message}`;
  }
}

// Wire buttons
$("btnStart").addEventListener("click", startEntropy);
$("btnReset").addEventListener("click", resetAll);
$("btnVerify").addEventListener("click", verifyWif);
