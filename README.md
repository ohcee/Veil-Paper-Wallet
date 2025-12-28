# Veil Paper Wallet (Basecoin Bech32) — Offline Generator

A **static, offline-capable** Veil paper wallet generator for **Basecoin bech32** addresses:

- **Mainnet:** `bv1...`
- **Testnet:** `tv1...`

This tool generates:
- **Compressed WIF private key** (Veil prefixes: `0x80` mainnet / `0xEF` testnet)
- **Bech32 P2WPKH (witness v0) address** (`bv1...` / `tv1...`)
- Optional **“Verify WIF”** feature to re-derive the address locally from the WIF

Repository:
- https://github.com/ohcee/Veil-Paper-Wallet

---

## Security notes (read this first)

This generator is safe **only when used offline**.

Recommended safe workflow:
1. Download this repository (or a Release zip) while online.
2. Verify you are using the correct repo and files.
3. Disconnect from the internet (**airplane mode / unplug ethernet / disable Wi-Fi**).
4. Open `index.html` locally in your browser.
5. Generate your wallet offline.
6. Store the private key safely (write it down, print it, or store encrypted).

Do **not**:
- paste your private key / WIF into unknown websites
- generate keys on a compromised machine
- screenshot or upload private keys anywhere

---

## What this wallet generates (technical)

- Address type: **Bech32 SegWit v0 (P2WPKH)**  
- Witness program: **20-byte HASH160(pubkey)**  
- Bech32 HRP:
  - Mainnet: `bv`
  - Testnet: `tv`
- WIF encoding:
  - Prefix: `0x80` (mainnet) or `0xEF` (testnet)
  - Compressed key marker: `0x01`
  - Checksum: first 4 bytes of `SHA256(SHA256(payload))`

---

## Quick start (offline use)

### Option A (recommended): use the included offline bundle
If this repo contains a prebuilt `bundle.js`, you can use it without building anything.

Steps:
1. Download the repo as a ZIP (GitHub → **Code** → **Download ZIP**) or grab a Release zip.
2. Extract it.
3. Disconnect from the internet.
4. Open `index.html` directly in a browser.

That’s it. No network requests are required to generate keys.

---

## Build it yourself (recommended for power users)

Building locally lets you verify that `bundle.js` is produced from `app.js` and the pinned dependencies.

### Requirements
- Node.js + npm

### Install dependencies
```bash
npm ci
