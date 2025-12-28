# Veil Paper Wallet (Basecoin Bech32)

A minimal, offline-capable **Veil basecoin** paper wallet generator.

- **Mainnet** addresses: `bv1...`
- **Testnet** addresses: `tv1...`
- Generates a **compressed WIF** private key + matching **bech32 (witness v0 / P2WPKH)** address.
- Designed so users can **download the repo and run it fully offline** after building.

> ⚠️ Best practice: generate wallets on an offline computer you control, ideally from a clean OS, and verify the WIF → address derivation locally.

---

## Why this exists

GitHub Pages is convenient for demos, but real paper wallet generation should be done **offline**. This repo supports:

- **Online demo** (GitHub Pages) for convenience
- **Offline build + run** for real usage

---

## Requirements

- Node.js (LTS recommended)
- npm

git clone https://github.com/ohcee/Veil-Paper-Wallet.git
cd Veil-Paper-Wallet
npm install

### Build
- npm run build
This produces bundle.js, which index.html loads.
After building, you can copy the entire folder to an offline machine and open index.html there (or run a tiny local server).
Run locally (optional)
You can open index.html directly, but a tiny local server can avoid browser module/file restrictions.
### Python
python3 -m http.server 8080
Then open:
http://localhost:8080
If port 8080 is taken, change it:
python3 -m http.server 9090
### Testnet mode
To generate testnet addresses (tv1...), open the page with:
?testnet=true
### Examples:
index.html?testnet=true
http://localhost:8080/?testnet=true
## To return to mainnet:
remove the query string (no testnet=true)
### How to verify the wallet you generated
1) Verify inside this tool (best, offline)
Use the Verify WIF box:
Paste the WIF
Click Verify
The tool derives the bech32 address from that WIF locally
If the derived address matches the displayed address, your key/address pairing is correct.
2) Verify via Veil Explorer API (format + chain info)
This is an online check (useful after the fact). It verifies the address is recognized and shows script details.
### Example:
curl -s -X POST 'https://explorer-api.veil-project.com/api/Address' \
  -H 'Content-Type: application/json' \
  -d '{"address":"bv1YOURADDRESSHERE","forceScanAmount":true}'
### Typical response fields include:
isValid
scriptPubKey
iswitness
witness_version
witness_program
### Notes:
The explorer may not show an address if it has never appeared on-chain.
The strongest verification is still: derive the address from the WIF locally.
### Project layout
index.html — UI (open this)
app.js — source code (build input)
bundle.js — bundled build output (offline ready)
package.json / package-lock.json — dependencies + scripts
README.md — documentation
### Development notes
Uses @noble/secp256k1 for public key derivation
Uses @noble/hashes for SHA256 and RIPEMD160
Implements Bech32 encode and Base58Check (WIF) internally
Uses browser crypto.getRandomValues() plus mouse movement mixing for entropy
### Security notes (read this)
Paper wallets are easy to mess up operationally. A few practical rules:
Generate keys on a machine you trust, ideally offline.
Don’t reuse paper wallet keys across multiple contexts.
Printing can leak (printers can store jobs). Writing down by hand is safer than printing.
Verify the WIF → address derivation before funding.
Always test with a small amount first before trusting large balances.
### Disclaimer
This software is provided as-is, without warranty of any kind.
You are responsible for verifying your environment and operational security.
Always test with small amounts first before trusting large balances.
::contentReference[oaicite:0]{index=0}
