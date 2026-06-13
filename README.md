# Veil Paper Wallet

Offline-capable Veil paper wallet generator for both **Basecoin** and **Stealth/RingCT** addresses.

GitHub Pages is only for quick testing/demo. **For real use, download the repo and run it offline.**

## Wallets

| Wallet | Address Format | Keys | File |
|---|---|---|---|
| Basecoin | `bv1…` (mainnet) / `tv1…` (testnet) | 1 private key (WIF) | `index.html` |
| Stealth / RingCT | `sv1qq…` (mainnet) / `tps1qq…` (testnet) | 2 private keys (scan + spend WIF) | `stealth.html` |

## Quick Start

```
git clone https://github.com/ohcee/Veil-Paper-Wallet.git
cd Veil-Paper-Wallet
npm install
```

## Build

```
npm run build-all
```

This builds both `bundle.js` (basecoin) and `stealth-bundle.js` (stealth). After building, you can copy the whole folder to an offline machine and open the HTML files directly.

## Serve Locally

```
python3 -m http.server 8080
```

Open:
- Basecoin: `http://localhost:8080`
- Stealth: `http://localhost:8080/stealth.html`

## Testnet

Add `?testnet=true` to either URL:
- `http://localhost:8080?testnet=true`
- `http://localhost:8080/stealth.html?testnet=true`

## Stealth Wallet Details

The stealth wallet generates a dual-key stealth address compatible with Veil's RingCT system. Two private keys are generated:

- **Scan key** — required to detect incoming transactions
- **Spend key** — required to spend received funds

**Both keys are needed to access your funds.** Losing either one means permanent loss. Store them securely.

### Address Encoding

The stealth address encodes both public keys in bech32 format:

```
[options: 1 byte] [scan_pubkey: 33 bytes] [N: 1 byte]
[spend_pubkey: 33 bytes] [num_sigs: 1 byte] [prefix_bits: 1 byte]
= 70 bytes → bech32 with "sv" (mainnet) or "tps" (testnet) prefix
```

## Security

- This tool does not contact any API
- All key generation happens locally in the browser
- Mouse entropy is mixed with `crypto.getRandomValues()` for randomness
- Use on a clean, offline machine for maximum security
- Print or write down your keys — do not store digitally
