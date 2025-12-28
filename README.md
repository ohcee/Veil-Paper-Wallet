# Veil Paper Wallet (Basecoin)

Offline-capable Veil basecoin paper wallet generator (bech32 `bv1...` / `tv1...`) that outputs **WIF + address**.

**GitHub Pages is only for quick testing/demo.**  
For real use, download the repo and run it **offline**.

## Quick start

```bash
git clone https://github.com/ohcee/Veil-Paper-Wallet.git
cd Veil-Paper-Wallet
npm install
```

## Run
`npm start`

## Build (offline-ready)
`npm run build`

After building, you can copy the whole folder to an offline machine and open `index.html` (or serve it locally).

## Serve locally (optional)
`python3 -m http.server 8080`

## Open: 
`http://localhost:8080`

## For Testnet 
Open with `?testnet=true:`
`http://localhost:8080?testnet=true`
