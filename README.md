# Hybrid Encryption Demo (X25519 and AES‑GCM)

A small Node.js/TypeScript project showing how to encrypt off‑chain data for on‑chain storage using X25519 + AES‑GCM.

## Available scripts

```
npm run keygen     # generate X25519 key pair: admin-priv.hex and admin-pub.hex
npm run encrypt    # encrypt demo plaintext: payload.json & from-blockchain.hex
npm run decrypt    # decrypt from-blockchain.hex: prints original message
```

### Keygen

Generates a 32‑byte X25519 keypair and writes:

- `admin-priv.hex` (your private key)  
- `admin-pub.hex` (your public key)

### Encrypt

- Reads `admin-pub.hex`
- Generates an ephemeral X25519 key and does ECDH -> shared secret
- Derives a 256‑bit AES key via SHA‑256
- Encrypts some secret data with AES‑GCM
- Writes:
  - `payload.json` (JSON with `ephPub`, `iv`, `ciphertext`)
  - `from-blockchain.hex` (raw `ephPub|iv|ciphertext` hex)

### Decrypt

- Reads `from-blockchain.hex` and `admin-priv.hex`
- Splits out `ephPub`, `iv`, and `ciphertext`
- Re‑derives AES key via ECDH + SHA‑256
- Decrypts and logs the original plaintext
