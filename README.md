# Hybrid Encryption Demo (X25519 + AES‑GCM / XChaCha20‑Poly1305)

A small Node.js/TypeScript project showing how to encrypt off‑chain data for on‑chain storage using [X25519](https://datatracker.ietf.org/doc/html/rfc7748) + authenticated encryption.

## Supported ciphers

### AES‑GCM (WebCrypto)

- Fast if AES‑NI is available (modern CPUs)
- Native support via `webcrypto.subtle`
- Good for browser compatibility or Node.js with hardware acceleration

### XChaCha20‑Poly1305 (libsodium)

- Fast on all platforms, especially without AES‑NI (e.g. ARM, mobile)
- Large 24‑byte nonce (safe even without nonce tracking)
- Resistant to side-channel attacks
- Simple, solid, battle‑tested
- Based on [libsodium](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)

## Available scripts

```
npm run keygen     # generate X25519 key pair: admin-priv.hex and admin-pub.hex
npm run encrypt    # encrypt demo plaintext: payload.json & from-blockchain.hex
npm run encryptcha # same but with XChaCha20‑Poly1305
npm run decrypt    # decrypt from-blockchain.hex: prints original message
npm run decryptcha # same but with XChaCha20‑Poly1305
```

## Keygen

Generates a 32‑byte X25519 keypair and writes:

- `admin-priv.hex` (your private key)  
- `admin-pub.hex` (your public key)

## Encrypt

### Common steps

- Reads `admin-pub.hex`
- Generates an ephemeral X25519 keypair
- Computes shared secret via ECDH
- Derives symmetric encryption key via `SHA‑256(sharedSecret)`

### AES‑GCM

- Encrypts using `AES‑GCM` and a 12‑byte IV
- Authenticated tag is embedded in the ciphertext
- Writes:
  - `payload.json` — JSON with `ephPub`, `iv`, `ciphertext`, `hmac`
  - `from-blockchain.hex` — raw `ephPub | iv | ciphertext | hmac`

### XChaCha20‑Poly1305

- Encrypts using `XChaCha20-Poly1305` and a 24‑byte nonce
- Uses `ephPub` as associated data (AEAD)
- Same `payload.json` and `from-blockchain.hex` output as above

> HMAC is added manually over the structure for additional integrity checks (optional, since AEAD already authenticates data)

## Decrypt

### Common steps

- Reads `from-blockchain.hex` and `admin-priv.hex`
- Extracts `ephPub`, nonce/IV, `ciphertext`, and `hmac`
- Re‑derives shared secret → encryption key

### AES‑GCM

- Verifies HMAC over `ephPub | iv | ciphertext`
- Decrypts using WebCrypto `AES‑GCM` and the derived key

### XChaCha20‑Poly1305

- Verifies HMAC over `ephPub | nonce | ciphertext`
- Decrypts using `libsodium.crypto_aead_xchacha20poly1305_ietf_decrypt`
- Associated data must match the original (typically `ephPub`)