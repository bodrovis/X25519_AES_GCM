import fs from "node:fs";
import { x25519 } from "@noble/curves/ed25519";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import sodium from "libsodium-wrappers";
import { assertLength, fromHex, toHex } from "./utils.js";

async function main(): Promise<void> {
	await sodium.ready;

	// Load raw payload from blockchain (hex-encoded)
	const fullHex = fs.readFileSync("from-blockchain.hex", "utf8").trim();
	const fullPayload = fromHex(fullHex);

	// Parse fields
	const ephPub = fullPayload.slice(0, 32);
	assertLength(ephPub, 32, "Ephemeral public key");

	const nonce = fullPayload.slice(32, 56);
	assertLength(nonce, 24, "Nonce (XChaCha)");

	const tag = fullPayload.slice(-32);
	assertLength(tag, 32, "HMAC tag");

	const ciphertext = fullPayload.slice(56, -32);
	if (ciphertext.length === 0) throw new Error("Ciphertext is empty");

	// Load admin's private key
	const privHex = fs.readFileSync("admin-priv.hex", "utf8").trim();
	const adminPriv = fromHex(privHex);
	assertLength(adminPriv, 32, "Admin private key");

	// Derive shared secret → key
	const shared = x25519.getSharedSecret(adminPriv, ephPub);
	const chachaKey = sha256(shared);
	const hmacKey = sha256(new TextEncoder().encode(`HMAC${toHex(shared)}`));

	// Rebuild HMAC input: ephPub || nonce || ciphertext
	const macInput = new Uint8Array(
		ephPub.length + nonce.length + ciphertext.length,
	);
	macInput.set(ephPub, 0);
	macInput.set(nonce, ephPub.length);
	macInput.set(ciphertext, ephPub.length + nonce.length);

	const computedTag = hmac(sha256, hmacKey, macInput);
	if (!Buffer.from(computedTag).equals(Buffer.from(tag))) {
		throw new Error("HMAC verification failed (data tampered?)");
	}
	console.log("HMAC verified");

	// Decrypt
	const decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
		null, // no additional data
		ciphertext,
		ephPub, // associated data
		nonce,
		chachaKey,
	);

	const plaintext = new TextDecoder().decode(decrypted);
	console.log("Decrypted message:", plaintext);
}

main().catch((err) => {
	console.error("Decryption failed:", err);
	process.exit(1);
});
