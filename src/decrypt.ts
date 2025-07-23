import { webcrypto as crypto } from "node:crypto";
import fs from "node:fs";
import { x25519 } from "@noble/curves/ed25519";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { assertLength, fromHex, toHex } from "./utils.js";

async function main(): Promise<void> {
	// Load raw payload from blockchain (hex-encoded)
	const fullHex = fs.readFileSync("from-blockchain.hex", "utf8").trim();
	const fullPayload = fromHex(fullHex);

	// Parse fields
	const ephPub = fullPayload.slice(0, 32);
	assertLength(ephPub, 32, "Ephemeral public key");

	const iv = fullPayload.slice(32, 44);
	assertLength(iv, 12, "IV");

	const tag = fullPayload.slice(-32);
	assertLength(tag, 32, "HMAC tag");

	const ciphertext = fullPayload.slice(44, -32);
	if (ciphertext.length === 0) throw new Error("Ciphertext is empty");

	// Load admin's private key
	const privHex = fs.readFileSync("admin-priv.hex", "utf8").trim();
	const adminPriv = fromHex(privHex);
	assertLength(adminPriv, 32, "Admin private key");

	// Derive shared secret → AES + HMAC key
	const shared = x25519.getSharedSecret(adminPriv, ephPub);
	const aesKey = sha256(shared);
	const hmacKey = sha256(new TextEncoder().encode(`HMAC${toHex(shared)}`));

	// Rebuild HMAC input: ephPub || iv || ciphertext
	const macInput = new Uint8Array(
		ephPub.length + iv.length + ciphertext.length,
	);
	macInput.set(ephPub, 0);
	macInput.set(iv, ephPub.length);
	macInput.set(ciphertext, ephPub.length + iv.length);

	const computedTag = hmac(sha256, hmacKey, macInput);
	if (!Buffer.from(computedTag).equals(Buffer.from(tag))) {
		throw new Error("HMAC verification failed (data tampered?)");
	}
	console.log("HMAC verified");

	// Decrypt the ciphertext
	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		aesKey,
		"AES-GCM",
		false,
		["decrypt"],
	);
	const decryptedBuffer = await crypto.subtle.decrypt(
		{ name: "AES-GCM", iv },
		cryptoKey,
		ciphertext,
	);

	const plaintext = new TextDecoder().decode(decryptedBuffer);
	console.log("Decrypted message:", plaintext);
}

main().catch((err) => {
	console.error("Decryption failed:", err);
	process.exit(1);
});
