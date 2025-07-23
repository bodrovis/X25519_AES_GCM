import { webcrypto as crypto } from "node:crypto";
import fs from "node:fs";
import { x25519 } from "@noble/curves/ed25519";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes } from "@noble/hashes/utils";
import { assertLength, toHex } from "./utils.js";

async function main(): Promise<void> {
	// Load admin public key
	const pubHex = fs.readFileSync("admin-pub.hex", "utf8").trim();
	const adminPub = Uint8Array.from(Buffer.from(pubHex, "hex"));
	assertLength(adminPub, 32, "Admin public key");

	// Generate ephemeral keypair
	const ephPriv = randomBytes(32);
	const ephPub = x25519.getPublicKey(ephPriv);
	assertLength(ephPub, 32, "Ephemeral public key");

	// Shared secret → AES key
	const shared = x25519.getSharedSecret(ephPriv, adminPub);
	const aesKey = sha256(shared);
	assertLength(aesKey, 32, "Derived AES key");

	console.log("Ephemeral public key:", toHex(ephPub));
	console.log("Derived AES key:", toHex(aesKey));

	// HMAC key derived from shared secret (separate from AES key)
	const hmacKey = sha256(new TextEncoder().encode(`HMAC${toHex(shared)}`));
	assertLength(hmacKey, 32, "HMAC key");

	// Generate IV for AES-GCM
	const iv = randomBytes(12);
	assertLength(iv, 12, "IV");

	// Encrypt the message
	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		aesKey,
		{ name: "AES-GCM" },
		false,
		["encrypt"],
	);

	const plainText = new TextEncoder().encode(
		"секретные данные для связи: @bodrovis (https://bodrovis.tech)",
	);
	const cipherBuffer = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv },
		cryptoKey,
		plainText,
	);
	const ciphertext = new Uint8Array(cipherBuffer);

	// HMAC over full structure: ephPub || iv || ciphertext
	const macInput = new Uint8Array(
		ephPub.length + iv.length + ciphertext.length,
	);
	macInput.set(ephPub, 0);
	macInput.set(iv, ephPub.length);
	macInput.set(ciphertext, ephPub.length + iv.length);

	const tag = hmac(sha256, hmacKey, macInput);
	assertLength(tag, 32, "HMAC tag");

	// Write payload to JSON
	const payload = {
		ephPub: toHex(ephPub),
		iv: toHex(iv),
		ciphertext: toHex(ciphertext),
		hmac: toHex(tag),
	};

	const payloadFilename = "payload.json";
	fs.writeFileSync(payloadFilename, JSON.stringify(payload, null, 2), "utf8");
	console.log(`Encrypted and saved to ${payloadFilename}`);

	// Write raw payload: ephPub || iv || ciphertext || hmac
	const fullPayload = new Uint8Array(macInput.length + tag.length);
	fullPayload.set(macInput, 0);
	fullPayload.set(tag, macInput.length);

	const hexOutput = toHex(fullPayload);

	const hexFilename = "from-blockchain.hex";
	fs.writeFileSync(hexFilename, hexOutput, "utf8");
	console.log(`Hex payload saved to ${hexFilename}`);
	console.log("Raw payload (hex):");
	console.log(hexOutput);
}

main().catch((err) => {
	console.error("Encryption failed:", err);
	process.exit(1);
});
