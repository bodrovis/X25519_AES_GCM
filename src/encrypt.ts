import { webcrypto as crypto } from "node:crypto";
import fs from "node:fs";
import { x25519 } from "@noble/curves/ed25519";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes } from "@noble/hashes/utils";
import { assertLength, toHex } from "./utils.js";

async function main(): Promise<void> {
	// Get pub key
	const pubHex = fs.readFileSync("admin-pub.hex", "utf8").trim();
	const adminPub = Uint8Array.from(Buffer.from(pubHex, "hex"));
	assertLength(adminPub, 32, "Admin public key");

	// Make shared secret
	const ephPriv = randomBytes(32);
	const ephPub = x25519.getPublicKey(ephPriv);
	assertLength(ephPub, 32, "Ephemeral public key");

	const shared = x25519.getSharedSecret(ephPriv, adminPub);
	const aesKey = sha256(shared); // 32 bytes!
	assertLength(aesKey, 32, "Derived AES key");

	console.log("Ephemeral public key:", toHex(ephPub));
	console.log("Derived AES key:", toHex(aesKey));

	// Derive separate HMAC key
	const hmacKey = sha256(new TextEncoder().encode(`HMAC${toHex(shared)}`));

	// AES-GCM, ciphering
	const iv = randomBytes(12);
	assertLength(iv, 12, "IV");

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

	const tag = hmac(sha256, hmacKey, ciphertext);
	assertLength(tag, 32, "HMAC tag");

	// Make a payload
	const payload = {
		ephPub: toHex(ephPub),
		iv: toHex(iv),
		ciphertext: toHex(ciphertext),
		hmac: toHex(tag),
	};

	const payloadFilename = "payload.json";
	fs.writeFileSync(payloadFilename, JSON.stringify(payload, null, 2), {
		encoding: "utf8",
	});
	console.log(`Encrypted and saved to ${payloadFilename}`);

	// Concatenate binary payload (ephPub || iv || ciphertext || hmac)
	const fullPayload = new Uint8Array(
		ephPub.length + iv.length + ciphertext.length + tag.length,
	);
	fullPayload.set(ephPub, 0);
	fullPayload.set(iv, ephPub.length);
	fullPayload.set(ciphertext, ephPub.length + iv.length);
	fullPayload.set(tag, ephPub.length + iv.length + ciphertext.length);

	const rawHex = toHex(fullPayload);
	console.log("Raw payload (hex):");
	console.log(rawHex);

	const hexFilename = "from-blockchain.hex";
	fs.writeFileSync(hexFilename, rawHex, { encoding: "utf8" });
	console.log(`Hex payload saved to ${hexFilename}`);
}

main().catch((err) => {
	console.error("Error:", err);
	process.exit(1);
});
