import { webcrypto as crypto } from "node:crypto";
import fs from "node:fs";
import { x25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes } from "@noble/hashes/utils";
import { toHex } from "./utils.js";

async function main(): Promise<void> {
	// Get pub key
	const pubHex = fs.readFileSync("admin-pub.hex", "utf8").trim();
	const adminPub = Uint8Array.from(Buffer.from(pubHex, "hex"));

	// Make shared secret
	const ephPriv = randomBytes(32);
	const ephPub = x25519.getPublicKey(ephPriv);
	const shared = x25519.getSharedSecret(ephPriv, adminPub);
	const aesKey = sha256(shared); // 32 bytes!

	console.log("Ephemeral public key:", toHex(ephPub));
	console.log("Derived AES key:", toHex(aesKey));

	// AES-GCM, ciphering
	const iv = crypto.getRandomValues(new Uint8Array(12));
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

	// Make a payload
	const payload = {
		ephPub: toHex(ephPub),
		iv: toHex(iv),
		ciphertext: toHex(new Uint8Array(cipherBuffer)),
	};
	fs.writeFileSync("payload.json", JSON.stringify(payload, null, 2), {
		encoding: "utf8",
	});
	console.log("Encrypted and saved to payload.json");

	// Make raw bytes (as we don't store JSON in a blockchain)
	const fullPayload = new Uint8Array(
		ephPub.length + iv.length + cipherBuffer.byteLength,
	);
	fullPayload.set(ephPub, 0);
	fullPayload.set(iv, ephPub.length);
	fullPayload.set(new Uint8Array(cipherBuffer), ephPub.length + iv.length);

	const rawHex = toHex(fullPayload);

	console.log("Raw payload (hex):");
	console.log(rawHex);

	fs.writeFileSync("from-blockchain.hex", rawHex, { encoding: "utf8" });
	console.log("Hex payload saved to from-blockchain.hex");
}

main().catch((err) => {
	console.error("Error:", err);
	process.exit(1);
});
