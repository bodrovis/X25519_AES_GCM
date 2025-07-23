import { webcrypto as crypto } from "node:crypto";
import fs from "node:fs";
import { x25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { fromHex } from "./utils.js";

async function main(): Promise<void> {
	// Get raw data that might come from blockchain
	const fullHex = fs.readFileSync("from-blockchain.hex", "utf8").trim();
	const fullPayload = fromHex(fullHex);

	// Parse fields
	const ephPub = fullPayload.slice(0, 32);
	const iv = fullPayload.slice(32, 44);
	const ciphertext = fullPayload.slice(44);

	// Get private key (might be entered on a web page, MUST be secure)
	const adminPrivHex = fs.readFileSync("admin-priv.hex", "utf8").trim();
	const adminPriv = fromHex(adminPrivHex);

	// Derive shared secret
	const shared = x25519.getSharedSecret(adminPriv, ephPub);
	const aesKey = sha256(shared); // 32 bytes!

	// AES-GCM, decipher
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

	// Decode and print decrypted data
	const plaintext = new TextDecoder().decode(decryptedBuffer);
	console.log("Decrypted message:", plaintext);
}

main().catch((err) => {
	console.error("Decryption failed:", err);
	process.exit(1);
});
