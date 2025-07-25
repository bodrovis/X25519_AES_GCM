import fs from "node:fs";
import { x25519 } from "@noble/curves/ed25519";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes } from "@noble/hashes/utils";
import sodium from "libsodium-wrappers";
import { assertLength, toHex } from "./utils.js";

async function main(): Promise<void> {
	await sodium.ready;

	// Load admin public key
	const pubHex = fs.readFileSync("admin-pub.hex", "utf8").trim();
	const adminPub = Uint8Array.from(Buffer.from(pubHex, "hex"));
	assertLength(adminPub, 32, "Admin public key");

	// Generate ephemeral keypair
	const ephPriv = randomBytes(32);
	const ephPub = x25519.getPublicKey(ephPriv);
	assertLength(ephPub, 32, "Ephemeral public key");

	// Shared secret → encryption key
	const shared = x25519.getSharedSecret(ephPriv, adminPub);
	const chachaKey = sha256(shared);
	assertLength(chachaKey, 32, "Derived ChaCha20 key");

	console.log("Ephemeral public key:", toHex(ephPub));
	console.log("Derived ChaCha20 key:", toHex(chachaKey));

	// HMAC key (optional, separate)
	const hmacKey = sha256(new TextEncoder().encode(`HMAC${toHex(shared)}`));
	assertLength(hmacKey, 32, "HMAC key");

	// Nonce (IV)
	const nonce = randomBytes(24);
	assertLength(nonce, 24, "Nonce");

	// Message
	const plainText = new TextEncoder().encode(
		"секретные данные для связи: @bodrovis (https://bodrovis.tech)",
	);

	// Encrypt with XChaCha20-Poly1305 (AD = ephPub)
	const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
		plainText,
		ephPub,
		null,
		nonce,
		chachaKey,
	);

	// HMAC over ephPub || nonce || ciphertext
	const macInput = new Uint8Array(
		ephPub.length + nonce.length + ciphertext.length,
	);
	macInput.set(ephPub, 0);
	macInput.set(nonce, ephPub.length);
	macInput.set(ciphertext, ephPub.length + nonce.length);

	const tag = hmac(sha256, hmacKey, macInput);
	assertLength(tag, 32, "HMAC tag");

	// Write payload to JSON
	const payload = {
		ephPub: toHex(ephPub),
		nonce: toHex(nonce),
		ciphertext: toHex(ciphertext),
		hmac: toHex(tag),
	};

	const payloadFilename = "payload.json";
	fs.writeFileSync(payloadFilename, JSON.stringify(payload, null, 2), "utf8");
	console.log(`Encrypted and saved to ${payloadFilename}`);

	// Write raw payload: ephPub || nonce || ciphertext || hmac
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
