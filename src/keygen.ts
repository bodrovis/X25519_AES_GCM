import fs from "node:fs";
import { x25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes } from "@noble/hashes/utils";
import { toHex } from "./utils.js";

function printFingerprint(pub: Uint8Array) {
	const hash = sha256(pub);
	return Buffer.from(hash.slice(0, 6))
		.toString("hex")
		.match(/.{2}/g)
		?.join(":");
}

function main(): void {
	const priv: Uint8Array = randomBytes(32);
	const pub: Uint8Array = x25519.getPublicKey(priv);

	fs.writeFileSync("admin-priv.hex", toHex(priv), { encoding: "utf8" });
	fs.writeFileSync("admin-pub.hex", toHex(pub), { encoding: "utf8" });

	console.log("Key pair generated (x25519)!");
	console.log("Pub:", toHex(pub));
	console.log(`Fingerprint: ${printFingerprint(pub)}`);
}

main();
