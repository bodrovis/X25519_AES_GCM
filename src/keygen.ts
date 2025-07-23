import fs from "node:fs";
import { x25519 } from "@noble/curves/ed25519";
import { randomBytes } from "@noble/hashes/utils";
import { toHex } from "./utils.js";

function main(): void {
	const priv: Uint8Array = randomBytes(32);
	const pub: Uint8Array = x25519.getPublicKey(priv);

	fs.writeFileSync("admin-priv.hex", toHex(priv), { encoding: "utf8" });
	fs.writeFileSync("admin-pub.hex", toHex(pub), { encoding: "utf8" });

	console.log("Key pair generated (x25519):");
	console.log("Pub :", toHex(pub));
}

main();
