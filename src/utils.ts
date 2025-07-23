export function toHex(u8: Uint8Array): string {
	return Buffer.from(u8).toString("hex");
}

export function fromHex(hex: string): Uint8Array {
	return Uint8Array.from(Buffer.from(hex, "hex"));
}
