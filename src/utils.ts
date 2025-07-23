export function toHex(u8: Uint8Array): string {
	return Buffer.from(u8).toString("hex");
}

export function fromHex(hex: string): Uint8Array {
	return Uint8Array.from(Buffer.from(hex, "hex"));
}

export function assertLength(buf: Uint8Array, expected: number, label: string) {
	if (buf.length !== expected) {
		throw new Error(
			`${label} must be ${expected} bytes, got ${buf.length} bytes`,
		);
	}
}
