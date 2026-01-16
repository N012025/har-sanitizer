import { describe, expect, it } from "vitest";
import { extractInlineKvKeys, getHarInfo, sanitize } from "./har_sanitize";

describe("extractInlineKvKeys", () => {
	it("extracts keys from inline key=value pairs", () => {
		const input = `"value": "client_secret=mysupersecret&client_id=app123"`;
		const keys = extractInlineKvKeys(input);
		expect(keys).toEqual(["client_id", "client_secret"]);
	});

	it("filters out keys longer than 64 characters", () => {
		const longKey = "a".repeat(65);
		const input = `"value": "${longKey}=value&short_key=value"`;
		const keys = extractInlineKvKeys(input);
		expect(keys).toEqual(["short_key"]);
	});

	it("returns empty array when no keys found", () => {
		const input = `"value": "no key value pairs here"`;
		const keys = extractInlineKvKeys(input);
		expect(keys).toEqual([]);
	});

	it("deduplicates keys", () => {
		const input = `"value": "token=abc&token=def"`;
		const keys = extractInlineKvKeys(input);
		expect(keys).toEqual(["token"]);
	});

	it("extracts keys with hyphens", () => {
		const input = `"value": "x-client-data=abc123&api-key=secret"`;
		const keys = extractInlineKvKeys(input);
		expect(keys).toEqual(["api-key", "x-client-data"]);
	});
});

describe("getHarInfo", () => {
	it("extracts inlineKvPairs from HAR content", () => {
		const har = JSON.stringify({
			log: {
				entries: [
					{
						request: {
							headers: [
								{
									name: "X-Custom-Auth",
									value: "client_secret=mysupersecret&client_id=app123",
								},
							],
							cookies: [],
							queryString: [],
						},
						response: {
							headers: [],
							cookies: [],
							content: { mimeType: "application/json" },
						},
					},
				],
			},
		});
		const info = getHarInfo(har);
		expect(info.inlineKvPairs).toContain("client_secret");
		expect(info.inlineKvPairs).toContain("client_id");
	});
});

describe("sanitize", () => {
	it("sanitizes inline key=value pairs with default scrub words", () => {
		const har = JSON.stringify({
			log: {
				entries: [
					{
						request: {
							headers: [
								{
									name: "X-Custom-Auth",
									value: "client_secret=mysupersecret&client_id=app123",
								},
							],
							cookies: [],
							queryString: [],
						},
						response: {
							headers: [],
							cookies: [],
							content: { mimeType: "application/json" },
						},
					},
				],
			},
		});

		const result = sanitize(har, {
			scrubWords: ["client_secret", "client_id"],
		});

		expect(result).toContain("[client_secret redacted]");
		expect(result).toContain("[client_id redacted]");
		expect(result).not.toContain("mysupersecret");
		expect(result).not.toContain("app123");
	});

	it("uses defaultScrubItems when scrubWords is empty array", () => {
		const har = JSON.stringify({
			log: {
				entries: [
					{
						request: {
							headers: [{ name: "Authorization", value: "Bearer token123" }],
							cookies: [],
							queryString: [],
						},
						response: {
							headers: [],
							cookies: [],
							content: { mimeType: "application/json" },
						},
					},
				],
			},
		});

		const result = sanitize(har, { scrubWords: [] });
		expect(result).toContain("[Authorization redacted]");
	});
});
