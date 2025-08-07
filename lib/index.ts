import crypto from "node:crypto";

/**
 * Create base64-encoded HMAC SHA-256 hash.
 * This hash is a security mechanism used when a cognito client is configured with a client secret.
 */

export default async (
  username: string,
  clientId: string,
  clientSecret: string
): Promise<string> => {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(clientSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${username}${clientId}`)
  );
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
};
