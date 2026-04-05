# Implementing Agent Auth Protocol on Cloudflare Workers

This guide explains how to implement the Agent Auth Protocol using standard Web APIs, specifically optimized for Cloudflare Workers.

Cloudflare Workers do not support Node.js specific libraries like `crypto` by default in the same way, but they do have excellent support for the native `Web Crypto API` (`crypto.subtle`). This document outlines how to use the Web Crypto API to fulfill the core cryptographic requirements of the Agent Auth Protocol.

## Architecture Overview

To act as an Agent Auth Provider, your server must handle:
1. **Discovery:** Serving a static `/.well-known/agent-configuration` JSON file.
2. **Registration:** Handling `POST /agent/register` to establish trust with an agent's public key.
3. **Execution/Capabilities:** Verifying short-lived Agent JWTs on your protected endpoints.

The heaviest cryptographic lifting is in the **JWT verification** and **thumbprint calculation** steps.

## Core Cryptographic Primitives via Web Crypto

### 1. Generating Ed25519 Keypairs
The Agent Auth Protocol explicitly specifies `Ed25519` for keys.

```typescript
const keyPair = await crypto.subtle.generateKey(
  { name: "Ed25519" },
  true,
  ["sign", "verify"]
);

const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
```

### 2. Calculating JWK Thumbprints
The Host's identity (`iss` claim) is the SHA-256 thumbprint of its public key, per RFC 7638.

```typescript
async function calculateJwkThumbprint(jwk: JsonWebKey): Promise<string> {
  const canonicalJwk = {
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
  };

  const textEncoder = new TextEncoder();
  const jsonString = JSON.stringify(canonicalJwk);
  const digest = await crypto.subtle.digest("SHA-256", textEncoder.encode(jsonString));

  return base64urlEncode(digest); // Base64URL encode the raw bytes
}
```

### 3. Verifying Agent JWTs
When an agent calls your protected API, it sends a JWT signed with its private key. Your server must verify this signature using the agent's stored public key.

```typescript
async function verifyAgentJWT(jwt: string, storedPublicKeyJwk: JsonWebKey) {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT");

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  // Import the stored JWK
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    storedPublicKeyJwk,
    { name: "Ed25519" },
    false,
    ["verify"]
  );

  // Decode the signature and verify
  const signatureBytes = base64urlDecode(encodedSignature);
  const textEncoder = new TextEncoder();

  const isValid = await crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    signatureBytes as BufferSource,
    textEncoder.encode(signingInput)
  );

  if (!isValid) throw new Error("Invalid Agent Signature");

  // Parse payload and check exp, aud, etc.
  const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(encodedPayload)));
  return payload;
}
```

## Bridging to Your Existing System

If you are integrating this into an existing gateway or server that already issues custom JWTs or API keys for human users:

1. **The Registration Endpoint:** When an agent hits `POST /agent/register`, extract the `agent_public_key` from the Host JWT. Store this public key in your database associated with the newly generated `agent_id`.
2. **The Execution Gateway:**
   - intercept the `Authorization: Bearer <agent_jwt>` header.
   - Extract the `sub` claim (the `agent_id`).
   - Fetch the associated `agent_public_key` from your database.
   - Use `crypto.subtle.verify` (as shown above) to validate the token.
   - Ensure the `aud` claim matches your endpoint, and the `exp` claim is still in the future.
3. **Passing Context:** Once the Agent JWT is verified, your gateway knows *which agent* is making the call and *which human user* (if any) approved it. You can securely pass this context down to your backend services.

## Base64URL Utility Helpers
Because Web Crypto operates on raw buffers, you will need `base64url` encoding and decoding. On Cloudflare Workers, you can use the native `atob` and `btoa` functions, adapting them for URL safety:

```typescript
function base64urlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(base64url: string): Uint8Array {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
```

By leveraging these native Web APIs, your Agent Auth implementation will be highly performant, secure, and fully compatible with the Cloudflare Workers runtime, without requiring massive polyfills or heavy NPM cryptographic dependencies.