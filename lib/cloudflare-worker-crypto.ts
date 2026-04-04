// lib/cloudflare-worker-crypto.ts
// Native Web Crypto API implementation for Agent Auth Protocol
// Optimized for Cloudflare Workers (zero external crypto dependencies)

/**
 * Base64URL encoding/decoding utilities
 */
function base64urlEncode(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlDecode(base64url: string): Uint8Array {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (base64.length % 4)) % 4;
  const padded = base64 + "=".repeat(padLen);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

const textEncoder = new TextEncoder();

/**
 * Generates an Ed25519 keypair and exports it as JWKs.
 */
export async function generateEd25519Keypair(): Promise<{
  publicKey: JsonWebKey;
  privateKey: JsonWebKey;
}> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "Ed25519",
    },
    true,
    ["sign", "verify"]
  );

  const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

  return {
    publicKey: publicKeyJwk,
    privateKey: privateKeyJwk,
  };
}

/**
 * Calculates the JWK Thumbprint (RFC 7638) using SHA-256.
 * This is used for the `iss` claim representing the host identity.
 */
export async function calculateJwkThumbprint(jwk: JsonWebKey): Promise<string> {
  // Required fields for Ed25519 thumbprint in lexicographic order
  const canonicalJwk = {
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
  };

  const jsonString = JSON.stringify(canonicalJwk);
  const digest = await crypto.subtle.digest("SHA-256", textEncoder.encode(jsonString));

  return base64urlEncode(digest);
}

/**
 * Signs a payload to create a JWT using Ed25519.
 */
export async function signJWT(
  header: Record<string, any>,
  payload: Record<string, any>,
  privateKeyJwk: JsonWebKey
): Promise<string> {
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    privateKeyJwk,
    { name: "Ed25519" },
    false,
    ["sign"]
  );

  const encodedHeader = base64urlEncode(textEncoder.encode(JSON.stringify(header)));
  const encodedPayload = base64urlEncode(textEncoder.encode(JSON.stringify(payload)));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signatureBuffer = await crypto.subtle.sign(
    { name: "Ed25519" },
    privateKey,
    textEncoder.encode(signingInput)
  );

  const encodedSignature = base64urlEncode(signatureBuffer);

  return `${signingInput}.${encodedSignature}`;
}

/**
 * Verifies an Ed25519 JWT.
 */
export async function verifyJWT(
  jwt: string,
  publicKeyJwk: JsonWebKey
): Promise<{ header: any; payload: any; valid: boolean }> {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    publicKeyJwk,
    { name: "Ed25519" },
    false,
    ["verify"]
  );

  const signatureBytes = base64urlDecode(encodedSignature);

  const valid = await crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    signatureBytes as BufferSource,
    textEncoder.encode(signingInput)
  );

  if (!valid) {
    throw new Error("Invalid signature");
  }

  const header = JSON.parse(new TextDecoder().decode(base64urlDecode(encodedHeader)));
  const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(encodedPayload)));

  return { header, payload, valid };
}

/**
 * Creates a Host JWT for Agent Auth registration.
 */
export async function createHostJWT(
  hostPrivateKeyJwk: JsonWebKey,
  hostPublicKeyJwk: JsonWebKey,
  audience: string,
  agentPublicKeyJwk?: JsonWebKey,
  expiresInSeconds = 60
): Promise<string> {
  const thumbprint = await calculateJwkThumbprint(hostPublicKeyJwk);
  const now = Math.floor(Date.now() / 1000);

  const header = {
    alg: "EdDSA",
    typ: "host+jwt",
  };

  const payload: any = {
    iss: thumbprint,
    sub: thumbprint,
    aud: audience,
    iat: now,
    exp: now + expiresInSeconds,
    jti: `h-${crypto.randomUUID()}`,
    host_public_key: hostPublicKeyJwk,
  };

  if (agentPublicKeyJwk) {
    payload.agent_public_key = agentPublicKeyJwk;
  }

  return signJWT(header, payload, hostPrivateKeyJwk);
}

/**
 * Creates an Agent JWT for Agent Auth execution.
 */
export async function createAgentJWT(
  agentPrivateKeyJwk: JsonWebKey,
  hostThumbprint: string,
  agentId: string,
  audience: string,
  capabilities?: string[],
  expiresInSeconds = 60
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  const header = {
    alg: "EdDSA",
    typ: "agent+jwt",
  };

  const payload: any = {
    iss: hostThumbprint,
    sub: agentId,
    aud: audience,
    iat: now,
    exp: now + expiresInSeconds,
    jti: `a-${crypto.randomUUID()}`,
  };

  if (capabilities && capabilities.length > 0) {
    payload.capabilities = capabilities;
  }

  return signJWT(header, payload, agentPrivateKeyJwk);
}
