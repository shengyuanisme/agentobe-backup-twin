import { createServer, type Server } from "node:http";
import {
  SignJWT,
  exportJWK,
  generateKeyPair,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { OidcAccessTokenVerifier } from "./auth.js";

const ISSUER = "https://identity.partner.example/";
const AUDIENCE = "agentobe-api";

describe("OIDC access token verification", () => {
  let server: Server;
  let verifier: OidcAccessTokenVerifier;
  let privateKey: Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];

  beforeAll(async () => {
    const pair = await generateKeyPair("RS256", { extractable: true });
    privateKey = pair.privateKey;
    const publicJwk = await exportJWK(pair.publicKey);
    const jwks = JSON.stringify({ keys: [{ ...publicJwk, kid: "partner-key-1", alg: "RS256", use: "sig" }] });
    server = createServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json", "cache-control": "max-age=60" });
      response.end(jwks);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("JWKS test server failed to bind.");
    verifier = await OidcAccessTokenVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: `http://127.0.0.1:${address.port}/jwks`,
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  });

  async function sign(overrides: { issuer?: string; audience?: string; expiresAt?: number } = {}) {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ email: "partner@example.test", name: "Partner Operator" })
      .setProtectedHeader({ alg: "RS256", kid: "partner-key-1" })
      .setIssuer(overrides.issuer ?? ISSUER)
      .setSubject("partner-operator-42")
      .setAudience(overrides.audience ?? AUDIENCE)
      .setIssuedAt(now)
      .setExpirationTime(overrides.expiresAt ?? now + 300)
      .sign(privateKey);
  }

  it("accepts a correctly signed access token and preserves the exact issuer", async () => {
    await expect(verifier.verify(await sign())).resolves.toEqual({
      issuer: ISSUER,
      subject: "partner-operator-42",
      email: "partner@example.test",
      displayName: "Partner Operator",
    });
  });

  it("rejects the wrong issuer, audience, and expired tokens", async () => {
    const now = Math.floor(Date.now() / 1000);
    await expect(verifier.verify(await sign({ issuer: "https://attacker.example/" }))).rejects.toMatchObject({
      statusCode: 401,
      code: "ACCESS_TOKEN_INVALID",
    });
    await expect(verifier.verify(await sign({ audience: "another-api" }))).rejects.toMatchObject({
      statusCode: 401,
      code: "ACCESS_TOKEN_INVALID",
    });
    await expect(verifier.verify(await sign({ expiresAt: now - 60 }))).rejects.toMatchObject({
      statusCode: 401,
      code: "ACCESS_TOKEN_INVALID",
    });
  });
});
