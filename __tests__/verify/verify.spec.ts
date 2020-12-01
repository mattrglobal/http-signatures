/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import { generateKeyPairFromSeed, KeyPair, sign, verify } from "@stablelib/ed25519";

import { verifySignatureHeader, createSignatureHeader, CreateSignatureHeaderOptions } from "../../src";
import { createSignatureHeaderOptions } from "../__fixtures__/createSignatureHeaderOptions";

describe("createSignatureHeader", () => {
  Date.now = jest.fn(() => 1577836800); //01.01.2020

  const verifyEd25519 = (publicKey: Uint8Array) => async (
    keyId: string,
    data: Uint8Array,
    signature: Uint8Array
  ): Promise<boolean> => await verify(publicKey, data, signature);

  let createSignatureResult: { digest?: string; signature: string };
  let keyPair: KeyPair;

  beforeEach(async () => {
    keyPair = generateKeyPairFromSeed(new Uint8Array(32));
    const signEd25519 = async (data: Uint8Array): Promise<Uint8Array> => await sign(keyPair.secretKey, data);
    const createOptions: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyId: "key1", sign: signEd25519 },
    };
    createSignatureResult = await createSignatureHeader(createOptions);
  });

  it("Should verify a signature", async () => {
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        Digest: `${createSignatureResult.digest}`,
        Signature: createSignatureResult.signature,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyEd25519(keyPair.publicKey) },
    });

    expect(result).toBe(true);
  });

  it("Should resolve to false when verifying a tampered signature", async () => {
    await expect(
      verifySignatureHeader({
        httpHeaders: {
          ...createSignatureHeaderOptions.httpHeaders,
          Digest: `${createSignatureResult.digest}`,
          Signature: createSignatureResult.signature,
        },
        method: "PUT",
        url: createSignatureHeaderOptions.url,
        verifier: { verify: verifyEd25519(keyPair.publicKey) },
      })
    ).resolves.toBe(false);
  });

  it("Should ignore headers not included in a signature string headers", async () => {
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        Digest: `${createSignatureResult.digest}`,
        extraHeader: "value",
        Signature: createSignatureResult.signature,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyEd25519(keyPair.publicKey) },
    });

    expect(result).toBe(true);
  });

  it("Should reject if headers to verify do not match headers defined in the signature string", async () => {
    await expect(
      verifySignatureHeader({
        httpHeaders: {
          randomHeader: "value",
          Signature: createSignatureResult.signature,
        },
        method: createSignatureHeaderOptions.method,
        url: createSignatureHeaderOptions.url,
        verifier: { verify: verifyEd25519(keyPair.publicKey) },
      })
    ).rejects.toMatchObject(Error("signature headers string mismatch"));
  });

  it("Should reject if signature header is not a string", async () => {
    await expect(
      verifySignatureHeader({
        httpHeaders: {},
        method: createSignatureHeaderOptions.method,
        url: createSignatureHeaderOptions.url,
        verifier: { verify: verifyEd25519(keyPair.publicKey) },
      })
    ).rejects.toMatchObject(Error("bad signature header - signature header must be a string"));
  });

  test.each([
    ["keyId", `created=1,headers="",signature=""`],
    ["signature", `created=1,headers="",keyId=""`],
    ["created", `signature="",headers="",keyId=""`],
    ["headers", `signature="",created=1,keyId=""`],
  ])("Should reject when signature header value is missing %s field", async (missing, headerValue) => {
    await expect(
      verifySignatureHeader({
        httpHeaders: {
          ...createSignatureHeaderOptions.httpHeaders,
          Signature: headerValue,
        },
        method: createSignatureHeaderOptions.method,
        url: createSignatureHeaderOptions.url,
        verifier: { verify: verifyEd25519(keyPair.publicKey) },
      })
    ).rejects.toMatchObject(Error("signature string is missing a required field"));
  });
});
