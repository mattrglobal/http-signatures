/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import { generateKeyPairFromSeed, sign } from "@stablelib/ed25519";

import { createSignatureHeader, CreateSignatureHeaderOptions } from "../../src/sign";
import { createSignatureHeaderOptions } from "../__fixtures__/createSignatureHeaderOptions";

describe("createSignatureHeader", () => {
  const mockSign = jest.fn((_data) => Promise.resolve(Uint8Array.from([1])));
  Date.now = jest.fn(() => 1577836800); //01.01.2020

  beforeEach(() => {
    mockSign.mockClear();
  });

  it("Should create a signature and a digest", async () => {
    const seed = generateKeyPairFromSeed(new Uint8Array(32));
    const signEd25519 = async (data: Uint8Array): Promise<Uint8Array> => await sign(seed.secretKey, data);
    const options: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyId: "key1", sign: signEd25519 },
    };

    await expect(createSignatureHeader(options)).resolves.toMatchObject({
      digest: "SHA-256=wnRdPgQ+BTyxU5jDYMTAg3GXadmb7etzdN5ymvsJ8WQ=",
      signature:
        'keyId="key1",algorithm="hs2019",created=1577837,headers="(request-target) (created) host digest content-type x-custom-header",signature="94JK8kKRfuiJ31cRgqIqGoQaDwhaci_4Nzrj5P4WqzoS3z5UNXLpvDu5Glh2FicR4RTZ0PR4EoUkmDwSHjGSAw=="',
    });
  });

  it("Should handle a string body", async () => {
    const options = {
      ...createSignatureHeaderOptions,
      body: "string body",
      signer: { keyId: "key1", sign: mockSign },
    };

    await expect(createSignatureHeader(options)).resolves.toMatchObject({
      digest: "SHA-256=qoxd+emcQclK6Mp84PxOeUumOdjbx+mSW/pxhEXlcno=",
      signature:
        'keyId="key1",algorithm="hs2019",created=1577837,headers="(request-target) (created) host digest content-type x-custom-header",signature="AQ=="',
    });
    expect(mockSign).toHaveBeenCalledTimes(1);
  });

  it("Should reject if a body is defined and content type is not", async () => {
    const options = {
      ...createSignatureHeaderOptions,
      headers: {},
      signer: { keyId: "key1", sign: mockSign },
    };

    await expect(createSignatureHeader(options)).rejects.toMatchObject(
      Error("content-type header must be defined if a body is defined")
    );
    expect(mockSign).toHaveBeenCalledTimes(0);
  });
});
