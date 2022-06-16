/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import { generateKeyPairFromSeed, sign } from "@stablelib/ed25519";

import { createSignatureHeader, CreateSignatureHeaderOptions } from "../../src/sign";
import { createSignatureHeaderOptions } from "../__fixtures__/createSignatureHeaderOptions";

describe("createSignatureHeader", () => {
  Date.now = jest.fn(() => 1577836800); //01.01.2020

  it("Should create a signature and a digest", async () => {
    const seed = generateKeyPairFromSeed(new Uint8Array(32));
    const signEd25519 = async (data: Uint8Array): Promise<Uint8Array> => await sign(seed.secretKey, data);
    const options: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyId: "key1", sign: signEd25519 },
    };

    const result = await createSignatureHeader(options);

    if (result.isErr()) {
      throw result.error;
    }
    expect(result.value).toMatchObject({
      digest: "SHA-256=wnRdPgQ-BTyxU5jDYMTAg3GXadmb7etzdN5ymvsJ8WQ=",
      signature:
        'keyId="key1",algorithm="hs2019",created=1577837,headers="(created) (request-target) arrvalue content-type digest host undefinedvalue x-custom-header",signature="1rRYstzVwCxmTbuF-lzKRxR1V8eImf3lRdjFqv7olV9wxgkpQ4Z8w-B7YHDSl5Qk_NgrjLgZbhriQiiDetXzAA=="',
    });
  });

  it("Should create the same signature with different order http headers", async () => {
    const seed = generateKeyPairFromSeed(new Uint8Array(32));
    const signEd25519 = async (data: Uint8Array): Promise<Uint8Array> => await sign(seed.secretKey, data);
    const options1: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      body: undefined,
      httpHeaders: { three: "3", two: "two", one: "one" },
      signer: { keyId: "key1", sign: signEd25519 },
    };
    const options2: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      body: undefined,
      httpHeaders: { one: "one", two: "two", three: "3" },
      signer: { keyId: "key1", sign: signEd25519 },
    };

    const result1 = await createSignatureHeader(options1);
    const result2 = await createSignatureHeader(options2);

    if (result1.isErr() || result2.isErr()) {
      throw "result is an error";
    }

    expect(result1.value).toStrictEqual(result2.value);
  });

  it("Should handle a string body", async () => {
    const sign = (): Promise<Uint8Array> => Promise.resolve(Uint8Array.from([1]));
    const options = {
      ...createSignatureHeaderOptions,
      body: "string body",
      signer: { keyId: "key1", sign: sign },
    };

    const result = await createSignatureHeader(options);
    if (result.isErr()) {
      throw result.error;
    }

    expect(result.value).toMatchObject({
      digest: "SHA-256=qoxd-emcQclK6Mp84PxOeUumOdjbx-mSW_pxhEXlcno=",
      signature:
        'keyId="key1",algorithm="hs2019",created=1577837,headers="(created) (request-target) arrvalue content-type digest host undefinedvalue x-custom-header",signature="AQ=="',
    });
  });

  it("Should return an err if headers is empty", async () => {
    const result = await createSignatureHeader({
      ...createSignatureHeaderOptions,
      httpHeaders: {},
    });

    if (result.isOk()) {
      throw "result is not an error";
    }
    expect(result.error).toEqual({ type: "MalformedInput", message: "Http headers must not be empty" });
  });

  it("Should return an error if headers contains a duplicate case insensitive entry", async () => {
    const options = {
      ...createSignatureHeaderOptions,
      httpHeaders: { header1: "value", HEADER1: "value" },
    };

    const result = await createSignatureHeader(options);

    if (result.isOk()) {
      throw "result is not an error";
    }

    expect(result.error).toEqual({
      type: "MalformedInput",
      message: "Duplicate case insensitive header keys detected, specify an array of values instead",
    });
  });

  it("Should return an error if sign throws", async () => {
    const error = Error("unexpected error");
    const badSign = (): Promise<Uint8Array> => Promise.reject(error);
    const options = {
      ...createSignatureHeaderOptions,
      signer: { keyId: "key1", sign: badSign },
    };

    const result = await createSignatureHeader(options);

    if (result.isOk()) {
      throw "result is not an error";
    }

    await expect(result.error).toEqual({
      type: "SignFailed",
      message: "Failed to sign signature header",
    });
  });

  it("Should return a handled error if an unexpected error is thrown", async () => {
    const error = Error("Error");
    const badSign = (): Promise<Uint8Array> => {
      throw error;
    };

    const options = {
      ...createSignatureHeaderOptions,
      signer: { keyId: "key1", sign: badSign },
    };

    const result = await createSignatureHeader(options);

    if (result.isOk()) {
      throw "result is not an error";
    }

    expect(result.error).toEqual({
      type: "SignFailed",
      message: "An error occurred when signing signature header",
    });
  });
});
