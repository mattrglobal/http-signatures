/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import crypto from "crypto";

import { createSignatureHeader, CreateSignatureHeaderOptions } from "../../src/sign";
import { createSignatureHeaderOptions } from "../__fixtures__/createSignatureHeaderOptions";
import { signECDSA } from "../__fixtures__/cryptoPrimatives";

let ecdsaKeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };

describe("createSignatureHeader", () => {
  Date.now = jest.fn(() => 1577836800000);

  beforeEach(() => {
    ecdsaKeyPair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  });

  it("Should create a signature and a digest", async () => {
    const options: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: signECDSA(ecdsaKeyPair.privateKey) },
    };

    const result = await createSignatureHeader(options);

    if (result.isErr()) {
      throw result.error;
    }

    expect(result.value).toEqual({
      // we can't compare the signature directly as ECDSA is not deterministic
      signature: expect.stringMatching(/^sig1=*.*:$/),
      signatureInput:
        'sig1=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1577836800',
      digest: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
    });
  });

  it("Should accept an optional nonce and expiry", async () => {
    const options: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: signECDSA(ecdsaKeyPair.privateKey) },
      expires: 1577836801,
      nonce: "abcdefg",
    };

    const result = await createSignatureHeader(options);

    if (result.isErr()) {
      throw result.error;
    }

    expect(result.value).toEqual({
      // we can't compare the signature directly as ECDSA is not deterministic
      signature: expect.stringMatching(/^sig1=*.*:$/),
      signatureInput:
        'sig1=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1577836800;expires=1577836801;nonce="abcdefg"',
      digest: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
    });
  });

  it("Should use a custom signature ID if one was provided", async () => {
    const signatureId = "testsig123";
    const options: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: signECDSA(ecdsaKeyPair.privateKey) },
      signatureId,
    };

    const result = await createSignatureHeader(options);

    if (result.isErr()) {
      throw result.error;
    }

    expect(result.value).toEqual({
      // we can't compare the signature directly as ECDSA is not deterministic
      signature: expect.stringMatching(/^testsig123=*.*:$/),
      signatureInput:
        'testsig123=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1577836800',
      digest: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
    });
  });

  it("Should be able to create multiple signatures on the same message", async () => {
    const options: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: signECDSA(ecdsaKeyPair.privateKey) },
    };

    const result = await createSignatureHeader(options);

    if (result.isErr()) {
      throw result.error;
    }

    const createSecondSignatureHeaderOptions = {
      signer: { keyid: "key2", sign: signECDSA(ecdsaKeyPair.privateKey) },
      url: "http://example.com/foo?param=value&pet=dog",
      method: "POST",
      httpHeaders: {
        ["HOST"]: "example.com",
        ["Content-Type"]: "application/json",
        Signature: result.value.signature,
        "Signature-Input":
          'sig1=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1577836800',
        "Content-Digest": "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
      },
      body: `{"hello": "world"}`,
    };
    const optionsTwo: CreateSignatureHeaderOptions = {
      ...createSecondSignatureHeaderOptions,
    };

    const resultTwo = await createSignatureHeader(optionsTwo);

    if (resultTwo.isErr()) {
      throw resultTwo.error;
    }

    expect(resultTwo.value).toEqual({
      // we can't compare the signature directly as ECDSA is not deterministic
      signature: expect.stringMatching(/^sig1=*.*:, sig2=*.*:$/),
      signatureInput:
        'sig1=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1577836800, sig2=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key2";created=1577836800',
      digest: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
    });
  });

  it("Should sign over a previous signature if a signature id is provided", async () => {
    const createSecondSignatureHeaderOptions = {
      signer: { keyid: "key2", sign: signECDSA(ecdsaKeyPair.privateKey) },
      url: "http://example.com/foo?param=value&pet=dog",
      method: "POST",
      httpHeaders: {
        ["HOST"]: "example.com",
        ["Content-Type"]: "application/json",
        Signature: "sig1=abcde:",
        "Signature-Input":
          'sig1=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1577836800',
        "Content-Digest": "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
      },
      body: `{"hello": "world"}`,
      existingSignatureKey: "sig1",
    };
    const optionsTwo: CreateSignatureHeaderOptions = {
      ...createSecondSignatureHeaderOptions,
    };

    const resultTwo = await createSignatureHeader(optionsTwo);

    if (resultTwo.isErr()) {
      throw resultTwo.error;
    }

    expect(resultTwo.value).toEqual({
      // we can't compare the signature directly as ECDSA is not deterministic
      signature: expect.stringMatching(/^sig1=*.*:, sig2=*.*:$/),
      signatureInput:
        'sig1=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1577836800, sig2=("@request-target" "content-type" "host" "@method" "content-digest" "signature";key="sig1");alg="ecdsa-p256-sha256";keyid="key2";created=1577836800',
      digest: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
    });
  });

  it("Should handle a string body", async () => {
    const options = {
      ...createSignatureHeaderOptions,
      body: "string body",
      signer: { keyid: "key1", sign: signECDSA(ecdsaKeyPair.privateKey) },
    };

    const result = await createSignatureHeader(options);
    if (result.isErr()) {
      throw result.error;
    }

    expect(result.value).toMatchObject({
      digest: "sha-256=:qoxd-emcQclK6Mp84PxOeUumOdjbx-mSW_pxhEXlcno=:",
      signatureInput: `sig1=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1577836800`,
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

  it("Should return an error when expiry is in the past", async () => {
    const options: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: signECDSA(ecdsaKeyPair.privateKey) },
      expires: 1,
    };

    const result = await createSignatureHeader(options);

    if (result.isOk()) {
      throw "result is not an error";
    }

    await expect(result.error).toEqual({
      type: "SignFailed",
      message: "Expiry must not be in the past",
    });
  });

  it("Should return an error if sign throws", async () => {
    const error = Error("unexpected error");
    const badSign = (): Promise<Uint8Array> => Promise.reject(error);
    const options = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: badSign },
    };

    const result = await createSignatureHeader(options);

    if (result.isOk()) {
      throw "result is not an error";
    }

    await expect(result.error).toEqual({
      type: "SignFailed",
      message: "unexpected error",
    });
  });

  it("Should return a handled error if an unexpected error is thrown", async () => {
    const error = Error("Error");
    const badSign = (): Promise<Uint8Array> => {
      throw error;
    };

    const options = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: badSign },
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
