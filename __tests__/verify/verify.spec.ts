/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import crypto from "crypto";
import { err } from "neverthrow";

import { verifySignatureHeader, createSignatureHeader, CreateSignatureHeaderOptions } from "../../src";
import * as common from "../../src/common";
import { unwrap } from "../../src/errors";
import { createSignatureHeaderOptions } from "../__fixtures__/createSignatureHeaderOptions";
import { signECDSA, verifyECDSA } from "../../src/common/cryptoPrimatives";

describe("verifySignatureHeader", () => {
  Date.now = jest.fn(() => 1577836800); //01.01.2020

  let createSignatureResult: { digest?: string; signature: string; signatureInput: string };
  let createSignatureResultTwo: { digest?: string; signature: string; signatureInput: string };
  let ecdsaKeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };
  let ecdsaKeyPairTwo: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };
  let keyMap: { [keyid: string]: crypto.KeyObject };

  beforeEach(async () => {
    ecdsaKeyPair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const createOptions: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: signECDSA(ecdsaKeyPair.privateKey) },
      expires: 10000000000,
      nonce: "abcd",
      context: "application specific context",
    };
    await createSignatureHeader(createOptions).then((res) => {
      expect(res.isOk()).toBe(true);
      res.isOk() ? (createSignatureResult = res.value) : undefined;
    });

    ecdsaKeyPairTwo = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const createOptionsTwo: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        Signature: createSignatureResult.signature,
        ["Signature-Input"]: createSignatureResult.signatureInput,
      },
      signer: { keyid: "key2", sign: signECDSA(ecdsaKeyPairTwo.privateKey) },
    };
    await createSignatureHeader(createOptionsTwo).then((res) => {
      expect(res.isOk()).toBe(true);
      res.isOk() ? (createSignatureResultTwo = res.value) : undefined;
    });

    keyMap = { key1: ecdsaKeyPair.publicKey, key2: ecdsaKeyPairTwo.publicKey };
  });

  it("Should verify a valid signature", async () => {
    const validHttpHeaderInput = {
      Signature: createSignatureResult.signature,
      "Signature-Input": createSignatureResult.signatureInput,
      "Content-Digest": createSignatureResult.digest,
    };
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        ...validHttpHeaderInput,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      body: createSignatureHeaderOptions.body,
      verifier: { verify: verifyECDSA(keyMap) },
    });

    expect(unwrap(result)).toEqual(true);

    const lowerCaseValidHttpHeaderInput = common.reduceKeysToLowerCase(validHttpHeaderInput);
    const resultWithLowerCaseHeader = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        ...lowerCaseValidHttpHeaderInput,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      body: createSignatureHeaderOptions.body,
      verifier: { verify: verifyECDSA(keyMap) },
    });

    expect(unwrap(resultWithLowerCaseHeader)).toEqual(true);
  });

  it("Should verify just one signature when a specific key is given", async () => {
    const validHttpHeaderInput = {
      Signature: createSignatureResultTwo.signature,
      "Signature-Input": createSignatureResultTwo.signatureInput,
      "Content-Digest": createSignatureResultTwo.digest,
    };
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        ...validHttpHeaderInput,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      body: createSignatureHeaderOptions.body,
      verifier: { verify: verifyECDSA({ key2: keyMap.key2 }) },
      signatureKey: "sig2",
    });

    expect(unwrap(result)).toEqual(true);
  });

  it("Should return verified false when a key is specified but not present in the signature", async () => {
    const validHttpHeaderInput = {
      Signature: createSignatureResultTwo.signature,
      "Signature-Input": createSignatureResultTwo.signatureInput,
      "Content-Digest": createSignatureResultTwo.digest,
    };
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        ...validHttpHeaderInput,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      body: createSignatureHeaderOptions.body,
      verifier: { verify: verifyECDSA({ key2: keyMap.key2 }) },
      signatureKey: "abcdefg",
    });

    expect(unwrap(result)).toEqual(false);
  });

  it("Should verify multiple valid signatures", async () => {
    const validHttpHeaderInput = {
      Signature: createSignatureResultTwo.signature,
      "Signature-Input": createSignatureResultTwo.signatureInput,
      "Content-Digest": createSignatureResultTwo.digest,
    };
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        ...validHttpHeaderInput,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      body: createSignatureHeaderOptions.body,
      verifier: { verify: verifyECDSA(keyMap) },
    });

    expect(unwrap(result)).toEqual(true);
  });

  it("Should verify signatures that are signed over other signatures", async () => {
    const signatureOverAnotherSignatureOptions: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        Signature: createSignatureResult.signature,
        ["Signature-Input"]: createSignatureResult.signatureInput,
      },
      signer: { keyid: "key2", sign: signECDSA(ecdsaKeyPairTwo.privateKey) },
      existingSignatureKey: "sig1",
    };

    const signatureOverAnotherSignatureResult = await createSignatureHeader(signatureOverAnotherSignatureOptions);

    if (signatureOverAnotherSignatureResult.isErr()) {
      throw signatureOverAnotherSignatureResult.error;
    }

    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        Signature: signatureOverAnotherSignatureResult.value.signature,
        "Signature-Input": signatureOverAnotherSignatureResult.value.signatureInput,
        "Content-Digest": signatureOverAnotherSignatureResult.value.digest,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      body: createSignatureHeaderOptions.body,
      verifier: { verify: verifyECDSA(keyMap) },
    });

    expect(unwrap(result)).toEqual(true);
  });

  it("Should return verified false when verifying a tampered signature", async () => {
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        "Content-Digest": `${createSignatureResult.digest}`,
        Signature: createSignatureResult.signature,
        "Signature-Input": createSignatureResult.signatureInput,
      },
      method: "PUT",
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyECDSA(keyMap) },
      body: createSignatureHeaderOptions.body,
    });

    expect(unwrap(result)).toEqual(false);
  });

  it("Should ignore headers not included in a signature string headers", async () => {
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        "Content-Digest": `${createSignatureResult.digest}`,
        extraHeader: "value",
        Signature: createSignatureResult.signature,
        "Signature-Input": createSignatureResult.signatureInput,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyECDSA(keyMap) },
      body: createSignatureHeaderOptions.body,
    });

    expect(unwrap(result)).toEqual(true);
  });

  it("Should return verified false if headers to verify do not match headers defined in the signature string", async () => {
    const result = await verifySignatureHeader({
      httpHeaders: {
        randomHeader: "value",
        Signature: createSignatureResult.signature,
        "Signature-Input": createSignatureResult.signatureInput,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyECDSA(keyMap) },
      body: createSignatureHeaderOptions.body,
    });

    expect(unwrap(result)).toEqual(false);
  });

  it("Should return verified false if signature header is not a string", async () => {
    const result = await verifySignatureHeader({
      httpHeaders: {},
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyECDSA(keyMap) },
    });

    expect(unwrap(result)).toEqual(false);
  });

  test.each([
    [
      "@request-target",
      `sig1=("content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1`,
    ],
    [
      "content-type",
      `sig1=("@request-target" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1`,
    ],
    [
      "host",
      `sig1=("@request-target" "content-type" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1`,
    ],
    [
      "method",
      `sig1=("@request-target" "content-type" "host" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1`,
    ],
    ["alg", `sig1=("@request-target" "content-type" "host" "@method");keyid="key1";created=1`],
    [
      "keyid",
      `sig1=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";created=1`,
    ],
    [
      "created",
      `sig1=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1"`,
    ],
  ])(
    "Should return verified false when signature-input header value is missing %s field",
    async (missing, headerValue) => {
      const result = await verifySignatureHeader({
        httpHeaders: {
          ...createSignatureHeaderOptions.httpHeaders,
          "Content-Digest": `${createSignatureResult.digest}`,
          Signature: createSignatureResult.signature,
          "Signature-Input": headerValue,
        },
        method: createSignatureHeaderOptions.method,
        url: createSignatureHeaderOptions.url,
        verifier: { verify: verifyECDSA(keyMap) },
        body: createSignatureHeaderOptions.body,
      });
      expect(result).toMatchObject({ value: false });
    }
  );

  it("Should return verified false if an err is returned from decoding", async () => {
    const mockDecode = jest.spyOn(common, "decodeBase64");
    mockDecode.mockImplementationOnce(() => {
      return err("Failed to decode base64 bytes");
    });

    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        "Content-Digest": createSignatureResult.digest,
        "Signature-Input": createSignatureResult.signatureInput,
        Signature: createSignatureResult.signature,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyECDSA(keyMap) },
      body: createSignatureHeaderOptions.body,
    });

    expect(unwrap(result)).toEqual(false);
  });

  it("Should return verified false if included http headers contain duplicate case insensitive headers", async () => {
    // NOTE: We don't return verified result error messages so cannot confirm exact place of failure just that it returned false
    // We could achieve this by creating and running expects on spys surrounding the expected failure point
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        "Content-Digest": createSignatureResult.digest,
        "content-digest": createSignatureResult.digest,
        "Signature-Input": createSignatureResult.signatureInput,
        Signature: createSignatureResult.signature,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyECDSA(keyMap) },
      body: createSignatureHeaderOptions.body,
    });

    expect(unwrap(result)).toEqual(false);
  });

  it("Should return verified false if the body has been tampered", async () => {
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        "Content-Digest": createSignatureResult.digest,
        "Signature-Input": createSignatureResult.signatureInput,
        Signature: createSignatureResult.signature,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyECDSA(keyMap) },
      body: { tampered: "body" },
    });

    expect(unwrap(result)).toEqual(false);
  });

  it("Should return verified false if the body is undefined but the content-digest header is not", async () => {
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        "Content-Digest": createSignatureResult.digest,
        "Signature-Input": createSignatureResult.signatureInput,
        Signature: createSignatureResult.signature,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyECDSA(keyMap) },
    });

    expect(unwrap(result)).toEqual(false);
  });

  it("Should return verified false if the content-digest header is a string array", async () => {
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        "Content-Digest": ["string", "array"],
        "Signature-Input": createSignatureResult.signatureInput,
        Signature: createSignatureResult.signature,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyECDSA(keyMap) },
      body: createSignatureHeaderOptions.body,
    });

    expect(unwrap(result)).toEqual(false);
  });

  it("Should return verified false if the expiry date has passed", async () => {
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        "Content-Digest": createSignatureResult.digest,
        "Signature-Input": createSignatureResult.signatureInput.replace(/(expires=)[\d]+;/, "expires=1;"),
        Signature: createSignatureResult.signature,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyECDSA(keyMap) },
      body: createSignatureHeaderOptions.body,
    });

    expect(unwrap(result)).toEqual(false);
  });

  it("Should return a handled error if an error is thrown in the verify function", async () => {
    const error = Error("unexpected error");
    const badVerify = (): Promise<boolean> => Promise.reject(error);
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        Signature: createSignatureResult.signature,
        "Content-Digest": createSignatureResult.digest,
        "Signature-Input": createSignatureResult.signatureInput,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: badVerify },
      body: createSignatureHeaderOptions.body,
    });

    if (result.isOk()) {
      throw "result is not an error";
    }

    expect(result.error).toEqual({
      type: "VerifyFailed",
      message: "Failed to verify signature header",
    });
  });

  it("Should return a handled error if an unexpected error is thrown in the verify function", async () => {
    const error = Error("unexpected error");
    const badVerify = (): Promise<boolean> => {
      throw error;
    };
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        "Content-Digest": `${createSignatureResult.digest}`,
        Signature: createSignatureResult.signature,
        "Signature-Input": createSignatureResult.signatureInput,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: badVerify },
      body: createSignatureHeaderOptions.body,
    });

    if (result.isOk()) {
      throw "result is not an error";
    }

    expect(result.error).toEqual({
      type: "VerifyFailed",
      message: "An error occurred when verifying signature header",
    });
  });
});
