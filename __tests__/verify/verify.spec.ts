/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import * as base64 from "@stablelib/base64";
import crypto from "crypto";

import { verifySignatureHeader, createSignatureHeader, CreateSignatureHeaderOptions } from "../../src";
import { reduceKeysToLowerCase } from "../../src/common";
import { createSignatureHeaderOptions } from "../__fixtures__/createSignatureHeaderOptions";

describe("verifySignatureHeader", () => {
  Date.now = jest.fn(() => 1577836800); //01.01.2020

  const signECDSA =
    (privateKey: crypto.KeyObject) =>
    async (data: Uint8Array): Promise<Uint8Array> => {
      return crypto.createSign("sha256").update(data).sign({ key: privateKey, dsaEncoding: "ieee-p1363" });
    };

  const verifyECDSA =
    (publicKey: crypto.KeyObject) =>
    async (keyid: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> => {
      return await crypto
        .createVerify("SHA256")
        .update(data)
        .verify({ key: publicKey, dsaEncoding: "ieee-p1363" }, signature);
    };

  let createSignatureResult: { digest?: string; signature: string; signatureInput: string };
  let ecdsaKeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };

  beforeEach(async () => {
    ecdsaKeyPair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const createOptions: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: signECDSA(ecdsaKeyPair.privateKey) },
    };
    await createSignatureHeader(createOptions).then((res) => {
      expect(res.isOk()).toBe(true);
      res.isOk() ? (createSignatureResult = res.value) : undefined;
    });
  });

  it("Should verify a valid signature", async () => {
    const validHttpHeaderInput = {
      "Content-Digest": createSignatureResult.digest,
      Signature: createSignatureResult.signature,
      "Signature-Input": createSignatureResult.signatureInput,
    };
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        ...validHttpHeaderInput,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyECDSA(ecdsaKeyPair.publicKey) },
    });
    expect(result.isOk()).toBe(true);

    const lowerCaseValidHttpHeaderInput = reduceKeysToLowerCase(validHttpHeaderInput);
    const resultWithLowerCaseHeader = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        ...lowerCaseValidHttpHeaderInput,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyECDSA(ecdsaKeyPair.publicKey) },
    });
    expect(resultWithLowerCaseHeader.isOk()).toBe(true);
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
      verifier: { verify: verifyECDSA(ecdsaKeyPair.publicKey) },
      body: createSignatureHeaderOptions.body,
    });

    if (result.isErr()) {
      throw "result is an error";
    }

    expect(result.value).toEqual(false);
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
      verifier: { verify: verifyECDSA(ecdsaKeyPair.publicKey) },
      body: createSignatureHeaderOptions.body,
    });

    expect(result.isOk()).toBe(true);
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
      verifier: { verify: verifyECDSA(ecdsaKeyPair.publicKey) },
      body: createSignatureHeaderOptions.body,
    });

    if (result.isErr()) {
      throw "result is an error";
    }

    expect(result.value).toEqual(false);
  });

  it("Should return verified false if signature header is not a string", async () => {
    const result = await verifySignatureHeader({
      httpHeaders: {},
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyECDSA(ecdsaKeyPair.publicKey) },
    });

    if (result.isErr()) {
      throw "result is an error";
    }

    expect(result.value).toEqual(false);
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
        verifier: { verify: verifyECDSA(ecdsaKeyPair.publicKey) },
        body: createSignatureHeaderOptions.body,
      });
      expect(result).toMatchObject({ value: false });
    }
  );

  it("Should return verified false if an err is returned from decoding", async () => {
    const mockDecode = jest.spyOn(base64, "decodeURLSafe");
    const errorString = "error decoding";
    mockDecode.mockImplementationOnce(() => {
      throw Error(errorString);
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
      verifier: { verify: verifyECDSA(ecdsaKeyPair.publicKey) },
      body: createSignatureHeaderOptions.body,
    });

    if (result.isErr()) {
      throw "result is an error";
    }

    expect(result.value).toEqual(false);
  });

  it("Should return verified false if included http headers contain duplicate case insensitive headers", async () => {
    // NOTE: We don't return verified result error messages so cannot confirm exact place of failure just that it returned false
    // We could achieve this by creating and running expects on spys surrounding the expected failure point
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        Digest: `${createSignatureResult.digest}`,
        digest: `${createSignatureResult.digest}`,
        Signature: createSignatureResult.signature,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyECDSA(ecdsaKeyPair.publicKey) },
      body: createSignatureHeaderOptions.body,
    });

    if (result.isErr()) {
      throw "result is an error";
    }
    expect(result.value).toEqual(false);
  });

  it("Should return a verified false if the body has been tampered", async () => {
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        "Content-Digest": createSignatureResult.digest,
        "Signature-Input": createSignatureResult.signatureInput,
        Signature: createSignatureResult.signature,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyECDSA(ecdsaKeyPair.publicKey) },
      body: { tampered: "body" },
    });

    if (result.isErr()) {
      throw "result is an error";
    }
    expect(result.value).toEqual(false);
  });

  it("Should return a verified false if the body is undefined but the content-digest header is not", async () => {
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        "Content-Digest": createSignatureResult.digest,
        "Signature-Input": createSignatureResult.signatureInput,
        Signature: createSignatureResult.signature,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyECDSA(ecdsaKeyPair.publicKey) },
    });

    if (result.isErr()) {
      throw "result is an error";
    }
    expect(result.value).toEqual(false);
  });

  it("Should return a verified false if the digest header is a string array", async () => {
    const result = await verifySignatureHeader({
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        "Content-Digest": createSignatureResult.digest,
        "Signature-Input": createSignatureResult.signatureInput,
        Signature: createSignatureResult.signature,
      },
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyECDSA(ecdsaKeyPair.publicKey) },
      body: createSignatureHeaderOptions.body,
    });

    if (result.isErr()) {
      throw "result is an error";
    }
    expect(result.value).toEqual(false);
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
