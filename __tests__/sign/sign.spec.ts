/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import crypto from "crypto";

import http from "http";
import { unwrap } from "../../src/errors";
import { createSignatureHeader, CreateSignatureHeaderOptions, signRequest, AlgorithmTypes } from "../../src/sign";
import { createSignatureHeaderOptions } from "../__fixtures__/createSignatureHeaderOptions";
import { signECDSA } from "../../src/sign/cryptoPrimatives";

let ecdsaKeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };
let ecdsaKeyPairTwo: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };

describe("signRequest", () => {
  let server: http.Server;
  let path: string;

  beforeEach(() => {
    server = http.createServer(function (req, res) {
      res.writeHead(200);
      res.end();
    });
    path = "/tmp/hudsontest4"; // TODO
    server.listen(path);
    ecdsaKeyPair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    ecdsaKeyPairTwo = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  });

  it("Should sign a request", async () => {
    const request = http.request({
      socketPath: path,
      method: "GET",
      headers: {
        "Content-Type": "text/plain",
      },
    });

    request.on("error", function (err) {
      console.log(err);
    });

    request.on("response", function (response) {
      server.close();
    });

    const result = await signRequest({
      alg: AlgorithmTypes["ecdsa-p256-sha256"],
      key: ecdsaKeyPair.privateKey,
      keyid: "key1",
      request,
    });

    request.end();

    expect(unwrap(result).getHeaders()).toMatchObject({
      signature: expect.stringMatching(/^sig1=*.*:$/),
      "signature-input":
        'sig1=("@request-target" "content-type" "host" "@method");alg="ecdsa-p256-sha256";keyid="key1";created=1577836800',
    });
  });
});

describe("createSignatureHeader", () => {
  Date.now = jest.fn(() => 1577836800000);

  beforeEach(() => {
    ecdsaKeyPair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    ecdsaKeyPairTwo = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  });

  it("Should create a signature and a digest", async () => {
    const options: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: signECDSA(ecdsaKeyPair.privateKey) },
    };

    const result = await createSignatureHeader(options);

    expect(unwrap(result)).toEqual({
      // we can't compare the signature directly as ECDSA is not deterministic
      signature: expect.stringMatching(/^sig1=*.*:$/),
      signatureInput:
        'sig1=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1577836800',
      digest: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
    });
  });

  it("Should accept an optional nonce, expiry and context", async () => {
    const options: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: signECDSA(ecdsaKeyPair.privateKey) },
      expires: 1577836801,
      nonce: "abcdefg",
      context: "application specific context",
    };

    const result = await createSignatureHeader(options);

    expect(unwrap(result)).toEqual({
      // we can't compare the signature directly as ECDSA is not deterministic
      signature: expect.stringMatching(/^sig1=*.*:$/),
      signatureInput:
        'sig1=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1577836800;expires=1577836801;nonce="abcdefg";context="application specific context"',
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

    expect(unwrap(result)).toEqual({
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

    const resultValue = unwrap(result);

    const optionsTwo: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        signature: resultValue.signature,
        "Signature-Input": resultValue.signatureInput,
      },
      signer: { keyid: "key2", sign: signECDSA(ecdsaKeyPairTwo.privateKey) },
    };

    const resultTwo = await createSignatureHeader(optionsTwo);

    expect(unwrap(resultTwo)).toEqual({
      // we can't compare the signature directly as ECDSA is not deterministic
      signature: expect.stringMatching(/^sig1=*.*:, sig2=*.*:$/),
      signatureInput:
        'sig1=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1577836800, sig2=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key2";created=1577836800',
      digest: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
    });
  });

  it("Should sign over a previous signature if a signature id is provided", async () => {
    const optionsTwo: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key2", sign: signECDSA(ecdsaKeyPairTwo.privateKey) },
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        Signature: "sig1=abcde:",
        "Signature-Input":
          'sig1=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1577836800',
      },
      existingSignatureKey: "sig1",
    };

    const resultTwo = await createSignatureHeader(optionsTwo);

    expect(unwrap(resultTwo)).toEqual({
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

    expect(unwrap(result)).toMatchObject({
      digest: "sha-256=:qoxd-emcQclK6Mp84PxOeUumOdjbx-mSW_pxhEXlcno=:",
      signatureInput: `sig1=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1577836800`,
    });
  });

  it("Should handle an empty body", async () => {
    const options = {
      signer: { keyid: "key1", sign: signECDSA(ecdsaKeyPair.privateKey) },
      url: "http://example.com/foo?param=value&pet=dog",
      alg: AlgorithmTypes["ecdsa-p256-sha256"],
      method: "POST",
      httpHeaders: {
        ["HOST"]: "example.com",
        ["Content-Type"]: "application/json",
      },
    };

    const result = await createSignatureHeader(options);

    expect(unwrap(result)).toMatchObject({
      digest: undefined,
      signatureInput: `sig1=("@request-target" "content-type" "host" "@method");alg="ecdsa-p256-sha256";keyid="key1";created=1577836800`,
    });
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
