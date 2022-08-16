/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import { AsnParser } from "@peculiar/asn1-schema";
import crypto from "crypto";
import { asn1 } from "webcrypto-core";

import { createSignatureHeader, CreateSignatureHeaderOptions } from "../../src/sign";
import { createSignatureHeaderOptions } from "../__fixtures__/createSignatureHeaderOptions";

const addPadding = (pointSize: number, bytes: Buffer): Buffer => {
  const res = Buffer.alloc(pointSize);
  res.set(Buffer.from(bytes), pointSize - bytes.length);
  return res;
};

const signECDSA = async (data: Uint8Array): Promise<Uint8Array> => {
  const key = {
    kty: "EC",
    d: "wcHNx8kkBCcBnGY39K995TShcdOFdKtaRQLGrUELqBI",
    crv: "P-256",
    x: "m5dnqNXawIKF3qyCfs_raR1LtTKUtyf4t2uVa4Wmd6A",
    y: "prF8Lo5JC2JTyj2GwtaI2LWWEaRa6v6XykjUMg-9C1U",
    alg: "ES256",
  };
  const signer = crypto.createSign("sha256");
  signer.update(data);
  const signature = signer.sign(crypto.createPrivateKey({ key, format: "jwk" }));

  // TODO: Node Crypto produce ASN.1 format of the signature, can we do it without AsnParser?
  const ecSignature = AsnParser.parse(signature, asn1.EcDsaSignature);
  const r = addPadding(32, Buffer.from(ecSignature.r));
  const s = addPadding(32, Buffer.from(ecSignature.s));
  return new Uint8Array(Buffer.concat([r, s]));
};

describe("createSignatureHeader", () => {
  Date.now = jest.fn(() => 1577836800000);

  it("Should create a signature and a digest", async () => {
    const options: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: signECDSA },
    };

    const result = await createSignatureHeader(options);

    if (result.isErr()) {
      throw result.error;
    }

    console.log("##", result.value);
    expect(result.value).toEqual({
      // we can't compare the signature directly as ECDSA is not deterministic
      signature: expect.stringMatching(/^sig=*.*:$/),
      signatureInput:
        'sig=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1577836800',
      digest: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
    });
  });

  it("Should handle a string body", async () => {
    const options = {
      ...createSignatureHeaderOptions,
      body: "string body",
      signer: { keyid: "key1", sign: signECDSA },
    };

    const result = await createSignatureHeader(options);
    if (result.isErr()) {
      throw result.error;
    }

    expect(result.value).toMatchObject({
      digest: "sha-256=:qoxd-emcQclK6Mp84PxOeUumOdjbx-mSW_pxhEXlcno=:",
      signatureInput: `sig=("@request-target" "content-type" "host" "@method" "content-digest");alg="ecdsa-p256-sha256";keyid="key1";created=1577836800`,
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
