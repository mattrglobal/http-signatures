/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import crypto from "crypto";
import http from "http";
import { err } from "neverthrow";

import {
  verifySignatureHeader,
  createSignatureHeader,
  CreateSignatureHeaderOptions,
  verifyRequest,
  AlgorithmTypes,
} from "../../src";
import * as common from "../../src/common";
import { signSha256, signEd25519, verifySha256 } from "../../src/common/cryptoPrimatives";
import { unwrap } from "../../src/errors";
import { createSignatureHeaderOptions } from "../__fixtures__/createSignatureHeaderOptions";

let createSignatureResult: { digest?: string; signature: string; signatureInput: string };
let createSignatureResultTwo: { digest?: string; signature: string; signatureInput: string };
let ecdsap256KeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };
let ecdsap256KeyPairTwo: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };
let ed25519KeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };
let keyMap: { [keyid: string]: crypto.KeyObject };

describe("verifyRequest", () => {
  Date.now = jest.fn(() => 1577836800); //01.01.2020
  let server: http.Server;
  let host: string;
  let port: number;

  type Response = {
    headers: Record<string, unknown>;
    statusCode: number | undefined;
    body: unknown;
  };
  const request = (httpoptions: http.RequestOptions, data?: string): Promise<Response> => {
    return new Promise<Response>((resolve, reject) => {
      const req = http.request(httpoptions, (res) => {
        const chunks: unknown[] = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          resolve({
            headers: res.headers,
            statusCode: res.statusCode,
            body: JSON.parse(chunks.join("")),
          });
        });
      });

      if (data) {
        req.write(data);
      }

      req.on("error", (error) => reject(error));
      req.end();
    });
  };

  afterEach(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  beforeEach(async () => {
    ecdsap256KeyPair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    ecdsap256KeyPairTwo = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    ed25519KeyPair = crypto.generateKeyPairSync("ed25519");

    const createOptions: CreateSignatureHeaderOptions = {
      url: `http://127.0.0.1/test`,
      method: "POST",
      signer: { keyid: "key1", sign: signSha256(ecdsap256KeyPair.privateKey) },
      expires: 10000000000,
      nonce: "abcd",
      httpHeaders: {
        ["HOST"]: "127.0.0.1",
        ["Content-Type"]: "application/json",
      },
      alg: AlgorithmTypes["ecdsa-p256-sha256"],
      body: `{"hello": "world"}`,
    };
    await createSignatureHeader(createOptions).then((res) => {
      expect(res.isOk()).toBe(true);
      res.isOk() ? (createSignatureResult = res.value) : undefined;
    });

    const createOptionsTwo: CreateSignatureHeaderOptions = {
      url: `http://127.0.0.1/test`,
      method: "POST",
      signer: { keyid: "key1", sign: signEd25519(ed25519KeyPair.privateKey) },
      expires: 10000000000,
      nonce: "abcd",
      httpHeaders: {
        ["HOST"]: "127.0.0.1",
        ["Content-Type"]: "application/json",
      },
      alg: AlgorithmTypes["ecdsa-p256-sha256"],
      body: `{"hello": "world"}`,
    };
    await createSignatureHeader(createOptionsTwo).then((res) => {
      expect(res.isOk()).toBe(true);
      res.isOk() ? (createSignatureResultTwo = res.value) : undefined;
    });
  });

  it("Should verify a request with ecdsa-p256 alg", async () => {
    server = http.createServer((req, res) => {
      if (req.url === "/test") {
        const keymap = { key1: ecdsap256KeyPair.publicKey };
        const alg = AlgorithmTypes["ecdsa-p256-sha256"];

        let reqdata = "";
        req.on("data", (chunk) => {
          reqdata += chunk;
        });

        req.on("end", () => {
          verifyRequest({ keymap, alg, request: req, data: reqdata }).then((verifyResult) => {
            expect(unwrap(verifyResult)).toEqual(true);
          });
        });

        const data = {
          headers: req.headers,
        };
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(data));
      } else {
        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end(JSON.stringify({ error: "Not Found" }));
      }
    });

    await new Promise<void>((resolve) => {
      server.listen(() => resolve());
    });

    const address = server.address();
    if (typeof address !== "object" || address == null) {
      throw new Error("Unexpected server address");
    }
    host = "127.0.0.1";
    port = address?.port;

    const validHttpHeaderInput = {
      Signature: createSignatureResult.signature,
      "Signature-Input": createSignatureResult.signatureInput,
      "Content-Digest": createSignatureResult.digest,
    };

    const data = `{"hello": "world"}`;

    await request(
      {
        host,
        port,
        path: "/test",
        method: "POST",
        headers: {
          ...validHttpHeaderInput,
          ["HOST"]: "127.0.0.1",
          ["Content-Type"]: "application/json",
        },
      },
      data
    );
  });

  it("Should verify a request with ed25519 alg", async () => {
    server = http.createServer((req, res) => {
      if (req.url === "/test") {
        const keymap = { key1: ed25519KeyPair.publicKey };
        const alg = AlgorithmTypes.ed25519;

        let reqdata = "";
        req.on("data", (chunk) => {
          reqdata += chunk;
        });

        req.on("end", () => {
          verifyRequest({ keymap, alg, request: req, data: reqdata }).then((verifyResult) => {
            expect(unwrap(verifyResult)).toEqual(true);
          });
        });

        const data = {
          headers: req.headers,
        };
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(data));
      } else {
        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end(JSON.stringify({ error: "Not Found" }));
      }
    });

    await new Promise<void>((resolve) => {
      server.listen(() => resolve());
    });

    const address = server.address();
    if (typeof address !== "object" || address == null) {
      throw new Error("Unexpected server address");
    }
    host = "127.0.0.1";
    port = address?.port;

    const validHttpHeaderInput = {
      Signature: createSignatureResultTwo.signature,
      "Signature-Input": createSignatureResultTwo.signatureInput,
      "Content-Digest": createSignatureResultTwo.digest,
    };

    const data = `{"hello": "world"}`;

    await request(
      {
        host,
        port,
        path: "/test",
        method: "POST",
        headers: {
          ...validHttpHeaderInput,
          ["HOST"]: "127.0.0.1",
          ["Content-Type"]: "application/json",
        },
      },
      data
    );
  });
});

describe("verifySignatureHeader", () => {
  Date.now = jest.fn(() => 1577836800); //01.01.2020

  beforeEach(async () => {
    ecdsap256KeyPair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const createOptions: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: signSha256(ecdsap256KeyPair.privateKey) },
      expires: 10000000000,
      nonce: "abcd",
      context: "application specific context",
    };
    await createSignatureHeader(createOptions).then((res) => {
      expect(res.isOk()).toBe(true);
      res.isOk() ? (createSignatureResult = res.value) : undefined;
    });

    ecdsap256KeyPairTwo = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const createOptionsTwo: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        Signature: createSignatureResult.signature,
        ["Signature-Input"]: createSignatureResult.signatureInput,
      },
      signer: { keyid: "key2", sign: signSha256(ecdsap256KeyPairTwo.privateKey) },
    };
    await createSignatureHeader(createOptionsTwo).then((res) => {
      expect(res.isOk()).toBe(true);
      res.isOk() ? (createSignatureResultTwo = res.value) : undefined;
    });

    keyMap = { key1: ecdsap256KeyPair.publicKey, key2: ecdsap256KeyPairTwo.publicKey };
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
      verifier: { verify: verifySha256(keyMap) },
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
      verifier: { verify: verifySha256(keyMap) },
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
      verifier: { verify: verifySha256({ key2: keyMap.key2 }) },
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
      verifier: { verify: verifySha256({ key2: keyMap.key2 }) },
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
      verifier: { verify: verifySha256(keyMap) },
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
      signer: { keyid: "key2", sign: signSha256(ecdsap256KeyPairTwo.privateKey) },
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
      verifier: { verify: verifySha256(keyMap) },
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
      verifier: { verify: verifySha256(keyMap) },
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
      verifier: { verify: verifySha256(keyMap) },
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
      verifier: { verify: verifySha256(keyMap) },
      body: createSignatureHeaderOptions.body,
    });

    expect(unwrap(result)).toEqual(false);
  });

  it("Should return verified false if signature header is not a string", async () => {
    const result = await verifySignatureHeader({
      httpHeaders: {},
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifySha256(keyMap) },
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
        verifier: { verify: verifySha256(keyMap) },
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
      verifier: { verify: verifySha256(keyMap) },
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
      verifier: { verify: verifySha256(keyMap) },
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
      verifier: { verify: verifySha256(keyMap) },
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
      verifier: { verify: verifySha256(keyMap) },
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
      verifier: { verify: verifySha256(keyMap) },
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
      verifier: { verify: verifySha256(keyMap) },
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

  // it("test case from spec", async () => {
  //     const rsa_pss_key = crypto.createPublicKey(`-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI2wIDAQAB\n-----END PUBLIC KEY-----`)

  //     const result = await verifySignatureHeader({
  //       httpHeaders: {
  //         Signature: "sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:",
  //         "Signature-Input": 'sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
  //         "Content-Digest": "sha-512=:JlEy2bfUz7WrWIjc1qV6KVLpdr/7L5/L4h7Sxvh6sNHpDQWDCL+GauFQWcZBvVDhiyOnAQsxzZFYwi0wDH+1pw==:",
  //       },
  //       method: "POST",
  //       url: 'https://example.com/foo?param=Value&Pet=dog',
  //       body: `{"hello": "world"}`,
  //       verifier: { verify: verifyRsaPssSha512({'test-key-rsa-pss': rsa_pss_key}) },
  //     });

  //     expect(unwrap(result)).toEqual(true);
  // })
});
