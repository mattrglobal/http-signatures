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
import {
  algMap,
  signEcdsaSha256,
  verifyEcdsaSha256,
  verifyEd25519,
  verifyHmacSha256,
  verifyRsaPssSha512,
} from "../../src/common/cryptoPrimatives";
import { unwrap } from "../../src/errors";
import { createSignatureHeaderOptions } from "../__fixtures__/createSignatureHeaderOptions";

let createSignatureResult: { digest?: string; signature: string; signatureInput: string };
let createSignatureResultTwo: { digest?: string; signature: string; signatureInput: string };
const ecdsaP256KeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject } = crypto.generateKeyPairSync(
  "ec",
  { namedCurve: "P-256" }
);
const ecdsaP256KeyPairTwo: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject } = crypto.generateKeyPairSync(
  "ec",
  { namedCurve: "P-256" }
);
const ecdsaP384KeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject } = crypto.generateKeyPairSync(
  "ec",
  { namedCurve: "P-384" }
);
const ed25519KeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject } =
  crypto.generateKeyPairSync("ed25519");
const rsaPssKeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject } = crypto.generateKeyPairSync(
  "rsa-pss",
  { modulusLength: 4096 }
);
const rsaV1_5KeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject } = crypto.generateKeyPairSync(
  "rsa",
  { modulusLength: 4096 }
);
const keymap = { key1: ecdsaP256KeyPair.publicKey, key2: ecdsaP256KeyPairTwo.publicKey };
const hmacSharedSecret: crypto.KeyObject = crypto.createSecretKey(crypto.randomBytes(4096));

const examplePublicRsaPssKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB\n-----END PUBLIC KEY-----`;

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

  test.each([
    [AlgorithmTypes["ecdsa-p256-sha256"], ecdsaP256KeyPair.privateKey, ecdsaP256KeyPair.publicKey],
    [AlgorithmTypes["ecdsa-p384-sha384"], ecdsaP384KeyPair.privateKey, ecdsaP384KeyPair.publicKey],
    [AlgorithmTypes.ed25519, ed25519KeyPair.privateKey, ed25519KeyPair.publicKey],
    [AlgorithmTypes["hmac-sha256"], hmacSharedSecret, hmacSharedSecret],
    [AlgorithmTypes["rsa-pss-sha512"], rsaPssKeyPair.privateKey, rsaPssKeyPair.publicKey],
    [AlgorithmTypes["rsa-v1_5-sha256"], rsaV1_5KeyPair.privateKey, rsaV1_5KeyPair.publicKey],
  ])(
    "Should verify a request with %s algorithm",
    async (alg: AlgorithmTypes, privateKey: crypto.KeyObject, publicKey: crypto.KeyObject) => {
      server = http.createServer((req, res) => {
        if (req.url === "/test") {
          let reqdata = "";
          req.on("data", (chunk) => {
            reqdata += chunk;
          });

          req.on("end", () => {
            verifyRequest({ keymap: { key1: publicKey }, alg, request: req, data: reqdata }).then((verifyResult) => {
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

      const createOptions: CreateSignatureHeaderOptions = {
        url: `http://127.0.0.1/test`,
        method: "POST",
        signer: { keyid: "key1", sign: algMap[alg].sign(privateKey) },
        expires: 10000000000,
        nonce: "abcd",
        httpHeaders: {
          ["HOST"]: "127.0.0.1",
          ["Content-Type"]: "application/json",
        },
        alg,
        body: `{"hello": "world"}`,
      };
      await createSignatureHeader(createOptions).then((res) => {
        expect(res.isOk()).toBe(true);
        res.isOk() ? (createSignatureResult = res.value) : undefined;
      });

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
    }
  );
});

describe("verifySignatureHeader", () => {
  Date.now = jest.fn(() => 1577836800); //01.01.2020

  beforeEach(async () => {
    const createOptions: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: signEcdsaSha256(ecdsaP256KeyPair.privateKey) },
      expires: 10000000000,
      nonce: "abcd",
      tag: "application specific context",
    };
    await createSignatureHeader(createOptions).then((res) => {
      expect(res.isOk()).toBe(true);
      res.isOk() ? (createSignatureResult = res.value) : undefined;
    });

    const createOptionsTwo: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        Signature: createSignatureResult.signature,
        ["Signature-Input"]: createSignatureResult.signatureInput,
      },
      signer: { keyid: "key2", sign: signEcdsaSha256(ecdsaP256KeyPairTwo.privateKey) },
    };
    await createSignatureHeader(createOptionsTwo).then((res) => {
      expect(res.isOk()).toBe(true);
      res.isOk() ? (createSignatureResultTwo = res.value) : undefined;
    });
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
      verifier: { verify: verifyEcdsaSha256(keymap) },
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
      verifier: { verify: verifyEcdsaSha256(keymap) },
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
      verifier: { verify: verifyEcdsaSha256({ key2: keymap.key2 }) },
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
      verifier: { verify: verifyEcdsaSha256({ key2: keymap.key2 }) },
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
      verifier: { verify: verifyEcdsaSha256(keymap) },
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
      signer: { keyid: "key2", sign: signEcdsaSha256(ecdsaP256KeyPairTwo.privateKey) },
      coveredFields: [
        ["@request-target", new Map()],
        ["@method", new Map()],
        ["content-digest", new Map()],
        ["signature", new Map([["key", "sig1"]])],
        ["content-type", new Map()],
        ["host", new Map()],
      ],
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
      verifier: { verify: verifyEcdsaSha256(keymap) },
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
      verifier: { verify: verifyEcdsaSha256(keymap) },
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
      verifier: { verify: verifyEcdsaSha256(keymap) },
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
      verifier: { verify: verifyEcdsaSha256(keymap) },
      body: createSignatureHeaderOptions.body,
    });

    expect(unwrap(result)).toEqual(false);
  });

  it("Should return verified false if signature header is not a string", async () => {
    const result = await verifySignatureHeader({
      httpHeaders: {},
      method: createSignatureHeaderOptions.method,
      url: createSignatureHeaderOptions.url,
      verifier: { verify: verifyEcdsaSha256(keymap) },
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
        verifier: { verify: verifyEcdsaSha256(keymap) },
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
      verifier: { verify: verifyEcdsaSha256(keymap) },
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
      verifier: { verify: verifyEcdsaSha256(keymap) },
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
      verifier: { verify: verifyEcdsaSha256(keymap) },
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
      verifier: { verify: verifyEcdsaSha256(keymap) },
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
      verifier: { verify: verifyEcdsaSha256(keymap) },
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
      verifier: { verify: verifyEcdsaSha256(keymap) },
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

  it("should be able to verify the signature from test B.2.1. in the spec", async () => {
    // refer to https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-13.html#name-minimal-signature-using-rsa
    const rsa_pss_key = crypto.createPublicKey({ key: examplePublicRsaPssKey });

    const result = await verifySignatureHeader({
      httpHeaders: {
        Signature:
          "sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:",
        "Signature-Input": 'sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
      },
      method: "POST",
      url: "http://example.com/foo?param=Value&Pet=dog",
      body: `{"hello": "world"}`,
      verifier: { verify: verifyRsaPssSha512({ "test-key-rsa-pss": rsa_pss_key }) },
    });

    expect(unwrap(result)).toEqual(true);
  });

  it("should be able to verify the signature from test B.2.2. in the spec", async () => {
    // refer to https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-13.html#name-minimal-signature-using-rsa
    const rsa_pss_key = crypto.createPublicKey({ key: examplePublicRsaPssKey });

    const result = await verifySignatureHeader({
      httpHeaders: {
        Signature:
          "sig-b22=:LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQEdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SARYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoKUqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==:",
        "Signature-Input":
          'sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"',
        "Content-Digest":
          "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
      },
      method: "POST",
      url: "http://example.com/foo?Pet=dog",
      body: `{"hello": "world"}`,
      verifier: { verify: verifyRsaPssSha512({ "test-key-rsa-pss": rsa_pss_key }) },
    });

    expect(unwrap(result)).toEqual(true);
  });

  it("should be able to verify the signature from test B.2.3. in the spec", async () => {
    // refer to https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-13.html#name-full-coverage-using-rsa-pss
    const rsa_pss_key = crypto.createPublicKey({ key: examplePublicRsaPssKey });

    const result = await verifySignatureHeader({
      httpHeaders: {
        Signature:
          "sig-b23=:bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yBiMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fUxN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5ZJzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==:",
        "Signature-Input":
          'sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"',
        "Content-Digest":
          "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
        Date: "Tue, 20 Apr 2021 02:07:55 GMT",
        ["Content-Type"]: "application/json",
        ["Content-Length"]: "18",
      },
      method: "POST",
      url: "http://example.com/foo?param=Value&Pet=dog",
      body: `{"hello": "world"}`,
      verifier: { verify: verifyRsaPssSha512({ "test-key-rsa-pss": rsa_pss_key }) },
    });

    expect(unwrap(result)).toEqual(true);
  });

  it("should be able to verify the signature from test B.2.4. in the spec", async () => {
    // refer to https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-13.html#name-signing-a-response-using-ec
    const test_key_ecc_p256 = crypto.createPublicKey({
      key: `-----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
    w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==\n-----END PUBLIC KEY-----`,
    });

    const result = await verifySignatureHeader({
      httpHeaders: {
        Signature: "sig-b24=:wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==:",
        "Signature-Input":
          'sig-b24=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"',
        "Content-Digest":
          "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:",
        ["Content-Type"]: "application/json",
        ["Content-Length"]: "23",
      },
      method: "POST",
      url: "http://example.com/foo?param=Value&Pet=dog",
      statusCode: 200,
      body: `{"message": "good dog"}`,
      verifier: { verify: verifyEcdsaSha256({ "test-key-ecc-p256": test_key_ecc_p256 }) },
    });

    expect(unwrap(result)).toEqual(true);
  });

  it("should be able to verify the signature from test B.2.5. in the spec", async () => {
    // refer to https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-13.html#name-signing-a-request-using-hma

    const b64secret = "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==";
    const decodeResult = common.decodeBase64(b64secret);
    if (decodeResult.isErr()) {
      throw decodeResult.error;
    }
    const { value: secret } = decodeResult;

    const hmacSharedSecret = Buffer.from(secret);
    const key = crypto.createSecretKey(hmacSharedSecret);

    const result = await verifySignatureHeader({
      httpHeaders: {
        Signature: "sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:",
        "Signature-Input": 'sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
        "Content-Type": "application/json",
        date: "Tue, 20 Apr 2021 02:07:55 GMT",
      },
      method: "POST",
      url: "http://example.com/foo",
      verifier: { verify: verifyHmacSha256({ "test-shared-secret": key }) },
    });

    expect(unwrap(result)).toEqual(true);
  });

  it("should be able to verify the signature from test B.2.6. in the spec", async () => {
    // refer to https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-13.html#name-signing-a-request-using-ed2
    const ed25519TestKey = crypto.createPublicKey(
      `-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=\n-----END PUBLIC KEY-----`
    );

    const result = await verifySignatureHeader({
      httpHeaders: {
        Signature: "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:",
        "Signature-Input":
          'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
        "Content-Type": "application/json",
        "Content-Length": "18",
        date: "Tue, 20 Apr 2021 02:07:55 GMT",
      },
      method: "POST",
      url: "http://example.com/foo",
      verifier: { verify: verifyEd25519({ "test-key-ed25519": ed25519TestKey }) },
    });

    expect(unwrap(result)).toEqual(true);
  });
});
