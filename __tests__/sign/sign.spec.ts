/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import crypto from "crypto";
import http from "http";
import superagent from "superagent";

import { decodeBase64 } from "../../src/common";
import { signSha256, signEcdsaSha384, signRsaPssSha512, signHmacSha256 } from "../../src/common/cryptoPrimatives";
import { unwrap } from "../../src/errors";
import {
  createSignatureHeader,
  CreateSignatureHeaderOptions,
  signRequest,
  SignOptions,
  AlgorithmTypes,
} from "../../src/sign";
import { createSignatureHeaderOptions } from "../__fixtures__/createSignatureHeaderOptions";

let ecdsaP256KeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };
let ecdsaP384KeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };
let ed25519KeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };
let rsaPssKeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };
let hmacSharedSecret: crypto.KeyObject;

describe("signRequest", () => {
  let server: http.Server;
  let host: string;
  let port: number;

  type Response = {
    headers: Record<string, unknown>;
    statusCode: number | undefined;
    body: unknown;
  };
  const request = (httpoptions: http.RequestOptions, signOptions?: SignOptions): Promise<Response> => {
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

      if (signOptions) {
        signRequest({ ...signOptions, request: req }).then((signResult) => {
          if (signResult.isErr()) {
            throw signResult.error;
          } else {
            const signedRequest = signResult.value;
            signedRequest.on("error", (error) => reject(error));
            signedRequest.end();
          }
        });
      } else {
        req.on("error", (error) => reject(error));
        req.end();
      }
    });
  };

  type SuperAgentRequestOptions = {
    url: string;
    method: "get" | "post" | "put" | "patch" | "delete";
    headers: { [key: string]: string };
    body?: { [key: string]: string };
  };
  const superAgentRequest = (
    requestOptions: SuperAgentRequestOptions,
    signOptions?: SignOptions
  ): Promise<Response> => {
    return new Promise<Response>((resolve, reject) => {
      const req = superagent[requestOptions.method](requestOptions.url);

      if (requestOptions.body) {
        req.send(requestOptions.body);
      }

      for (const key in requestOptions.headers) {
        req.set(key, requestOptions.headers[key]);
      }

      if (signOptions) {
        signRequest({ ...signOptions, request: req }).then((signResult) => {
          if (signResult.isErr()) {
            throw signResult.error;
          } else {
            const signedRequest = signResult.value;
            signedRequest.end((err, res) => {
              if (err) {
                reject(err);
              }
              resolve({
                headers: res.headers,
                statusCode: res.statusCode,
                body: res.body,
              });
            });
          }
        });
      }
    });
  };

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      if (req.url === "/test") {
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
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  beforeEach(() => {
    ecdsaP256KeyPair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    ecdsaP384KeyPair = crypto.generateKeyPairSync("ec", { namedCurve: "P-384" });
    ed25519KeyPair = crypto.generateKeyPairSync("ed25519");
    rsaPssKeyPair = crypto.generateKeyPairSync("rsa-pss", { modulusLength: 4096 });
    hmacSharedSecret = crypto.createSecretKey(crypto.randomBytes(4096));
  });

  it("Should sign a request with ecdsa-p256-sha256 alg", async () => {
    const requestOptions = {
      host,
      port,
      path: "/test",
      method: "GET",
      headers: {
        "content-type": "text/plain",
      },
    };

    const signOptions: SignOptions = {
      alg: AlgorithmTypes["ecdsa-p256-sha256"],
      key: ecdsaP256KeyPair.privateKey,
      keyid: "key1",
      data: `{"Hello": "World"}`,
    };

    const res = await request(requestOptions, signOptions);
    expect(res.statusCode).toBe(200);
    expect(res.headers).toEqual({
      connection: "close",
      date: expect.any(String),
      "content-type": "application/json",
      "transfer-encoding": "chunked",
    });
    expect(res.body).toMatchObject({
      headers: {
        signature: expect.stringMatching(/^sig1=*.*:$/),
        "signature-input":
          'sig1=("@request-target" "@method" "content-digest" "content-type" "host");created=1577836800;alg="ecdsa-p256-sha256";keyid="key1"',
      },
    });
  });

  it("Should sign a request with ecdsa-p384-sha384 alg", async () => {
    const requestOptions = {
      host,
      port,
      path: "/test",
      method: "GET",
      headers: {
        "content-type": "text/plain",
      },
    };

    const signOptions: SignOptions = {
      alg: AlgorithmTypes["ecdsa-p384-sha384"],
      key: ecdsaP384KeyPair.privateKey,
      keyid: "key1",
      data: `{"Hello": "World"}`,
    };

    const res = await request(requestOptions, signOptions);
    expect(res.statusCode).toBe(200);
    expect(res.headers).toEqual({
      connection: "close",
      date: expect.any(String),
      "content-type": "application/json",
      "transfer-encoding": "chunked",
    });
    expect(res.body).toMatchObject({
      headers: {
        signature: expect.stringMatching(/^sig1=*.*:$/),
        "signature-input":
          'sig1=("@request-target" "@method" "content-digest" "content-type" "host");created=1577836800;alg="ecdsa-p384-sha384";keyid="key1"',
      },
    });
  });

  it("Should sign a request with ed25519 alg", async () => {
    const requestOptions = {
      host,
      port,
      path: "/test",
      method: "GET",
      headers: {
        "content-type": "text/plain",
      },
    };

    const signOptions = {
      alg: AlgorithmTypes.ed25519,
      key: ed25519KeyPair.privateKey,
      keyid: "key1",
      data: `{"Hello": "World"}`,
    };

    const res = await request(requestOptions, signOptions);
    expect(res.statusCode).toBe(200);
    expect(res.headers).toEqual({
      connection: "close",
      date: expect.any(String),
      "content-type": "application/json",
      "transfer-encoding": "chunked",
    });
    expect(res.body).toMatchObject({
      headers: {
        signature: expect.stringMatching(/^sig1=*.*:$/),
        "signature-input":
          'sig1=("@request-target" "@method" "content-digest" "content-type" "host");created=1577836800;alg="ed25519";keyid="key1"',
      },
    });
  });

  it("Should sign a request with hmac-sha256 alg", async () => {
    const requestOptions = {
      host,
      port,
      path: "/test",
      method: "GET",
      headers: {
        "content-type": "text/plain",
      },
    };

    const signOptions = {
      alg: AlgorithmTypes["hmac-sha256"],
      key: hmacSharedSecret,
      keyid: "key1",
      data: `{"Hello": "World"}`,
    };

    const res = await request(requestOptions, signOptions);
    expect(res.statusCode).toBe(200);
    expect(res.headers).toEqual({
      connection: "close",
      date: expect.any(String),
      "content-type": "application/json",
      "transfer-encoding": "chunked",
    });
    expect(res.body).toMatchObject({
      headers: {
        signature: expect.stringMatching(/^sig1=*.*:$/),
        "signature-input":
          'sig1=("@request-target" "@method" "content-digest" "content-type" "host");created=1577836800;alg="hmac-sha256";keyid="key1"',
      },
    });
  });

  it("Should sign a request with rsa-pss-sha512 alg", async () => {
    const requestOptions = {
      host,
      port,
      path: "/test",
      method: "GET",
      headers: {
        "content-type": "text/plain",
      },
    };

    const signOptions = {
      alg: AlgorithmTypes["rsa-pss-sha512"],
      key: rsaPssKeyPair.privateKey,
      keyid: "key1",
      data: `{"Hello": "World"}`,
    };

    const res = await request(requestOptions, signOptions);
    expect(res.statusCode).toBe(200);
    expect(res.headers).toEqual({
      connection: "close",
      date: expect.any(String),
      "content-type": "application/json",
      "transfer-encoding": "chunked",
    });
    expect(res.body).toMatchObject({
      headers: {
        signature: expect.stringMatching(/^sig1=*.*:$/),
        "signature-input":
          'sig1=("@request-target" "@method" "content-digest" "content-type" "host");created=1577836800;alg="rsa-pss-sha512";keyid="key1"',
      },
    });
  });

  it("Should sign a request created by SuperAgent", async () => {
    const requestOptions: SuperAgentRequestOptions = {
      url: `http://${host}:${port}/test`,
      method: "post",
      headers: {
        "Content-Type": "Application/Json",
        host,
      },
      body: {
        Hello: "World",
      },
    };

    const signOptions: SignOptions = {
      alg: AlgorithmTypes["ecdsa-p256-sha256"],
      key: ecdsaP256KeyPair.privateKey,
      keyid: "key1",
    };

    const res = await superAgentRequest(requestOptions, signOptions);

    expect(res.statusCode).toBe(200);
    expect(res.headers).toEqual({
      connection: "close",
      date: expect.any(String),
      "content-type": "application/json",
      "transfer-encoding": "chunked",
    });
    expect(res.body).toMatchObject({
      headers: {
        signature: expect.stringMatching(/^sig1=*.*:$/),
        "signature-input":
          'sig1=("@request-target" "@method" "content-digest" "content-type" "host");created=1577836800;alg="ecdsa-p256-sha256";keyid="key1"',
      },
    });
  });
});

describe("createSignatureHeader", () => {
  Date.now = jest.fn(() => 1577836800000);

  beforeEach(() => {
    ecdsaP256KeyPair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    ecdsaP384KeyPair = crypto.generateKeyPairSync("ec", { namedCurve: "P-384" });
  });

  it("Should create a signature and a digest", async () => {
    const options: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: signSha256(ecdsaP256KeyPair.privateKey) },
    };

    const result = await createSignatureHeader(options);

    expect(unwrap(result)).toEqual({
      // we can't compare the signature directly as ECDSA is not deterministic
      signature: expect.stringMatching(/^sig1=*.*:$/),
      signatureInput:
        'sig1=("@request-target" "@method" "content-digest" "content-type" "host");created=1577836800;alg="ecdsa-p256-sha256";keyid="key1"',
      digest: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
    });
  });

  it("Should accept an optional nonce, expiry and context", async () => {
    const options: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: signSha256(ecdsaP256KeyPair.privateKey) },
      expires: 1577836801,
      nonce: "abcdefg",
      context: "application specific context",
    };

    const result = await createSignatureHeader(options);

    expect(unwrap(result)).toEqual({
      // we can't compare the signature directly as ECDSA is not deterministic
      signature: expect.stringMatching(/^sig1=*.*:$/),
      signatureInput:
        'sig1=("@request-target" "@method" "content-digest" "content-type" "host");created=1577836800;expires=1577836801;nonce="abcdefg";alg="ecdsa-p256-sha256";keyid="key1";context="application specific context"',
      digest: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
    });
  });

  it("Should use a custom signature ID if one was provided", async () => {
    const signatureId = "testsig123";
    const options: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: signSha256(ecdsaP256KeyPair.privateKey) },
      signatureId,
    };

    const result = await createSignatureHeader(options);

    expect(unwrap(result)).toEqual({
      // we can't compare the signature directly as ECDSA is not deterministic
      signature: expect.stringMatching(/^testsig123=*.*:$/),
      signatureInput:
        'testsig123=("@request-target" "@method" "content-digest" "content-type" "host");created=1577836800;alg="ecdsa-p256-sha256";keyid="key1"',
      digest: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
    });
  });

  it("Should be able to create multiple signatures on the same message", async () => {
    const options: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key1", sign: signSha256(ecdsaP256KeyPair.privateKey) },
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
      alg: AlgorithmTypes["ecdsa-p384-sha384"],
      signer: { keyid: "key2", sign: signEcdsaSha384(ecdsaP384KeyPair.privateKey) },
    };

    const resultTwo = await createSignatureHeader(optionsTwo);

    expect(unwrap(resultTwo)).toEqual({
      // we can't compare the signature directly as ECDSA is not deterministic
      signature: expect.stringMatching(/^sig1=*.*:, sig2=*.*:$/),
      signatureInput:
        'sig1=("@request-target" "@method" "content-digest" "content-type" "host");created=1577836800;alg="ecdsa-p256-sha256";keyid="key1", sig2=("@request-target" "@method" "content-digest" "content-type" "host");created=1577836800;alg="ecdsa-p384-sha384";keyid="key2"',
      digest: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
    });
  });

  it("Should sign over a previous signature if a signature id is provided", async () => {
    const optionsTwo: CreateSignatureHeaderOptions = {
      ...createSignatureHeaderOptions,
      signer: { keyid: "key2", sign: signEcdsaSha384(ecdsaP384KeyPair.privateKey) },
      alg: AlgorithmTypes["ecdsa-p384-sha384"],
      httpHeaders: {
        ...createSignatureHeaderOptions.httpHeaders,
        Signature: "sig1=abcde:",
        "Signature-Input":
          'sig1=("@request-target" "@method" "content-digest" "content-type" "host");created=1577836800;alg="ecdsa-p256-sha256";keyid="key1"',
      },
      existingSignatureKey: "sig1",
    };

    const resultTwo = await createSignatureHeader(optionsTwo);

    expect(unwrap(resultTwo)).toEqual({
      // we can't compare the signature directly as ECDSA is not deterministic
      signature: expect.stringMatching(/^sig1=*.*:, sig2=*.*:$/),
      signatureInput:
        'sig1=("@request-target" "@method" "content-digest" "content-type" "host");created=1577836800;alg="ecdsa-p256-sha256";keyid="key1", sig2=("@request-target" "@method" "content-digest" "signature";key="sig1" "content-type" "host");created=1577836800;alg="ecdsa-p384-sha384";keyid="key2"',
      digest: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
    });
  });

  it("Should handle a string body", async () => {
    const options = {
      ...createSignatureHeaderOptions,
      body: "string body",
      signer: { keyid: "key1", sign: signSha256(ecdsaP256KeyPair.privateKey) },
    };

    const result = await createSignatureHeader(options);

    expect(unwrap(result)).toMatchObject({
      digest: "sha-256=:qoxd-emcQclK6Mp84PxOeUumOdjbx-mSW_pxhEXlcno=:",
      signatureInput: `sig1=("@request-target" "@method" "content-digest" "content-type" "host");created=1577836800;alg="ecdsa-p256-sha256";keyid="key1"`,
    });
  });

  it("Should handle an empty body", async () => {
    const options = {
      signer: { keyid: "key1", sign: signSha256(ecdsaP256KeyPair.privateKey) },
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
      signatureInput: `sig1=("@request-target" "@method" "content-type" "host");created=1577836800;alg="ecdsa-p256-sha256";keyid="key1"`,
    });
  });

  it("Should be able to create a minimal signature", async () => {
    // refer to https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-13.html#name-minimal-signature-using-rsa
    Date.now = jest.fn(() => 1618884473000);

    const exampleKey = crypto.createPrivateKey({
      key: `-----BEGIN PRIVATE KEY-----
      MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv
      P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5
      3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr
      FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA
      AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw
      9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy
      c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq
      pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X
      aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4
      XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ
      HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD
      2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N
      RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx
      DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6
      vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm
      rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi
      4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL
      FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/
      OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx
      NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR
      NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ
      3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE
      t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND
      dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF
      S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR
      rOjr9w349JooGXhOxbu8nOxX\n-----END PRIVATE KEY-----`,
      format: "pem",
      type: "pkcs8",
    });

    const options: CreateSignatureHeaderOptions = {
      signer: { keyid: "test-key-rsa-pss", sign: signRsaPssSha512(exampleKey) },
      coveredFields: [],
      nonce: "b3k2pp5k7z-50gnwp.yemd",
      signatureId: "sig-b21",
      url: "http://example.com/foo?param=value&pet=dog",
      method: "POST",
      httpHeaders: {
        ["HOST"]: "example.com",
        ["Content-Type"]: "application/json",
      },
      body: `{"hello": "world"}`,
    };

    const result = await createSignatureHeader(options);

    expect(unwrap(result)).toEqual({
      // rsa pss is not deterministic, so we can't compare the signatures directly
      signature: expect.stringMatching(/^sig-b21=*.*:$/),
      signatureInput: 'sig-b21=();created=1618884473;nonce="b3k2pp5k7z-50gnwp.yemd";keyid="test-key-rsa-pss"',
      digest: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
    });
  });

  it("should be able to recreate the signature from test case B.2.5. in the spec", async () => {
    // refer to https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-13.html#name-signing-a-request-using-hma

    Date.now = jest.fn(() => 1618884473000);
    const b64secret = "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==";
    const decodeResult = decodeBase64(b64secret);
    if (decodeResult.isErr()) {
      throw decodeResult.error;
    }
    const { value: secret } = decodeResult;

    const hmacSharedSecret = Buffer.from(secret);
    const key = crypto.createSecretKey(hmacSharedSecret);

    const result = await createSignatureHeader({
      httpHeaders: {
        "Content-Type": "application/json",
        date: "Tue, 20 Apr 2021 02:07:55 GMT",
      },
      method: "POST",
      url: "http://example.com/foo",
      signatureId: "sig-b25",
      coveredFields: [
        ["date", new Map()],
        ["@authority", new Map()],
        ["content-type", new Map()],
      ],
      signer: {
        keyid: "test-shared-secret",
        sign: signHmacSha256(key),
      },
    });

    expect(unwrap(result)).toEqual({
      signature: "sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:",
      signatureInput: 'sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
      digest: undefined,
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
      signer: { keyid: "key1", sign: signSha256(ecdsaP256KeyPair.privateKey) },
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
