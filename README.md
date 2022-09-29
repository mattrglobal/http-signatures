![Mattr logo](./docs/assets/mattr-black.svg)

# http-signatures

## Getting Started

### Prerequisites

- [Yarn](https://yarnpkg.com)

### Installation

```bash
yarn install --frozen-lockfile
yarn build
```

### Usage

#### Create signature

With node http

```typescript
const request = http.request("example.com");
const signResult = await signRequest({
  alg: AlgorithmTypes["ecdsa-p256-sha256"],
  key: privateKey,
  keyid: "key1",
  request,
});
if (signResult.isErr()) {
  onError(result.error);
}
if (signResult.isOk()) {
  const signedRequest = signResult.value;
  signedRequest.then((res) => {
    // process response
  });
}
// Optional data parameter handles request body
const request = http.post("example.com");
const signResult = await signRequest({
  alg: AlgorithmTypes["ecdsa-p256-sha256"],
  key: privateKey,
  keyid: "key1",
  request,
  data: `{"some": "request body"}`,
});
if (signResult.isErr()) {
  onError(result.error);
}
if (signResult.isOk()) {
  const signedRequest = signResult.value;
  signedRequest.then((res) => {
    // process response
  });
}
```

With SuperAgent

```typescript
const request = superagent.post("example.com").send({ some: "body" }).set("Content-Type", "Application/Json");
const signResult = await signRequest({
  alg: AlgorithmTypes["ecdsa-p256-sha256"],
  key: privateKey,
  keyid: "key1",
  request,
});
if (signResult.isErr()) {
  onError(result.error);
}
if (signResult.isOk()) {
  const signedRequest = signResult.value;
  signedRequest.end();
}
```

With axios config:

```typescript
const createSignedRequest = async (config: AxiosRequestConfig): Promise<AxiosRequestConfig> => {
  const signer = { sign: signWithEd25519, keyid: "key-1" };
  const { method = "POST", headers, url = "http://www.apiurl.com/path?query=1", data } = config;

  const result = await createSignatureHeader({
    signer,
    httpHeaders: headers,
    method,
    url,
    body: data,
  });
  if (result.isErr()) {
    return onError(result.error);
  }
  const { digest, signature } = result.value;
  const newHeaders = { ...headers, ...(digest ? { Digest: digest } : {}), Signature: signature };

  return { ...config, headers: newHeaders };
};
```

#### Verify signature

With node http

```typescript

    const server = http.createServer((req, res) => {
      const keymap = { keyid: ecdsap256PublicKey };
      const alg = AlgorithmTypes["ecdsa-p256-sha256"];

      let reqdata = "";
      req.on("data", (chunk) => {
        reqdata += chunk;
      });

      req.on("end", () => {
        verifyRequest({ keymap, alg, request: req, data: reqdata }).then((verifyResult) => {
          if(verifyResult.isErr()){
            onError(verifyResult.error);
          }
          if(verifyResult.isOk()){
            console.log(`Is verified: ${verifyResult.value}`);
          }
        });
      }
    }
```

With express

```typescript
const { headers, protocol, baseUrl, method, body } = request;
const url = req.protocol + "://" + headers.host + req.baseUrl;
const verifier = { verify: verifyFn };
const options = { verifier, url, method, httpHeaders: headers, body };

const result = await verifySignatureHeader(options);

if (result.isErr()) {
  return onError(result.error);
}

if (result.isOk()) {
  console.log(`Is verified: ${result.value}`);
}
```

### Covered Fields

By default, this library will sign over @request-target, @method, content-digest (if a request body is present) and any
http headers present on the request.

If you want to override this behaviour to instead cover more or less of a given message, you can provide a list of
message components to sign as an optional argument.

```typescript
const coveredFields = [
  ["@authority", new Map()],
  ["content-digest", new Map()],
  ["signature", new Map([["key", "sig123"]])],
  ["@query-param", new Map([["name", "Pet"]])],
];

const result = await createSignatureHeader({ signer, httpHeaders, method, url, coveredFields });

// produces a signature from the following covered fields string: (@authority content-digest signature;key=sig123 @query-param;name=Pet)
```

Any header can be signed over, or any derived component. A full list of derived components is available here:
https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-13.html#name-derived-components

### Signature Parameters

A number of metadata properties are available to be added during the signature's creation:

```typescript
import { AlgorithmTypes, createSignatureHeader } from "http-signatures";

const expires = 12345678;
const nonce = "test-nonce";
const alg = AlgorithmTypes["ecdsa-p256-sha256"];
const keyid = "key-abc";
const tag = "application-specific-context";
const signer = { sign: signWithEcdsaP256, keyid };

const result = await createSignatureHeader({
  signer,
  httpHeaders,
  method,
  url,
  expires,
  nonce,
  alg,
  tag,
});

// produces a signature with the following signature-params: (@request-target @method)created=1234;expires=12345678;nonce="test-nonce";alg="ecdsa-p256-sha256";keyid='key-abc';tag='application-specific-context'
```

The 'created' parameter will always be added during the signature's creation, and does not need to be provided as an
argument.

A full list of signature parameters is available here:
https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-13.html#name-signature-parameters

### Signature Algorithms

A full list of algorithms is available here:
https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-13.html#name-initial-contents

### Cryptography

Minimal cryptographic primitives are available for each of the signature algorithms. They are implemented using the
native node crypto library.

```typescript
import { signEcdsaP256Sha256, verifyEcdsaP256Sha256, algMap, AlgorithmTypes } from "http-signatures";

const ecdsaP256Sha256 = algMap[AlgorithmTypes["ecdsa-p256-sha256"]];

signer = { keyid: "key1", sign: ecdsaP256Sha256.sign(myPrivateKey) };
verifier = { keyid: "key1", verify: ecdsaP256Sha256.verify({ key1: myPublicKey }) };

// or directly

signer = { keyid: "key1", sign: signEcdsaP256Sha256(myPrivateKey) };
verifier = { keyid: "key1", verify: verifyEcdsaP256Sha256({ key1: myPublicKey }) };

const result = await createSignatureHeader({ signer, httpHeaders, method, url });

const result = await verifySignatureHeader({ verifier, url, method, httpHeaders, body });
```

Usage of these crypto primitives is not required, and acceptable substitute sign/verify functions for your applications
can be used instead. The SignRequest and VerifyRequest functions use these directly, so they should not be used if
you're intending to use or implement your own crypto.

## Security Policy

Please see our [security policy](./SECURITY.md) for additional details about responsible disclosure of security related
issues.

---

<p align="center"><a href="https://mattr.global" target="_blank"><img height="40px" src ="./docs/assets/mattr-logo-tm.svg"></a></p><p align="center">Copyright © MATTR Limited. <a href="./LICENSE">Some rights reserved.</a><br/>“MATTR” is a trademark of MATTR Limited, registered in New Zealand and other countries.</p>
