![Mattr logo](./docs/assets/mattr-black.svg)

# http-signatures

## Background

This library is an implementation of the
[HTTP Signatures IETF specification](https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-13.html) with
some added utils for ease of use.

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

    // Using a keymap and default cryptographic functions

    const server = http.createServer((req, res) => {
      const keyMap = { key1: { key: myEcdsap256PublicKey }};

      let reqdata = "";
      req.on("data", (chunk) => {
        reqdata += chunk;
      });

      req.on("end", () => {
        verifyRequest({ verifier: {keyMap}, request: req, data: reqdata }).then((verifyResult) => {
          if(verifyResult.isErr()){
            onError(verifyResult.error);
          }
          if(verifyResult.isOk()){
            console.log(`Is verified: ${verifyResult.value}`);
          }
        });
      }
    }

    // Using custom cryptographic functions

    const myVerifyFn = async (signatureParams, data, signature) => {
      // Use signatureParams.alg and signatureParams.keyid to determine appropriate cryptographic methods
      return verifyResult
    }

    const server = http.createServer((req, res) => {
      let reqdata = "";
      req.on("data", (chunk) => {
        reqdata += chunk;
      });

      req.on("end", () => {
        verifyRequest({ verifier: { verify: myVerifyFn }, request: req, data: reqdata }).then((verifyResult) => {
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
// To ensure it can produce the same HTTP content digest, the raw HTTP content should be used for the body to avoid any lossy transform by a body parser middleware.

let app = express();

app.use(
  bodyParser.json({
    verify: function (req, res, buf) {
      if (buf && buf.length) {
        req.rawBody = buf.toString("utf8");
      }
    },
  })
);

app.post("/test", (req, res) => {
  const keyMap = { key1: { key: myEcdsap256PublicKey } };
  verifyRequest({
    request: req,
    verifier: { keyMap },
    data: req.rawBody,
  }).then((verifyResult) => {
    if (verifyResult.isErr()) {
      onError(verifyResult.error);
    }
    if (verifyResult.isOk()) {
      console.log(`Is verified: ${verifyResult.value}`);
    }
  });
});

// In the case of a JSON parser, as long as there's no special replacer that would manipulate the original body, it would also be fine to stringify it back to the same HTTP body content.

const keyMap = { key1: { key: myEcdsap256PublicKey } };
let app = express();

app.use(bodyParser.json());

app.post("/test", (req, res) => {
  verifyRequest({
    request: req,
    verifier: { keyMap },
    data: req.body,
  }).then((verifyResult) => {
    if (verifyResult.isErr()) {
      onError(verifyResult.error);
    }
    if (verifyResult.isOk()) {
      console.log(`Is verified: ${verifyResult.value}`);
    }
  });
});

// or using verifySignatureHeader directly:

const { headers, protocol, baseUrl, method, body } = request;
const url = req.protocol + "://" + headers.host + req.baseUrl;
const keyMap = { key1: { key: myEcdsap256PublicKey } };
const options = { verifier: { keyMap }, url, method, httpHeaders: headers, body };

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
import { AlgorithmTypes, createSignatureHeader } from "mattrglobal/http-signatures";

const expires = 1665107239;
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

// produces a signature with the following signature-params: (@request-target @method)created=1630109947;expires=1665107239;nonce="test-nonce";alg="ecdsa-p256-sha256";keyid='key-abc';tag='application-specific-context'
```

The 'created' parameter will always be added during the signature's creation, and does not need to be provided as an
argument.

A full list of signature parameters is available here:
https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-13.html#name-signature-parameters

### Signature Algorithms

A full list of algorithms is available here:
https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-13.html#name-initial-contents

### Cryptography

Cryptographic primitives are available for each of the signature algorithms. They are implemented using the native node
crypto library.

```typescript
import { verifyDefault, algMap, AlgorithmTypes } from "mattrglobal/http-signatures";

const ecdsaP256Sha256 = algMap[AlgorithmTypes["ecdsa-p256-sha256"]];

signer = { keyid: "key1", sign: ecdsaP256Sha256.sign(myPrivateKey) };
verifier = { verify: verifyDefault({ key1: { key: myPublicKey } }) };

const signatureData = await createSignatureHeader({ signer, httpHeaders, method, url });

const result = await verifySignatureHeader({ verifier, url, method, httpHeaders, body });
```

Usage of these crypto primitives is not required, and acceptable substitute sign/verify functions for your applications
can be used instead.

## Security Policy

Please see our [security policy](./SECURITY.md) for additional details about responsible disclosure of security related
issues.

---

<p align="center"><a href="https://mattr.global" target="_blank"><img height="40px" src ="./docs/assets/mattr-logo-tm.svg"></a></p><p align="center">Copyright © MATTR Limited. <a href="./LICENSE">Some rights reserved.</a><br/>“MATTR” is a trademark of MATTR Limited, registered in New Zealand and other countries.</p>
