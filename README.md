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
    headers: headers,
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

---

<p align="center"><a href="https://mattr.global" target="_blank"><img height="40px" src ="./docs/assets/mattr-logo-tm.svg"></a></p><p align="center">Copyright © MATTR Limited. <a href="./LICENSE">Some rights reserved.</a><br/>“MATTR” is a trademark of MATTR Limited, registered in New Zealand and other countries.</p>
