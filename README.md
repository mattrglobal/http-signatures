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

With axios config:

```typescript
const createSignedRequest = async (config: AxiosRequestConfig): Promise<AxiosRequestConfig> => {
  const signer = { sign: signWithEd25519, keyId: "key-1" };
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

## Security Policy

Please see our [security policy](./SECURITY.md) for additional details about responsible disclosure of security related
issues.

---

<p align="center"><a href="https://mattr.global" target="_blank"><img height="40px" src ="./docs/assets/mattr-logo-tm.svg"></a></p><p align="center">Copyright © MATTR Limited. <a href="./LICENSE">Some rights reserved.</a><br/>“MATTR” is a trademark of MATTR Limited, registered in New Zealand and other countries.</p>
