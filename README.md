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
const { headers, protocol, headers, baseUrl, method } = request;
const url = req.protocol + "://" + headers.host + req.baseUrl;
const verifier = { verify: verifyFn };
const options = { verifier, url, method, httpHeaders: headers };

const result = await verifySignatureHeader(options);

if (result.isErr()) {
  return onError(result.error);
}

if (result.isOk()) {
  console.log(`Is verified: ${result.value}`);
}
```
