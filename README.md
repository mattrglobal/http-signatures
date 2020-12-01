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

  const { digest, signature } = await createSignatureHeader({
    signer,
    headers: headers,
    method,
    url,
    body: data,
  });
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

try {
  const verified = await verifySignatureHeader(options);
} catch (error) {
  console.log("There was an error verifying the signature");
}
```
