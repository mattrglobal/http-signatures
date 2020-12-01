/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { encodeURLSafe as base64URLEncode } from "@stablelib/base64";

import {
  generateDigest,
  generateHeadersListString,
  generateSignatureBytes,
  generateVerifyDataEntries,
} from "../common";

export type CreateSignatureHeaderOptions = {
  readonly signer: {
    /**
     * The key id used for creating the signature. This will be added to the signature string and used in verification
     */
    readonly keyId: string;
    /**
     * The function for signing the data with the hs2019 algorithm
     */
    readonly sign: (data: Uint8Array) => Promise<Uint8Array>;
  };
  /**
   * Full url of the request including query parameters
   */
  readonly url: string;
  /**
   * The HTTP request method of the request
   */
  readonly method: string;
  /**
   * Headers and their values to include in the signing
   * The keys of these headers will be appended to the signature string for verification
   */
  readonly httpHeaders: { readonly [key: string]: string | string[] | undefined };
  /**
   * The body of the request
   */
  readonly body?: object | string;
};

/**
 * Creates a signature header to be appended as a header on a request
 * A digest header will be returned if a body was included. This also needs to be appended to the request headers.
 * @see https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-4
 */
export const createSignatureHeader = async (
  options: CreateSignatureHeaderOptions
): Promise<{ digest?: string; signature: string }> => {
  const algorithm = "hs2019";
  const {
    signer: { keyId, sign },
    method,
    httpHeaders,
    body,
    url,
  } = options;

  // Append the digest if necessary
  const digest = body ? generateDigest(body) : undefined;
  const created = Math.round(Date.now() / 1000);
  const entriesToSign = generateVerifyDataEntries({
    httpHeaders: {
      ...httpHeaders,
      ...(digest ? { Digest: digest } : {}),
    },
    url,
    method,
    created,
  });
  const bytesToSign = generateSignatureBytes(entriesToSign);

  const signature = await sign(bytesToSign);

  const signatureBase64 = base64URLEncode(signature);
  const headersListString = generateHeadersListString(entriesToSign);
  const signatureHeaderValue = `keyId="${keyId}",algorithm="${algorithm}",created=${created},headers="${headersListString}",signature="${signatureBase64}"`;

  return {
    signature: signatureHeaderValue,
    digest,
  };
};
