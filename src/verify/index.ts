/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { decodeURLSafe as base64URLDecode } from "@stablelib/base64";
import { includes, pick } from "ramda";

import { generateHeadersListString, generateSignatureBytes, generateVerifyDataEntries } from "../common";

type SignatureParams = {
  readonly keyId: string;
  readonly created: number;
  readonly signature: string;
  readonly headers: string;
};
/**
 * Use a regex to get the values of the of fields in the signature string
 * We aren't currently getting the expires
 */
export const getSignatureParams = (signatureHeaderValue: string): SignatureParams => {
  const keyIdMatches: RegExpExecArray | null = /keyId="(.+?)"/.exec(signatureHeaderValue);
  const createdMatches: RegExpExecArray | null = /created=(.+?),/.exec(signatureHeaderValue);
  const headersMatches: RegExpExecArray | null = /headers="(.+?)"/.exec(signatureHeaderValue);
  const signatureMatches: RegExpExecArray | null = /signature="(.+?)"/.exec(signatureHeaderValue);

  if (!keyIdMatches || !createdMatches || !signatureMatches || !headersMatches) {
    throw Error("signature string is missing a required field");
  }
  return {
    keyId: keyIdMatches[1],
    created: Number(createdMatches[1]),
    signature: signatureMatches[1],
    headers: headersMatches[1],
  };
};

export type VerifySignatureHeaderOptions = {
  readonly verifier: {
    /**
     * The function for verifying the signature
     */
    readonly verify: (keyId: string, data: Uint8Array, signature: Uint8Array) => Promise<boolean>;
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
   * Headers of the request
   * httpHeaders is filtered during verification to include only the ones form the signature.
   */
  readonly httpHeaders: { readonly [key: string]: string | string[] | undefined };
};

/**
 * Verifies a signature header
 * @see https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-2.5
 */
export const verifySignatureHeader = async (options: VerifySignatureHeaderOptions): Promise<boolean> => {
  const {
    verifier: { verify },
    method,
    httpHeaders,
    url,
  } = options;

  const { Signature: signatureString } = httpHeaders;
  if (typeof signatureString !== "string") {
    return Promise.reject(new Error("bad signature header - signature header must be a string"));
  }
  const { created, headers, keyId, signature } = getSignatureParams(signatureString);

  // filter entries that aren't part defined in the signature string headers field
  const filterMatchingHeaders = (k: string): boolean => includes(k.toLowerCase(), headers);
  const matchingHeaderKeys = Object.keys(httpHeaders).filter(filterMatchingHeaders);
  const headersToVerify = pick(matchingHeaderKeys, httpHeaders);

  const entriesToVerify = generateVerifyDataEntries({
    created,
    method,
    url,
    httpHeaders: headersToVerify,
  });

  const verifyHeadersString = generateHeadersListString(entriesToVerify);
  if (verifyHeadersString !== headers) {
    return Promise.reject(new Error("signature headers string mismatch"));
  }

  const decodedSignature = base64URLDecode(signature);
  const bytesToVerify = generateSignatureBytes(entriesToVerify);
  return await verify(keyId, bytesToVerify, decodedSignature);
};
