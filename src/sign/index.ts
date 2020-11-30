/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { encodeURLSafe as base64URLEncode } from "@stablelib/base64";
import { pipe } from "ramda";
import urlParser from "url";

import { joinWithSpace, lowerCaseObjectKeys, generateDigest, stringToBytes } from "../common";

const generateObjectEntriesString = (entries: [string, string | number][]): string =>
  entries
    .map(([key, value]) => {
      const trimmedValue = typeof value === "string" ? value.trim() : value;
      return `${key}: ${trimmedValue}`;
    })
    .join("\n");

/**
 * Generate a string representation of an object and return the bytes of that string for signing
 * @see https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-2.3
 */
const generateBytesToSign = pipe(lowerCaseObjectKeys, Object.entries, generateObjectEntriesString, stringToBytes);

/**
 * Generate a string containing all the keys of an object separated by a space
 * @see https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-2.1.6
 */
const generateHeadersListString = pipe(lowerCaseObjectKeys, Object.keys, joinWithSpace);

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
  readonly headers: { readonly [key: string]: string };
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
    headers,
    body,
    url,
  } = options;
  const { host, path } = urlParser.parse(url);

  if (headers["Content-Type"] === undefined && body !== undefined) {
    return Promise.reject(Error("content-type header must be defined if a body is defined"));
  }

  const created = Math.round(Date.now() / 1000);
  const dataToSign = {
    ["(request-target)"]: joinWithSpace([method.toLowerCase(), path]),
    ["(created)"]: created,
    host,
    ...(body ? { digest: generateDigest(body) } : {}),
    ...headers,
  };

  const bytesToSign = generateBytesToSign(dataToSign);
  const signature = await sign(bytesToSign);
  const headersListString = generateHeadersListString(dataToSign);
  const signatureHeaderValue = `keyId="${keyId}",algorithm="${algorithm}",created=${created},headers="${headersListString}",signature="${base64URLEncode(
    signature
  )}"`;

  return {
    signature: signatureHeaderValue,
    ...(dataToSign.digest ? { digest: dataToSign.digest } : {}),
  };
};
