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

// see https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-2.3
const generateBytesToSign = pipe(lowerCaseObjectKeys, Object.entries, generateObjectEntriesString, stringToBytes);
// Generates a string containing all the keys of an object
const generateHeadersListString = pipe(lowerCaseObjectKeys, Object.keys, joinWithSpace);

export type CreateSignatureHeaderOptions = {
  readonly signer: {
    readonly keyId: string;
    readonly sign: (data: Uint8Array) => Promise<Uint8Array>;
  };
  readonly url: string;
  readonly method: string;
  readonly headers: { readonly [key: string]: string };
  readonly body?: object | string;
};

export const createSignatureHeader = async (
  options: CreateSignatureHeaderOptions
): Promise<{ digest: string; signature: string }> => {
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
    digest: dataToSign.digest,
    signature: signatureHeaderValue,
  };
};
