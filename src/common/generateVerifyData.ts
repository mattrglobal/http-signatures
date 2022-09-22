/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { err, ok, Result } from "neverthrow";
import { equals, keys, length, map, not, pipe, toLower, uniq } from "ramda";
import { InnerList } from "structured-headers";
import urlParser from "url";

import { VerifyData, VerifyDataEntry } from "./types";

export const reduceKeysToLowerCase = <T extends Record<string, unknown>>(obj: T): Record<string, T[keyof T]> =>
  Object.entries(obj).reduce((acc, [k, v]) => ({ ...acc, [k.toLowerCase()]: v }), {});
const isObjectKeysIgnoreCaseDuplicated = (obj: Record<string, unknown>): boolean =>
  pipe(keys, map(toLower), uniq, length, equals(keys(obj).length), not)(obj);

type RequiredSignatureData = {
  readonly "@request-target": string;
  readonly "@method": string;
  readonly host: string;
  key?: string;
};

type GenerateVerifyDataEntriesOptions = {
  readonly method: string;
  readonly url: string;
  readonly httpHeaders: { readonly [key: string]: string | string[] | undefined };
  readonly existingSignatureKey?: string;
};
/**
 * Create an array of entries out of an object required for a signature
 * consisting of http headers, host, @request-target and @method fields
 * note we return it as entries to guarantee order consistency
 */
export const generateVerifyData = (options: GenerateVerifyDataEntriesOptions): Result<VerifyData, string> => {
  const { url, httpHeaders, method, existingSignatureKey } = options;
  const { host, path } = urlParser.parse(url);

  // Checks if a header key is duplicated with a different case eg. no instances of key and kEy
  if (isObjectKeysIgnoreCaseDuplicated(httpHeaders)) {
    return err("Duplicate case insensitive header keys detected, specify an array of values instead");
  }

  if (host === null || path === null) {
    return err("Cannot resolve host and path from url");
  }

  const lowerCaseHttpHeaders = reduceKeysToLowerCase(httpHeaders);

  // Custom fields required by the specification
  const requiredSignatureData: RequiredSignatureData = {
    ["@request-target"]: path,
    ["@method"]: method.toUpperCase(),
    host,
    ...("signature" in lowerCaseHttpHeaders && existingSignatureKey && { key: existingSignatureKey }), // if a signature header is included for a previous signature, its ID should be included in the covered fields labelled 'key'
  };

  const dataToSign: VerifyData = {
    ...requiredSignatureData,
    ...lowerCaseHttpHeaders,
  };

  return ok(dataToSign);
};

export type GenereateSignatureParamsOptions = {
  readonly data: VerifyDataEntry[];
  readonly keyid: string;
  readonly alg: string;
  readonly created: number;
  readonly expires?: number;
  readonly nonce?: string;
  readonly context?: string;
  readonly existingSignatureKey?: string;
};
export const generateSignatureParams = (options: GenereateSignatureParamsOptions): InnerList => {
  const { data, keyid, alg, existingSignatureKey, created, expires, nonce, context } = options;

  return [
    data.map(([key]: VerifyDataEntry) =>
      key == "signature" && existingSignatureKey ? [key, new Map([["key", existingSignatureKey]])] : [key, new Map()]
    ), // covered fields
    new Map<string, string | number>([
      // signature params
      ["alg", alg],
      ["keyid", keyid],
      ["created", created],
      ...(expires ? [["expires", expires] as const] : []),
      ...(nonce ? [["nonce", nonce] as const] : []),
      ...(context ? [["context", context] as const] : []),
    ]),
  ];
};
