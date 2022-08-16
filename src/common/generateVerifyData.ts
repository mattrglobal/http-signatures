/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { err, ok, Result } from "neverthrow";
import { equals, keys, length, map, not, pipe, toLower, uniq, toPairs, join } from "ramda";
import urlParser from "url";

import { VerifyData, VerifyDataEntry } from "./types";

import { joinWithSpace } from "./index";

/**
 * Generate a string containing all the keys of an object separated by a space
 * The order of the object properties that was used in signing must be preserved in this list of headers
 * @see https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-2.1.6
 */
const mapEntryKeys = map(([key]: VerifyDataEntry) => key);

export const reduceKeysToLowerCase = <T extends Record<string, unknown>>(obj: T): Record<string, T[keyof T]> =>
  Object.entries(obj).reduce((acc, [k, v]) => ({ ...acc, [k.toLowerCase()]: v }), {});
const isObjectKeysIgnoreCaseDuplicated = (obj: Record<string, unknown>): boolean =>
  pipe(keys, map(toLower), uniq, length, equals(keys(obj).length), not)(obj);

type GenerateVerifyDataEntriesOptions = {
  readonly method: string;
  readonly url: string;
  readonly httpHeaders: { readonly [key: string]: string | string[] | undefined };
};
/**
 * Create an array of entries out of an object required for a signature
 * consisting of http headers, host, (request-target) and (created) fields
 * note we return it as entries to guarantee order consistency
 */
export const generateVerifyData = (options: GenerateVerifyDataEntriesOptions): Result<VerifyData, string> => {
  const { url, httpHeaders, method } = options;
  const { host, path } = urlParser.parse(url);

  // Checks if a header key is duplicated with a different case eg. no instances of key and kEy
  if (isObjectKeysIgnoreCaseDuplicated(httpHeaders)) {
    return err("Duplicate case insensitive header keys detected, specify an array of values instead");
  }

  if (host === null || path === null) {
    return err("Cannot resolve host and path from url");
  }

  // Custom fields required by the specification
  const requiredSignatureData = {
    ["@request-target"]: path,
    ["@method"]: method.toUpperCase(),
    host,
  };

  const lowerCaseHttpHeaders = reduceKeysToLowerCase(httpHeaders);
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
};
export const generateSignatureParams = (options: GenereateSignatureParamsOptions): string => {
  const { data, keyid, alg } = options;
  const created = Math.round(Date.now() / 1000);
  const headersParam = pipe(
    map(([key]: VerifyDataEntry) => `"${key}"`),
    joinWithSpace
  )(data);

  const otherParams = pipe(
    map(([k, v]) => `${k}=${typeof v === "number" ? v : `"${v}"`}`),
    join(";")
  )(toPairs({ alg, keyid, created }));
  return `(${headersParam});${otherParams}`;
};
