/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { equals, keys, length, map, not, pipe, toLower, uniq } from "ramda";
import urlParser from "url";

import { VerifyData, VerifyDataEntry } from "./types";

import { joinWithSpace } from "./index";

type GenerateVerifyDataEntriesOptions = {
  readonly method: string;
  readonly created: number;
  readonly url: string;
  readonly httpHeaders: { readonly [key: string]: string | string[] | undefined };
};
/**
 * Generate an array of object entries required for a signature
 * consisting of http headers, host, request target and created fields
 * return it as an entries array to retain the order it was sorted in
 */
export const generateVerifyDataEntries = (options: GenerateVerifyDataEntriesOptions): VerifyDataEntry[] => {
  const { url, httpHeaders, created, method } = options;
  const { host, path } = urlParser.parse(url);

  // Checks if a header key is duplicated with a different case eg. no instances of key and kEy
  const isObjectKeysIgnoreCaseDuplicated = (obj: object): boolean =>
    pipe(keys, map(toLower), uniq, length, equals(keys(obj).length), not)(obj);
  if (isObjectKeysIgnoreCaseDuplicated(httpHeaders)) {
    throw new Error("duplicate case insensitive header keys detected. Specify an array of values instead.");
  }

  if (created > Date.now()) {
    throw new Error("created date cannot be in the future");
  }

  if (httpHeaders.Digest !== undefined && httpHeaders["Content-Type"] === undefined) {
    throw new Error("content-type header must be defined if a body is defined");
  }

  if (host === null || path === null) {
    throw new Error("cannot resolve host and path from url");
  }

  const dataToSign: VerifyData = {
    ["(request-target)"]: joinWithSpace([method.toLowerCase(), path]),
    ["(created)"]: created.toString(),
    host,
    ...httpHeaders,
  };

  return [...Object.entries(dataToSign)].sort();
};
