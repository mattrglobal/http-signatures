/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { err, ok, Result } from "neverthrow";
import { equals, keys, length, map, not, pipe, toLower, uniq } from "ramda";
import urlParser from "url";

import { VerifyData } from "./types";

import { joinWithSpace } from "./index";

const reduceKeysToLowerCase = (obj: object): object =>
  Object.entries(obj).reduce((acc, [k, v]) => ({ ...acc, [k.toLowerCase()]: v }), {});
const isObjectKeysIgnoreCaseDuplicated = (obj: object): boolean =>
  pipe(keys, map(toLower), uniq, length, equals(keys(obj).length), not)(obj);

type GenerateVerifyDataEntriesOptions = {
  readonly method: string;
  readonly created: number;
  readonly url: string;
  readonly httpHeaders: { readonly [key: string]: string | string[] | undefined };
};
/**
 * Create an array of entries out of an object required for a signature
 * consisting of http headers, host, (request-target) and (created) fields
 * note we return it as entries to guarantee order consistency
 */
export const generateVerifyData = (options: GenerateVerifyDataEntriesOptions): Result<VerifyData, string> => {
  const { url, httpHeaders, created, method } = options;
  const { host, path } = urlParser.parse(url);

  // Checks if a header key is duplicated with a different case eg. no instances of key and kEy
  if (isObjectKeysIgnoreCaseDuplicated(httpHeaders)) {
    return err("Duplicate case insensitive header keys detected, specify an array of values instead");
  }

  if (created > Date.now()) {
    return err("Created date cannot be in the future");
  }

  if (host === null || path === null) {
    return err("Cannot resolve host and path from url");
  }

  // Custom fields required by the specification
  const requiredSignatureData = {
    ["(request-target)"]: joinWithSpace([method.toLowerCase(), path]),
    ["(created)"]: created.toString(),
    host,
  };

  const lowerCaseHttpHeaders = reduceKeysToLowerCase(httpHeaders);
  const dataToSign: VerifyData = {
    ...requiredSignatureData,
    ...lowerCaseHttpHeaders,
  };

  return ok(dataToSign);
};
