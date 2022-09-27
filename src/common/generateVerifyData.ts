/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { err, ok, Result } from "neverthrow";
import { equals, keys, length, map, not, pipe, toLower, uniq } from "ramda";
import { InnerList, Parameters } from "structured-headers";
import urlParser from "url";

import { VerifyData, VerifyDataEntry } from "./types";

export const reduceKeysToLowerCase = <T extends Record<string, unknown>>(obj: T): Record<string, T[keyof T]> =>
  Object.entries(obj).reduce((acc, [k, v]) => ({ ...acc, [k.toLowerCase()]: v }), {});
const isObjectKeysIgnoreCaseDuplicated = (obj: Record<string, unknown>): boolean =>
  pipe(keys, map(toLower), uniq, length, equals(keys(obj).length), not)(obj);

type DerivedComponents = {
  readonly "@request-target"?: string;
  readonly "@method"?: string;
  key?: string;
};

type GenerateVerifyDataEntriesOptions = {
  readonly coveredFieldNames: string[];
  readonly method: string;
  readonly url: string;
  readonly httpHeaders: { readonly [key: string]: string | string[] | undefined };
  readonly existingSignatureKey?: string;
};
/**
 * Create an array of entries consisting of http headers and derived components
 * (as per https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-12.html#name-derived-components)
 * note we return it as entries to guarantee order consistency
 */
export const generateVerifyData = (options: GenerateVerifyDataEntriesOptions): Result<VerifyData, string> => {
  const { coveredFieldNames, url, httpHeaders, method, existingSignatureKey } = options;
  const { host, path, query } = urlParser.parse(url);

  // Checks if a header key is duplicated with a different case eg. no instances of key and kEy
  if (isObjectKeysIgnoreCaseDuplicated(httpHeaders)) {
    return err("Duplicate case insensitive header keys detected, specify an array of values instead");
  }

  if (host === null || path === null) {
    return err("Cannot resolve host and path from url");
  }

  const lowerCaseHttpHeaders = reduceKeysToLowerCase(httpHeaders);

  const filtered = Object.keys(lowerCaseHttpHeaders)
    .filter((key: string) => coveredFieldNames.includes(key))
    .reduce((obj: { [key: string]: string | string[] | undefined }, key: string) => {
      return {
        [key]: lowerCaseHttpHeaders[key],
        ...obj,
      };
    }, {});

  const derivedComponents: DerivedComponents = {
    ...(coveredFieldNames.includes("@request-target") && { ["@request-target"]: path }),
    ...(coveredFieldNames.includes("@method") && { "@method": method.toUpperCase() }),
    ...(coveredFieldNames.includes("@authority") && { "@authority": host }),
    ...(coveredFieldNames.includes("@target-uri") && { "@target-uri": url }),
    ...(coveredFieldNames.includes("@path") && { "@path": path }),
    ...(coveredFieldNames.includes("@query") && { "@query": query }),
    ...(coveredFieldNames.includes("signature") && existingSignatureKey && { key: existingSignatureKey }),
  };
  // TODO implement derived components for scheme, query parameters, status code

  const dataToSign: VerifyData = {
    ...derivedComponents,
    ...filtered,
  };

  return ok(dataToSign);
};

export type GenereateSignatureParamsOptions = {
  readonly data: VerifyDataEntry[];
  readonly parameters: Parameters;
  readonly existingSignatureKey?: string;
};
export const generateSignatureParams = (options: GenereateSignatureParamsOptions): InnerList => {
  const { data, existingSignatureKey, parameters } = options;

  return [
    data.map(([key]: VerifyDataEntry) =>
      key == "signature" && existingSignatureKey ? [key, new Map([["key", existingSignatureKey]])] : [key, new Map()]
    ),
    parameters,
  ];
};
