/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { err, ok, Result } from "neverthrow";
import { equals, keys, length, map, not, pipe, toLower, uniq } from "ramda";
import { Item, Parameters } from "structured-headers";
import urlParser from "url";

import { VerifyDataEntry } from "./types";

export const reduceKeysToLowerCase = <T extends Record<string, unknown>>(obj: T): Record<string, T[keyof T]> =>
  Object.entries(obj).reduce((acc, [k, v]) => ({ ...acc, [k.toLowerCase()]: v }), {});
const isObjectKeysIgnoreCaseDuplicated = (obj: Record<string, unknown>): boolean =>
  pipe(keys, map(toLower), uniq, length, equals(keys(obj).length), not)(obj);

type GenerateVerifyDataEntriesOptions = {
  readonly coveredFields: [string, Parameters][];
  readonly statusCode?: number;
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
export const generateVerifyData = (options: GenerateVerifyDataEntriesOptions): Result<VerifyDataEntry[], string> => {
  const { coveredFields, url, httpHeaders, method, statusCode } = options;
  const { path, pathname, query: queryString, host, protocol } = urlParser.parse(url);
  const { query: queryObj } = urlParser.parse(url, true);

  // Checks if a header key is duplicated with a different case eg. no instances of key and kEy
  if (isObjectKeysIgnoreCaseDuplicated(httpHeaders)) {
    return err("Duplicate case insensitive header keys detected, specify an array of values instead");
  }

  const coveredFieldNames = coveredFields.map((item) => item[0]);

  if (
    host === null ||
    pathname === null ||
    path == null ||
    protocol == null ||
    (coveredFieldNames.includes("@query") && queryString == null) ||
    (coveredFieldNames.includes("@status") && statusCode == undefined)
  ) {
    return err("Cannot resolve host, path, protocol and/or query from url");
  }

  const lowerCaseHttpHeaders = reduceKeysToLowerCase(httpHeaders);

  const entries: VerifyDataEntry[] = coveredFields.reduce(
    (entries: VerifyDataEntry[], field: Item): VerifyDataEntry[] => {
      const [fieldName, fieldParams] = field;

      let newEntry: VerifyDataEntry;
      let queryParamName: string | undefined;
      if ((fieldName as string).startsWith("@")) {
        // derived components
        switch (fieldName) {
          case "@request-target":
            newEntry = [field, path];
            break;
          case "@method":
            newEntry = [field, method.toUpperCase()];
            break;
          case "@authority":
            newEntry = [field, host];
            break;
          case "@target-uri":
            newEntry = [field, url];
            break;
          case "@path":
            newEntry = [field, pathname];
            break;
          case "@query":
            newEntry = [field, `?${queryString}` ?? ""];
            break;
          case "@scheme":
            newEntry = [field, protocol];
            break;
          case "@query-param":
            queryParamName = fieldParams.get("name") as string | undefined;
            newEntry = queryParamName ? [field, queryObj[queryParamName]] : [field, ""];
            break;
          case "@status":
            newEntry = [field, statusCode];
            break;
          default:
            newEntry = [field, ""];
        }
      } else {
        newEntry = [field, lowerCaseHttpHeaders[fieldName as string]];
      }
      return [...entries, newEntry];
    },
    []
  );

  return ok(entries);
};
