/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { err, ok, Result } from "neverthrow";
import { equals, keys, length, map, not, pipe, toLower, uniq } from "ramda";
import { InnerList, Parameters } from "structured-headers";
import urlParser from "url";

import { VerifyDataEntry } from "./types";

export const reduceKeysToLowerCase = <T extends Record<string, unknown>>(obj: T): Record<string, T[keyof T]> =>
  Object.entries(obj).reduce((acc, [k, v]) => ({ ...acc, [k.toLowerCase()]: v }), {});
const isObjectKeysIgnoreCaseDuplicated = (obj: Record<string, unknown>): boolean =>
  pipe(keys, map(toLower), uniq, length, equals(keys(obj).length), not)(obj);

type GenerateVerifyDataEntriesOptions = {
  readonly coveredFields: [string, Parameters][];
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
  const { coveredFields, url, httpHeaders, method } = options;
  const { path, pathname, query: queryString, host } = urlParser.parse(url);
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
    (coveredFieldNames.includes("@query") && queryString == null)
  ) {
    return err("Cannot resolve host, path and/or query from url");
  }

  const lowerCaseHttpHeaders = reduceKeysToLowerCase(httpHeaders);

  const entries: VerifyDataEntry[] = coveredFields.reduce(
    (entries: VerifyDataEntry[], field: [string, Parameters]): VerifyDataEntry[] => {
      const fieldName = field[0].toLowerCase();

      let newEntry: VerifyDataEntry;
      let queryParamName: string | undefined;
      if (fieldName.startsWith("@")) {
        // derived components
        switch (fieldName) {
          case "@request-target":
            newEntry = [fieldName, path];
            break;
          case "@method":
            newEntry = [fieldName, method.toUpperCase()];
            break;
          case "@authority":
            newEntry = [fieldName, host];
            break;
          case "@target-uri":
            newEntry = [fieldName, url];
            break;
          case "@path":
            newEntry = [fieldName, pathname];
            break;
          case "@query":
            newEntry = [fieldName, `?${queryString}` ?? ""];
            break;
          case "@query-param":
            queryParamName = field[1].get("name") as string | undefined;
            newEntry = queryParamName ? [fieldName, queryObj[queryParamName]] : [fieldName, ""];
            break;
          default:
            newEntry = [fieldName, ""];
        }
      } else {
        newEntry = [fieldName, lowerCaseHttpHeaders[fieldName]];
      }
      return [...entries, newEntry];
    },
    []
  );
  // TODO implement derived components for scheme, status code

  return ok(entries);
};

export type GenereateSignatureParamsOptions = {
  readonly data: VerifyDataEntry[];
  readonly coveredFields: [string, Parameters][];
  readonly parameters: Parameters;
};
export const generateSignatureParams = (options: GenereateSignatureParamsOptions): InnerList => {
  const { data, coveredFields, parameters } = options;

  return [data.map(([key]: VerifyDataEntry, index: number) => [key, coveredFields[index][1]]), parameters];
};
