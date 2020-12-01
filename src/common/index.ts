/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { Buffer } from "buffer";
import { join, map, pipe, toLower } from "ramda";

import { VerifyDataEntry } from "./types";

export const joinWithSpace = join(" ");
export const stringToBytes = (str: string): Uint8Array => Uint8Array.from(Buffer.from(str, "utf-8"));

/**
 * Generate a string containing all the keys of an object separated by a space
 * Order that was used in signing must be preserved in this list of headers
 * @see https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-2.1.6
 */
const mapEntryKeys = map((entry: VerifyDataEntry) => entry[0]);
export const generateHeadersListString = pipe(mapEntryKeys, joinWithSpace, toLower);

/**
 * Generate a string representation of an object and return the bytes of that string for signing
 * @see https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-2.3
 */
const generateSignatureStringFromEntries = (entries: VerifyDataEntry[]): string =>
  entries
    .map(([key, value]) => {
      const processedValue = Array.isArray(value) ? value.join(", ").trim() : value?.trim();
      return `${key}: ${processedValue}`;
    })
    .join("\n");
export const generateSignatureBytes = pipe(generateSignatureStringFromEntries, stringToBytes);

export * from "./generateDigest";
export * from "./generateVerifyDataEntries";
