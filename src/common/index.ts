/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { decodeURLSafe } from "@stablelib/base64";
import { Buffer } from "buffer";
import { err, ok, Result } from "neverthrow";
import { join, pipe, split } from "ramda";

import { VerifyDataEntry } from "./types";

export const splitWithSpace = split(" ");
export const joinWithSpace = join(" ");
export const stringToBytes = (str: string): Uint8Array => Uint8Array.from(Buffer.from(str, "utf-8"));

export const decodeBase64Url = (bytes: string): Result<Uint8Array, string> => {
  try {
    return ok(decodeURLSafe(bytes));
  } catch (error) {
    return err("Failed to decode base64 bytes");
  }
};
/**
 * Generate a string representation of an object and return the bytes of that string for signing
 * We need to use entries so we can guarantee the order of the keys when iterated on
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
export * from "./generateVerifyData";
export * from "./generateSortedVerifyDataEntries";
export * from "./types";
