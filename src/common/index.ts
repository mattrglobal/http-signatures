/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { Buffer } from "buffer";
import { join, pipe, reduce } from "ramda";

export const joinWithSpace = join(" ");
export const stringToBytes = (str: string): Uint8Array => Uint8Array.from(Buffer.from(str, "utf-8"));
const reduceKeysToLowerCase = reduce(
  (acc: object, [key, value]: [string, unknown]) => ({
    ...acc,
    [key.toLowerCase()]: value,
  }),
  {}
);
export const lowerCaseObjectKeys = pipe(Object.entries, reduceKeysToLowerCase);
export * from "./digest";
