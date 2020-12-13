/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { encodeURLSafe as encodeBase64Url } from "@stablelib/base64";
import { hash } from "@stablelib/sha256";
import jsonCanonicalize from "canonicalize";
import { concat, pipe } from "ramda";

import { stringToBytes } from "./index";

const canonicalize = (data: object | string): string =>
  // Don't support canonicalize on strings
  typeof data === "string" ? data : jsonCanonicalize(data) ?? "";

const generateHash = pipe(canonicalize, stringToBytes, hash, encodeBase64Url);

// Only support a SHA-256 digest for now
export const generateDigest = (body: object | string): string => concat("SHA-256=", generateHash(body));
