/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import { encode as encodeBase64 } from "@stablelib/base64";
import { hash as sha256Hash } from "@stablelib/sha256";
import { hash as sha512Hash } from "@stablelib/sha512";
import jsonCanonicalize from "canonicalize";
import { pipe } from "ramda";

import { stringToBytes } from "./index";

const canonicalize = (data: Record<string, unknown> | string): string =>
  // Don't support canonicalize on strings
  typeof data === "string" ? data : jsonCanonicalize(data) ?? "";

const generateSha256Hash = pipe(canonicalize, stringToBytes, sha256Hash, encodeBase64);
const generateSha512Hash = pipe(canonicalize, stringToBytes, sha512Hash, encodeBase64);

// Only support a SHA-256 or SHA-512 digest for now
export const generateDigest = (body: Record<string, unknown> | string, digestAlg: string): string => {
  switch (digestAlg.toLowerCase()) {
    case "sha-512":
      return `sha-512=:${generateSha512Hash(body)}:`;
    case "sha-256":
      return `sha-256=:${generateSha256Hash(body)}:`;
    default:
      return "error";
  }
};
