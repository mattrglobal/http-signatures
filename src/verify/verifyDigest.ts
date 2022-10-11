/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { equals, isNil, pipe } from "ramda";

import { generateDigest } from "../common";

export const verifyDigest = (
  digest: string | string[],
  body: Record<string, unknown> | string | undefined,
  digestAlgorithm: string
): boolean => {
  if (Array.isArray(digest)) {
    return false;
  }

  if (isNil(body)) {
    return false;
  }

  return pipe(generateDigest, equals(digest))(body, digestAlgorithm);
};
