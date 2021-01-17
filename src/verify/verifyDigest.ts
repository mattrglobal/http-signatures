/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { equals, isNil, pipe } from "ramda";

import { generateDigest } from "../common";

export const verifyDigest = (digest: string | string[], body: object | string | undefined): boolean => {
  if (Array.isArray(digest)) {
    return false;
  }

  if (isNil(body)) {
    return false;
  }

  return pipe(generateDigest, equals(digest))(body);
};
