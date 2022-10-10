/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { decode as base64Decode } from "@stablelib/base64";
import { Buffer } from "buffer";
import { JsonWebKey } from "crypto";
import { err, ok, Result } from "neverthrow";
import { join, pipe, split } from "ramda";
import { serializeItem } from "structured-headers";

import { AlgorithmTypes } from "../sign";

import { VerifyDataEntry } from "./types";

export const splitWithSpace = split(" ");
export const joinWithSpace = join(" ");
export const stringToBytes = (str: string): Uint8Array => Uint8Array.from(Buffer.from(str, "utf-8"));

export const decodeBase64 = (bytes: string): Result<Uint8Array, string> => {
  try {
    return ok(base64Decode(bytes));
  } catch (error) {
    return err("Failed to decode base64 bytes");
  }
};
/**
 * Generate a string representation of an object and return the bytes of that string for signing
 * We need to use entries so we can guarantee the order of the keys when iterated on
 * @see https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-2.3
 */
const generateSignatureBase = (entries: VerifyDataEntry[]): string =>
  entries
    .map(([item, value]) => {
      const processedValue = Array.isArray(value)
        ? value.join(", ").trim()
        : typeof value == "string"
        ? value?.trim()
        : value;
      return `${serializeItem(item)}: ${processedValue}`;
    })
    .join("\n");
export const generateSignatureBytes = pipe(
  generateSignatureBase,
  (v) => {
    return v;
  },
  stringToBytes
);

export const getAlgFromJwk = (jwk: JsonWebKey): AlgorithmTypes | undefined => {
  switch (jwk.kty) {
    case "EC":
      if (jwk.crv == "P-256") {
        return AlgorithmTypes["ecdsa-p256-sha256"];
      }
      if (jwk.crv == "P-384") {
        return AlgorithmTypes["ecdsa-p384-sha384"];
      }
      return undefined;
    case "RSA":
      // TODO implement logic for determining appropriate rsa alg from jwk input
      return undefined;

    case "OKP":
      return AlgorithmTypes.ed25519;

    case "oct":
      return AlgorithmTypes["hmac-sha256"];

    default:
      return undefined;
  }
};

export * from "./generateDigest";
export * from "./generateVerifyData";
export * from "./getSignatureData";
export * from "./types";
