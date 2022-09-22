/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { errAsync, okAsync, ResultAsync } from "neverthrow";
import { includes, pickBy, toLower, values } from "ramda";

import {
  decodeBase64,
  generateSignatureBytes,
  generateSortedVerifyDataEntries,
  generateVerifyData,
  HttpHeaders,
  reduceKeysToLowerCase,
} from "../common";
import { getSignatureData } from "../common";
import { VerifySignatureHeaderError } from "../errors";

import { verifyDigest } from "./verifyDigest";

export type VerifySignatureHeaderOptions = {
  readonly verifier: {
    /**
     * The function for verifying the signature
     */
    readonly verify: (keyid: string, data: Uint8Array, signature: Uint8Array) => Promise<boolean>;
  };
  /**
   * Full url of the request including query parameters
   */
  readonly url: string;
  /**
   * The HTTP request method of the request
   */
  readonly method: string;
  /**
   * Headers of the request
   * httpHeaders is filtered during verification to include only the ones form the signature.
   */
  readonly httpHeaders: HttpHeaders;
  /**
   * The body of the request
   */
  readonly body?: Record<string, unknown> | string;
};

/**
 * Verifies a signature header
 * Anything wrong with the format will return an error, an exception thrown within verify will return an error
 * Otherwise an ok is returned with verified true or false
 * @see https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-2.5
 */
export const verifySignatureHeader = (
  options: VerifySignatureHeaderOptions
): ResultAsync<boolean, VerifySignatureHeaderError> => {
  const {
    verifier: { verify },
    method,
    httpHeaders,
    url,
    body,
  } = options;

  const verifications: Promise<boolean>[] = [];

  try {
    // need to make sure signature header is in lower case
    // SuperTest set() convert header to lower case
    const lowerCaseHttpHeaders = reduceKeysToLowerCase(httpHeaders);
    const { signature: signatureString, "signature-input": signatureInputString } = lowerCaseHttpHeaders;
    if (typeof signatureString !== "string" || typeof signatureInputString !== "string") {
      return okAsync(false);
    }
    const getSignatureDataResult = getSignatureData(signatureString, signatureInputString);
    if (getSignatureDataResult.isErr()) {
      return okAsync(false);
    }

    const signatureSet = getSignatureDataResult.value;

    for (const signatureId in signatureSet) {
      const { coveredFields: coveredFields = [], keyid, signature } = signatureSet[signatureId];

      // filter http headers that aren't defined in the signature string headers field in order to create accurate verifyData
      const isMatchingHeader = (value: unknown, key: keyof HttpHeaders): boolean =>
        includes(toLower(`${key}`), coveredFields);
      const httpHeadersToVerify = pickBy<HttpHeaders, HttpHeaders>(isMatchingHeader, httpHeaders);

      const verifyDataRes = generateVerifyData({
        method,
        url,
        httpHeaders: httpHeadersToVerify,
      });
      if (verifyDataRes.isErr()) {
        return okAsync(false);
      }
      const { value: verifyData } = verifyDataRes;

      const digest = verifyData["digest"];
      // Verify the digest if it's present
      if (digest !== undefined && !verifyDigest(digest, body)) {
        return okAsync(false);
      }

      const sortedEntriesRes = generateSortedVerifyDataEntries(verifyData, coveredFields);
      if (sortedEntriesRes.isErr()) {
        return okAsync(false);
      }
      const { value: sortedEntries } = sortedEntriesRes;

      const bytesToVerify = generateSignatureBytes(sortedEntries);
      const decodedSignatureRes = decodeBase64(signature);

      if (decodedSignatureRes.isErr()) {
        return okAsync(false);
      }
      const { value: decodedSignature } = decodedSignatureRes;

      // should not return!!
      // needs to add to a list

      verifications.push(verify(keyid, bytesToVerify, decodedSignature));
    }

    return ResultAsync.fromPromise(
      Promise.all(verifications).then((arr) => arr.reduce((acc, val) => acc && !!val, true)),
      () => ({
        type: "VerifyFailed",
        message: "Failed to verify signature header",
      })
    );
  } catch (error) {
    return errAsync({
      type: "VerifyFailed",
      message: "An error occurred when verifying signature header",
    });
  }
};
