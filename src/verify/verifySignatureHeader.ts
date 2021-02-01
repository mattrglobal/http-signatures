/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import Debug from "debug";
import { errAsync, okAsync, ResultAsync } from "neverthrow";
import { includes, pickBy, toLower } from "ramda";

import {
  decodeBase64Url,
  generateSignatureBytes,
  generateSortedVerifyDataEntries,
  generateVerifyData,
  HttpHeaders,
  splitWithSpace,
} from "../common";
import { VerifySignatureHeaderError } from "../errors";

import { getSignatureParams } from "./getSignatureParams";
import { verifyDigest } from "./verifyDigest";

const logDebug = Debug("http-signatures:verify");
const logTrace = Debug("http-signatures:verify:trace");

export type VerifySignatureHeaderOptions = {
  readonly verifier: {
    /**
     * The function for verifying the signature
     */
    readonly verify: (keyId: string, data: Uint8Array, signature: Uint8Array) => Promise<boolean>;
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
  readonly body?: object | string;
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
  logDebug("verifySignatureHeader start");

  const {
    verifier: { verify },
    method,
    httpHeaders,
    url,
    body,
  } = options;

  try {
    // need to make sure signature header is in lower case
    // SuperTest set() convert header to lower case
    const { signature: signatureString } = httpHeaders;
    if (typeof signatureString !== "string") {
      logDebug('typeof signatureString !== "string"');
      return okAsync(false);
    }
    const getSignatureParamsResult = getSignatureParams(signatureString);
    if (getSignatureParamsResult.isErr()) {
      logDebug("getSignatureParamsResult.isErr()");
      return okAsync(false);
    }
    const { created, headers: signatureHeadersString = "", keyId, signature } = getSignatureParamsResult.value;

    // filter http headers that aren't defined in the signature string headers field in order to create accurate verifyData
    const isMatchingHeader = (value: unknown, key: keyof HttpHeaders): boolean =>
      includes(toLower(`${key}`), splitWithSpace(signatureHeadersString));
    const httpHeadersToVerify = pickBy<HttpHeaders, HttpHeaders>(isMatchingHeader, httpHeaders);

    const verifyDataRes = generateVerifyData({
      created,
      method,
      url,
      httpHeaders: httpHeadersToVerify,
    });
    if (verifyDataRes.isErr()) {
      logDebug("verifyDataRes.isErr()");
      return okAsync(false);
    }
    const { value: verifyData } = verifyDataRes;

    const digest = verifyData["digest"];
    // Verify the digest if it's present
    if (digest !== undefined && !verifyDigest(digest, body)) {
      logDebug("digest !== undefined && !verifyDigest(digest, body)");
      return okAsync(false);
    }

    const sortedEntriesRes = generateSortedVerifyDataEntries(verifyData, signatureHeadersString);
    if (sortedEntriesRes.isErr()) {
      logDebug("sortedEntriesRes.isErr()");
      return okAsync(false);
    }
    const { value: sortedEntries } = sortedEntriesRes;
    logTrace("sortedEntries:");
    logTrace(sortedEntriesRes);

    const bytesToVerify = generateSignatureBytes(sortedEntries);
    const decodedSignatureRes = decodeBase64Url(signature);
    if (decodedSignatureRes.isErr()) {
      logDebug("decodedSignatureRes.isErr()");
      return okAsync(false);
    }
    const { value: decodedSignature } = decodedSignatureRes;

    logDebug("verifySignatureHeader end, return promise result from verify");
    return ResultAsync.fromPromise(verify(keyId, bytesToVerify, decodedSignature), (error) => ({
      type: "VerifyFailed",
      message: "Failed to verify signature header",
      rawError: error,
    }));
  } catch (error) {
    logDebug("verifySignatureHeader error");
    logDebug(error);
    return errAsync({
      type: "VerifyFailed",
      message: "Failed to verify signature header with unexpected error",
      rawError: error,
    });
  }
};
