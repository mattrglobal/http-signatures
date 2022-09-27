/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { errAsync, okAsync, ResultAsync } from "neverthrow";
import { includes, pickBy, toLower } from "ramda";
import { parseDictionary, serializeList, serializeDictionary } from "structured-headers";

import {
  decodeBase64,
  generateSignatureParams,
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
  /**
   * Optional field to identify a single signature that should be verified from the signature header. If omitted, this function will attempt to verify all signatures present.
   */
  readonly signatureKey?: string;
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
    signatureKey,
  } = options;

  const verifications = [];

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

    if (signatureKey && !(signatureKey in getSignatureDataResult.value)) {
      // specified key could not be found in the signature input data
      return okAsync(false);
    }

    const signatureSet = getSignatureDataResult.value;

    for (const signatureId in signatureSet) {
      if (signatureKey && signatureId != signatureKey) {
        continue;
      }

      const { coveredFields: coveredFields = [], parameters, signature } = signatureSet[signatureId];

      const currentTime = Math.floor(Date.now() / 1000);
      const coveredFieldNames = coveredFields.map((item) => item[0]);

      const expires = parameters.get("expires");

      if (expires && expires < currentTime) {
        return okAsync(false);
      }

      // filter http headers that aren't defined in the signature string headers field in order to create accurate verifyData
      const isMatchingHeader = (value: unknown, key: keyof HttpHeaders): boolean =>
        includes(toLower(`${key}`), coveredFieldNames);
      let httpHeadersToVerify = pickBy<HttpHeaders, HttpHeaders>(isMatchingHeader, httpHeaders);

      const existingSignatureItem = coveredFields.find((item) => item[0] == "signature");
      const existingSignatureKey = existingSignatureItem ? (existingSignatureItem[1].get("key") as string) : undefined;

      // if signature to be verified signed over another signature, reconstruct the signature header
      // to match what it would have been when the signature was created
      if (existingSignatureItem && existingSignatureKey) {
        const existingSignatures = httpHeadersToVerify.Signature;
        if (typeof existingSignatures == "string") {
          const existingSignaturesMap = parseDictionary(existingSignatures);
          const filteredMap = new Map([...existingSignaturesMap].filter(([k]) => k == existingSignatureKey));
          httpHeadersToVerify = { ...httpHeadersToVerify, Signature: serializeDictionary(filteredMap) };
        }
      }

      const verifyDataRes = generateVerifyData({
        coveredFieldNames,
        method,
        url,
        httpHeaders: httpHeadersToVerify,
      });
      if (verifyDataRes.isErr()) {
        return okAsync(false);
      }

      const { value: verifyData } = verifyDataRes;

      const digest = verifyData["content-digest"];
      // Verify the digest if it's present
      if (digest !== undefined && !verifyDigest(digest, body)) {
        return okAsync(false);
      }

      const sortedEntriesRes = generateSortedVerifyDataEntries(verifyData, coveredFieldNames);
      if (sortedEntriesRes.isErr()) {
        return okAsync(false);
      }
      const { value: sortedEntries } = sortedEntriesRes;

      const signatureParams = generateSignatureParams({
        data: sortedEntries,
        parameters,
        ...(existingSignatureItem ? { existingSignatureKey } : {}),
      });

      const keyid: string = parameters.get("keyid") as string;

      const bytesToVerify = generateSignatureBytes([
        ...sortedEntries,
        ["@signature-params", serializeList([signatureParams])],
      ]);

      const decodedSignatureRes = decodeBase64(signature);

      if (decodedSignatureRes.isErr()) {
        return okAsync(false);
      }
      const { value: decodedSignature } = decodedSignatureRes;

      verifications.push(verify(keyid, bytesToVerify, Buffer.from(decodedSignature)));
    }

    return ResultAsync.fromPromise(
      Promise.all(verifications).then((arr) =>
        arr.reduce((acc, val) => {
          return acc && !!val;
        }, true)
      ),
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
