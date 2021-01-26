/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { encodeURLSafe as base64URLEncode } from "@stablelib/base64";
import { errAsync, ResultAsync } from "neverthrow";
import { isEmpty, map, pipe } from "ramda";

import {
  generateDigest,
  generateSignatureBytes,
  joinWithSpace,
  HttpHeaders,
  VerifyDataEntry,
  generateVerifyData,
  generateSortedVerifyDataEntries,
} from "../common";
import { CreateSignatureHeaderError } from "../errors";

/**
 * Generate a string containing all the keys of an object separated by a space
 * The order of the object properties that was used in signing must be preserved in this list of headers
 * @see https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-2.1.6
 */
const mapEntryKeys = map(([key]: VerifyDataEntry) => key);
const generateHeadersListString = pipe(mapEntryKeys, joinWithSpace);

export type CreateSignatureHeaderOptions = {
  readonly signer: {
    /**
     * The key id used for creating the signature. This will be added to the signature string and used in verification
     */
    readonly keyId: string;
    /**
     * The function for signing the data with the hs2019 algorithm
     */
    readonly sign: (data: Uint8Array) => Promise<Uint8Array>;
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
   * Headers and their values to include in the signing
   * The keys of these headers will be appended to the signature string for verification
   */
  readonly httpHeaders: HttpHeaders;
  /**
   * The body of the request
   */
  readonly body?: object | string;
};

/**
 * Creates a signature header to be appended as a header on a request
 * A digest header will be returned if a body was included. This also needs to be appended to the request headers.
 * @see https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-4
 */
export const createSignatureHeader = (
  options: CreateSignatureHeaderOptions
): ResultAsync<{ digest?: string; signature: string }, CreateSignatureHeaderError> => {
  try {
    const algorithm = "hs2019";
    const {
      signer: { keyId, sign },
      method,
      httpHeaders,
      body,
      url,
    } = options;

    // Disallow empty headers
    // https://tools.ietf.org/html/draft-cavage-http-signatures-12#section-2.1.6
    if (isEmpty(httpHeaders)) {
      return errAsync({ type: "MalformedInput", message: "Http headers must not be empty" });
    }

    const digest = body ? generateDigest(body) : undefined;
    const created = Math.round(Date.now() / 1000);
    const verifyDataRes = generateVerifyData({
      httpHeaders: {
        ...httpHeaders,
        // Append the digest if necessary
        ...(digest ? { Digest: digest } : {}),
      },
      url,
      method,
      created,
    });
    if (verifyDataRes.isErr()) {
      return errAsync({ type: "MalformedInput", message: verifyDataRes.error });
    }
    const sortedEntriesRes = generateSortedVerifyDataEntries(verifyDataRes.value);
    if (sortedEntriesRes.isErr()) {
      return errAsync({ type: "MalformedInput", message: sortedEntriesRes.error });
    }

    const { value: sortedEntries } = sortedEntriesRes;
    const bytesToSign = generateSignatureBytes(sortedEntries);
    const headersListString = generateHeadersListString(sortedEntries);

    return ResultAsync.fromPromise<Uint8Array, CreateSignatureHeaderError>(sign(bytesToSign), () => ({
      type: "SignFailed",
      message: "Failed to sign signature header",
    })).map((result) => {
      const signatureBase64 = base64URLEncode(result);
      const signatureHeaderValue = `keyId="${keyId}",algorithm="${algorithm}",created=${created},headers="${headersListString}",signature="${signatureBase64}"`;
      return {
        signature: signatureHeaderValue,
        digest,
      };
    });
  } catch (error) {
    return errAsync({ type: "Error", message: "Failed to create signature header" });
  }
};
