/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { encode as base64Encode } from "@stablelib/base64";
import { err, errAsync, ok, Result, ResultAsync } from "neverthrow";
import { isEmpty } from "ramda";
import { parseDictionary, Item, InnerList } from "structured-headers";

import {
  generateDigest,
  generateSignatureBytes,
  generateSignatureParams,
  generateSortedVerifyDataEntries,
  generateVerifyData,
  HttpHeaders,
  reduceKeysToLowerCase,
} from "../common";
import { CreateSignatureHeaderError } from "../errors";

export type CreateSignatureHeaderOptions = {
  readonly signer: {
    /**
     * The key id used for creating the signature. This will be added to the signature string and used in verification
     */
    readonly keyid: string;
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
   * Optional field to identify this signature. This will be added to the signature and signature-input fields, and helps to distinguish
   * when multiple signatures are present. If omitted, this will default to 'sigx' where x is the lowest int not used in another signature id.
   */
  readonly signatureId?: string;
  /**
   * Headers and their values to include in the signing
   * The keys of these headers will be appended to the signature string for verification
   */
  readonly httpHeaders: HttpHeaders;
  /**
   * The body of the request
   */
  readonly body?: Record<string, unknown> | string;
  /**
   * If it's desired to sign over a previous signature, the key of the signature must be specified
   */
  readonly existingSignatureKey?: string;
};

/**
 * Creates a signature header to be appended as a header on a request
 * A digest header will be returned if a body was included. This also needs to be appended to the request headers.
 * @see https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-4
 */
export const createSignatureHeader = async (
  options: CreateSignatureHeaderOptions
): Promise<Result<{ digest?: string; signature: string; signatureInput: string }, CreateSignatureHeaderError>> => {
  try {
    const {
      signer: { keyid, sign },
      method,
      signatureId,
      httpHeaders,
      body,
      url,
      existingSignatureKey,
    } = options;

    // Disallow empty headers
    // https://tools.ietf.org/html/draft-cavage-http-signatures-12#section-2.1.6
    if (isEmpty(httpHeaders)) {
      return err({ type: "MalformedInput", message: "Http headers must not be empty" });
    }

    // determine appropriate key for new signature
    let sigKeyToUse: string | undefined = undefined;
    let existingSignatures = false;

    const lowerCaseHttpHeaders = reduceKeysToLowerCase(httpHeaders);
    const { signature: existingSignatureString, "signature-input": existingSignatureInputString } =
      lowerCaseHttpHeaders;
    let existingSignatureData: Map<string, Item | InnerList> = new Map();
    let existingSignatureInputData: Map<string, Item | InnerList> = new Map();

    if (typeof existingSignatureString == "string" && typeof existingSignatureInputString == "string") {
      existingSignatures = true;

      try {
        existingSignatureInputData = parseDictionary(existingSignatureInputString);
        existingSignatureData = parseDictionary(existingSignatureString);
      } catch {
        return err({ type: "MalformedInput", message: "Unable to parse existing signature data" });
      }

      if (signatureId) {
        if (existingSignatureData.get(signatureId)) {
          return err({ type: "SignFailed", message: "Specified signature id is already in use" });
        }
        sigKeyToUse = signatureId;
      } else {
        for (let i = 1; i < 100; i++) {
          // only supports up to 100 for now
          if (!existingSignatureData.get(`sig${i}`)) {
            sigKeyToUse = `sig${i}`;
            break;
          }
        }
        if (!sigKeyToUse) {
          return err({ type: "SignFailed", message: "Could not find a valid signature id to use" });
        }
      }
    } else {
      // no existing valid signature data
      sigKeyToUse = signatureId ?? "sig1";
    }

    const digest = body ? generateDigest(body) : undefined;

    const verifyDataRes = generateVerifyData({
      httpHeaders: {
        ...httpHeaders,
        // Append the digest if necessary
        ...(digest ? { "Content-Digest": digest } : {}),
      },
      url,
      method,
      existingSignatureKey,
    });
    if (verifyDataRes.isErr()) {
      return err({ type: "MalformedInput", message: verifyDataRes.error });
    }
    const sortedEntriesRes = generateSortedVerifyDataEntries(verifyDataRes.value, [
      "@request-target",
      "content-type",
      "host",
      "@method",
      "content-digest",
      ...(existingSignatures ? ["signature"] : []),
    ]);
    if (sortedEntriesRes.isErr()) {
      return err({ type: "MalformedInput", message: sortedEntriesRes.error });
    }

    const { value: sortedEntries } = sortedEntriesRes;

    const signatureParams = generateSignatureParams({
      data: sortedEntries,
      alg: "ecdsa-p256-sha256",
      keyid,
      signatureId: sigKeyToUse,
      existingSignatureInputData,
      existingSignatureKey,
    });

    const bytesToSign = generateSignatureBytes([
      ...sortedEntries,
      ["@signature-params", signatureParams.replace(`${sigKeyToUse}=`, "")],
    ]); // discussion point - format change
    const signResult = await ResultAsync.fromPromise(sign(bytesToSign), (e) => e);

    if (signResult.isErr()) {
      return err({
        type: "SignFailed",
        message: signResult.error instanceof Error ? signResult.error.message : "Unknown",
      });
    }

    const signature = base64Encode(signResult.value);

    return ok({
      signature: `${existingSignatures ? existingSignatureString + ", " : ""}${sigKeyToUse}=:${signature}:`,
      signatureInput: `${signatureParams}`,
      digest,
    });
  } catch (error) {
    return errAsync({
      type: "SignFailed",
      message: "An error occurred when signing signature header",
    });
  }
};
