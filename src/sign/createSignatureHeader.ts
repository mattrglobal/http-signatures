/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { encode as base64Encode } from "@stablelib/base64";
import { err, errAsync, ok, Result, ResultAsync } from "neverthrow";
import { parseDictionary, Item, InnerList, serializeDictionary, serializeList, Parameters } from "structured-headers";

import {
  generateDigest,
  generateSignatureBytes,
  generateVerifyData,
  HttpHeaders,
  reduceKeysToLowerCase,
  VerifyDataEntry,
} from "../common";
import { CreateSignatureHeaderError } from "../errors";

//  Algorithm list as per https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-12.html#section-6.1.2
export enum AlgorithmTypes {
  "rsa-pss-sha512" = "rsa-pss-sha512",
  "rsa-v1_5-sha256" = "rsa-v1_5-sha256",
  "hmac-sha256" = "hmac-sha256",
  "ecdsa-p256-sha256" = "ecdsa-p256-sha256",
  "ecdsa-p384-sha384" = "ecdsa-p384-sha384",
  ed25519 = "ed25519",
}

export type CreateSignatureHeaderOptions = {
  readonly signer: {
    /**
     * The key id used for creating the signature. This will be added to the signature string and used in verification
     */
    readonly keyid: string;
    /**
     * The function for signing the data with the specified algorithm
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
   * An optional expiry param as an Integer UNIX timestamp value, to indicate to the verifier a time after which this signature should no longer be trusted.
   * Sub- second precision is not supported.
   */
  readonly expires?: number;
  /**
   * An optional unique value generated for this signature as a String value.
   */
  readonly nonce?: string;
  /**
   * An optional application specific tag parameter to provide additional context for the signature
   */
  readonly tag?: string;
  /**
   * The HTTP message signature algorithm from the HTTP Message Signature Algorithm Registry, as a String value.
   */
  readonly alg?: AlgorithmTypes;
  /**
   * An optional list of field names to cover in the signature. If omitted, a default list is used.
   */
  readonly coveredFields?: [string, Parameters][];
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
    const bodyCovered = options.body ? ["content-digest"] : [];
    const headersCovered = (
      options.httpHeaders &&
      Object.keys(options.httpHeaders)
        .filter((header) => header.toLowerCase() != "signature" && header.toLowerCase() != "signature-input")
        .map((a) => a.toLowerCase())
    ).sort();
    const {
      signer: { keyid, sign },
      method,
      signatureId,
      httpHeaders,
      body,
      url,
      expires,
      nonce,
      tag,
      alg,
      coveredFields = ["@request-target", "@method", ...bodyCovered, ...headersCovered].map((a) => [a, new Map()]),
    } = options;

    const created = Math.floor(Date.now() / 1000);

    if (expires && expires < created) {
      return err({ type: "SignFailed", message: "Expiry must not be in the past" });
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
        existingSignatureData = parseDictionary(existingSignatureString);
        existingSignatureInputData = parseDictionary(existingSignatureInputString);
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

    const digest = body ? generateDigest(body, "sha-256") : undefined;

    const verifyDataRes = generateVerifyData({
      coveredFields,
      httpHeaders: {
        ...httpHeaders,
        // Append the digest if necessary
        ...(digest ? { "Content-Digest": digest } : {}),
      },
      url,
      method,
    });
    if (verifyDataRes.isErr()) {
      return err({ type: "MalformedInput", message: verifyDataRes.error });
    }

    const parameters = new Map<string, string | number>([
      ["created", created],
      ...(expires ? [["expires", expires] as const] : []),
      ...(nonce ? [["nonce", nonce] as const] : []),
      ...(alg ? [["alg", alg] as const] : []),
      ["keyid", keyid],
      ...(tag ? [["tag", tag] as const] : []),
    ]);

    const signatureParams: InnerList = [verifyDataRes.value.map(([item]: VerifyDataEntry) => item), parameters];

    const bytesToSign = generateSignatureBytes([
      ...verifyDataRes.value,
      [["@signature-params", new Map()], serializeList([signatureParams])],
    ]);
    const signResult = await ResultAsync.fromPromise(sign(bytesToSign), (e) => e);

    if (signResult.isErr()) {
      return err({
        type: "SignFailed",
        message: signResult.error instanceof Error ? signResult.error.message : "Unknown",
      });
    }

    const signature = base64Encode(signResult.value);

    existingSignatureInputData.set(sigKeyToUse, signatureParams);

    return ok({
      signature: `${existingSignatures ? existingSignatureString + ", " : ""}${sigKeyToUse}=:${signature}:`,
      signatureInput: serializeDictionary(existingSignatureInputData),
      digest,
    });
  } catch (error) {
    return errAsync({
      type: "SignFailed",
      message: "An error occurred when signing signature header",
    });
  }
};
