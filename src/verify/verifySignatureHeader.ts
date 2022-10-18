/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { JsonWebKey } from "crypto";
import { errAsync, okAsync, ResultAsync } from "neverthrow";
import { includes, pickBy, toLower } from "ramda";
import { AlgorithmTypes } from "src/sign";
import { parseDictionary, serializeList, serializeDictionary, InnerList } from "structured-headers";

import {
  decodeBase64,
  VerifyDataEntry,
  VerifyResult,
  VerifyFailureReasonType,
  generateSignatureBytes,
  generateVerifyData,
  HttpHeaders,
  reduceKeysToLowerCase,
  getSignatureData,
  getAlgFromJwk,
} from "../common";
import { algMap } from "../common/cryptoPrimatives";
import { VerifySignatureHeaderError } from "../errors";

import { verifyDigest } from "./verifyDigest";

export type Verifier =
  | {
      /**
       * A map of the cryptographic keys to use to verify the signatures on an http message. Default
       * cryptographic functions will be used
       */
      keyMap: {
        [keyid: string]: {
          alg?: AlgorithmTypes;
          key: JsonWebKey;
        };
      };
    }
  | {
      /**
       * A Custom verification function to be run agaist each signature on an http message.
       */
      verify: (
        signatureParams: { keyid: string; alg: AlgorithmTypes },
        data: Uint8Array,
        signature: Uint8Array
      ) => Promise<boolean>;
    };

export type VerifySignatureHeaderOptions = {
  readonly verifier: Verifier;
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
  /**
   * Optionally set this field to false if you don't want to fail verification based on the signature being past its expiry timestamp.
   * Defaults to true.
   */
  readonly verifyExpiry?: boolean;
};

/**
 * Verifies a signature header
 * Anything wrong with the format will return an error, an exception thrown within verify will return an error
 * Otherwise an ok is returned with verified true or false
 * @see https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12#section-2.5
 */
export const verifySignatureHeader = (
  options: VerifySignatureHeaderOptions
): ResultAsync<VerifyResult, VerifySignatureHeaderError> => {
  const { verifier, method, httpHeaders, url, body, signatureKey, verifyExpiry = true } = options;

  const keyMap = "keyMap" in verifier && verifier.keyMap;
  const verify = "verify" in verifier && verifier.verify;

  const verifications = [];

  try {
    // need to make sure signature header is in lower case
    // SuperTest set() convert header to lower case

    const lowerCaseHttpHeaders = reduceKeysToLowerCase(httpHeaders);
    const { signature: signatureString, "signature-input": signatureInputString } = lowerCaseHttpHeaders;
    if (typeof signatureString !== "string" || typeof signatureInputString !== "string") {
      return okAsync({
        verified: false,
        reason: {
          type: VerifyFailureReasonType.MissingOrInvalidSignature,
          message: "Signature or Signature-Input header is invalid or missing.",
        },
      });
    }

    const getSignatureDataResult = getSignatureData(signatureString, signatureInputString);
    if (getSignatureDataResult.isErr()) {
      return okAsync({
        verified: false,
        reason: {
          type: VerifyFailureReasonType.SignatureParseFailure,
          message: "Unable to parse Signature and Signature-Input headers.",
        },
      });
    }

    if (signatureKey && !(signatureKey in getSignatureDataResult.value)) {
      // specified key could not be found in the signature input data
      return okAsync({
        verified: false,
        reason: {
          type: VerifyFailureReasonType.MissingSignatureKey,
          message: `Specified key ${signatureKey} could not be found in the signature headers.`,
        },
      });
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
      const keyid: string = parameters.get("keyid") as string;

      if (keyMap && !(keyid in keyMap)) {
        return okAsync({
          verified: false,
          reason: {
            type: VerifyFailureReasonType.MissingJWK,
            message: `JWK ${keyid} could not be found in the keymap provided.`,
          },
        });
      }

      const keyMapData = keyMap ? keyMap[keyid] : undefined;

      // Use algorithm submitted from user, otherwise attempt to determine it from the signature-input header
      const alg =
        (keyMapData && keyMapData.alg) ??
        (parameters.get("alg") as AlgorithmTypes | undefined) ??
        (keyMapData && getAlgFromJwk(keyMapData.key));

      if (!alg) {
        return okAsync({
          verified: false,
          reason: {
            type: VerifyFailureReasonType.UndefinedAlgorithm,
            message: `Signature ${signatureId} algortithm could not be determined from signature params or from any JWKs provided - specify an algorithm directly.`,
          },
        });
      }

      if (verifyExpiry && expires && expires < currentTime) {
        return okAsync({
          verified: false,
          reason: {
            type: VerifyFailureReasonType.SignatureExpired,
            message: `Signature ${signatureId} has expired at timestamp ${expires}. If you wish to ignore this, set verifyExpiry to false.`,
          },
        });
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
        coveredFields,
        method,
        url,
        httpHeaders: httpHeadersToVerify,
      });
      if (verifyDataRes.isErr()) {
        return okAsync({
          verified: false,
          reason: {
            type: VerifyFailureReasonType.GenerateVerifyDataFail,
            message: `Unable to generate verify data for signature ${signatureId}.`,
            details: {
              cause: verifyDataRes.error,
            },
          },
        });
      }

      const { value: verifyData } = verifyDataRes;

      const digestEntry = verifyData.find(([[e]]) => e == "content-digest");
      // Verify the digest if it's present
      if (digestEntry !== undefined && digestEntry[1] !== undefined) {
        if (Array.isArray(digestEntry[1])) {
          return okAsync({
            verified: false,
            reason: {
              type: VerifyFailureReasonType.InvalidContentDigest,
              message: "Content-digest heder value should not be an array.",
            },
          });
        }
        const [digestAlg] = parseDictionary(digestEntry[1] as string).keys();
        if (!verifyDigest(digestEntry[1] as string, body, digestAlg)) {
          return okAsync({
            verified: false,
            reason: {
              type: VerifyFailureReasonType.ContentDigestMismatch,
              message: "The digest generated from the request body does not match the content-digest header value.",
            },
          });
        }
      }

      const signatureParams: InnerList = [verifyDataRes.value.map(([item]: VerifyDataEntry) => item), parameters];

      const bytesToVerify = generateSignatureBytes([
        ...verifyData,
        [["@signature-params", new Map()], serializeList([signatureParams])],
      ]);

      const decodedSignatureRes = decodeBase64(signature);

      if (decodedSignatureRes.isErr()) {
        return okAsync({
          verified: false,
          reason: {
            type: VerifyFailureReasonType.SignatureDecodeFailure,
            message: `Failed to decode signature ${signatureId} from base64.`,
          },
        });
      }
      const { value: decodedSignature } = decodedSignatureRes;

      if (verify) {
        verifications.push(verify({ keyid, alg }, bytesToVerify, Buffer.from(decodedSignature)));
      } else if (keyMapData) {
        verifications.push(algMap[alg].verify(keyMapData.key)(bytesToVerify, Buffer.from(decodedSignature)));
      } else {
        return errAsync({
          type: "VerifyFailed",
          message: `No key or verification function were provided for key ${keyid}`,
        });
      }
    }

    return ResultAsync.fromPromise(
      Promise.all(verifications).then((arr) => {
        const verified = arr.reduce((acc, val) => {
          return acc && !!val;
        }, true);
        return verified
          ? { verified }
          : {
              verified,
              reason: {
                type: VerifyFailureReasonType.FailedToVerify,
                message: "Signatures are well formed but one or more failed to verify.",
              },
            };
      }),
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
