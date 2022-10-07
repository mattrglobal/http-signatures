/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import http from "http";
import { errAsync, ResultAsync } from "neverthrow";

import { getSignatureData, reduceKeysToLowerCase } from "../common";
import { VerifySignatureHeaderError } from "../errors";

import { Verifier } from "./verifySignatureHeader";
import { verifySignatureHeader } from "./verifySignatureHeader";

export type VerifyRequestOptions = {
  verifier: Verifier;
  request: http.IncomingMessage;
  signatureKey?: string;
  data?: string;
};
export const verifyRequest = (options: VerifyRequestOptions): ResultAsync<boolean, VerifySignatureHeaderError> => {
  const { request, verifier, data, signatureKey } = options;

  const lowerCaseHttpHeaders = reduceKeysToLowerCase(request.headers);
  const { signature: signatureString, "signature-input": signatureInputString } = lowerCaseHttpHeaders;
  if (typeof signatureString !== "string" || typeof signatureInputString !== "string") {
    return errAsync({ type: "VerifyFailed", message: "" });
  }

  const getSignatureDataResult = getSignatureData(signatureString, signatureInputString);
  if (getSignatureDataResult.isErr()) {
    return errAsync({ type: "VerifyFailed", message: getSignatureDataResult.error });
  }

  return verifySignatureHeader({
    url: `http://${request.headers.host}${request.url}` ?? "",
    method: request.method ?? "",
    httpHeaders: request.headers,
    signatureKey: signatureKey,
    verifier,
    ...(data && { body: data }),
  });
};
