/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import http from "http";
import { ResultAsync } from "neverthrow";

import { VerifySignatureHeaderError } from "../errors";

import { Verifier } from "./verifySignatureHeader";
import { verifySignatureHeader } from "./verifySignatureHeader";

export type VerifyRequestOptions = {
  verifier: Verifier;
  request: http.IncomingMessage;
  signatureKey?: string;
  body?: string;
};
export const verifyRequest = (options: VerifyRequestOptions): ResultAsync<boolean, VerifySignatureHeaderError> => {
  const { request, verifier, body, signatureKey } = options;

  return verifySignatureHeader({
    url: `http://${request.headers.host}${request.url}` ?? "",
    method: request.method ?? "",
    httpHeaders: request.headers,
    signatureKey: signatureKey,
    verifier,
    ...(body && { body }),
  });
};
