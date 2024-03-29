/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import http from "http";
import { ResultAsync } from "neverthrow";

import { VerifyResult } from "../common";
import { VerifySignatureHeaderError } from "../errors";

import { Verifier } from "./verifySignatureHeader";
import { verifySignatureHeader } from "./verifySignatureHeader";

export type VerifyRequestOptions = {
  verifier: Verifier;
  request: http.IncomingMessage;
  signatureKey?: string;
  body?: Record<string, unknown> | string;
  verifyExpiry?: boolean;
};
export const verifyRequest = (options: VerifyRequestOptions): ResultAsync<VerifyResult, VerifySignatureHeaderError> => {
  const { request, verifier, body, signatureKey, verifyExpiry = true } = options;

  return verifySignatureHeader({
    url: `https://${request.headers.host}${request.url}`,
    method: request.method ?? "",
    httpHeaders: request.headers,
    signatureKey: signatureKey,
    verifier,
    ...(body && { body }),
    verifyExpiry,
  });
};
