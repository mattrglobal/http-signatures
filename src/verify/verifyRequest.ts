/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { JsonWebKey } from "crypto";
import http from "http";
import { ResultAsync } from "neverthrow";

import { algMap } from "../common/cryptoPrimatives";
import { VerifySignatureHeaderError } from "../errors";
import { AlgorithmTypes } from "../sign/createSignatureHeader";

import { verifySignatureHeader } from "./verifySignatureHeader";

export type VerifyRequestOptions = {
  keymap: { [keyid: string]: JsonWebKey };
  alg: AlgorithmTypes;
  request: http.IncomingMessage;
  signatureKey?: string;
  data?: string;
};
export const verifyRequest = (options: VerifyRequestOptions): ResultAsync<boolean, VerifySignatureHeaderError> => {
  /* 
    Currently this function accepts only one verifier. As such, it's recommended to pass in a signature key to verify 
    a specific signature unless all signatures on the request are signed with the same algorithm.
  */
  const { request, alg, keymap, data, signatureKey } = options;

  return verifySignatureHeader({
    url: `http://${request.headers.host}${request.url}` ?? "",
    method: request.method ?? "",
    httpHeaders: request.headers,
    signatureKey: signatureKey,
    verifier: {
      verify: algMap[alg].verify(keymap),
    },
    ...(data && { body: data }),
  });
};
