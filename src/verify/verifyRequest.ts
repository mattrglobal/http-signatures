/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { KeyObject } from "crypto";
import http from "http";
import { ResultAsync } from "neverthrow";

import { algMap } from "../common/cryptoPrimatives";
import { VerifySignatureHeaderError } from "../errors";
import { AlgorithmTypes } from "../sign/createSignatureHeader";

import { verifySignatureHeader } from "./verifySignatureHeader";

export type VerifyRequestOptions = {
  keymap: { [keyid: string]: KeyObject };
  alg: AlgorithmTypes;
  request: http.IncomingMessage;
  data?: string;
};
export const verifyRequest = (options: VerifyRequestOptions): ResultAsync<boolean, VerifySignatureHeaderError> => {
  // at the moment, only one verifier -> all signatures must use same alg
  const { request, alg, keymap, data } = options;

  // todo differentiate http and https

  return verifySignatureHeader({
    url: `http://${request.headers.host}${request.url}` ?? "",
    method: request.method ?? "",
    httpHeaders: request.headers,
    verifier: {
      verify: algMap[alg].verify(keymap),
    },
    ...(data && { body: data }),
  });
};
