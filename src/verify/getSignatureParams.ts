/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { ok, err, Result } from "neverthrow";

type SignatureParams = {
  readonly keyid: string;
  readonly created: number;
  readonly signature: string;
  readonly headers?: string;
};
/**
 * Use a regex to get the values of the of fields in the signature string
 * We aren't currently getting the expires
 */
export const getSignatureParams = (signatureHeaderValue: string): Result<SignatureParams, string> => {
  const keyidMatches: RegExpExecArray | null = /keyid="(.+?)"/.exec(signatureHeaderValue);
  const createdMatches: RegExpExecArray | null = /created=(.+?),/.exec(signatureHeaderValue);
  const headersMatches: RegExpExecArray | null = /headers="(.+?)"/.exec(signatureHeaderValue);
  const signatureMatches: RegExpExecArray | null = /signature="(.+?)"/.exec(signatureHeaderValue);

  if (!keyidMatches || !createdMatches || !signatureMatches || !headersMatches) {
    return err("Signature string is missing a required field");
  }
  return ok({
    keyid: keyidMatches[1],
    created: Number(createdMatches[1]),
    signature: signatureMatches[1],
    headers: headersMatches[1],
  });
};
