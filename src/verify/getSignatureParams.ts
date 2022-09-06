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
  readonly coveredFields?: string;
};
/**
 * Use a regex to get the values of the of fields in the signature string
 * We aren't currently getting the expires
 */
export const getSignatureParams = (
  signatureHeaderValue: string,
  signatureInputHeaderValue: string
): Result<SignatureParams, string> => {
  const keyidMatches: RegExpExecArray | null = /keyid="(.+?)"/.exec(signatureInputHeaderValue);
  const createdMatches: RegExpExecArray | null = /created=(\d+?)(,|$)/.exec(signatureInputHeaderValue);
  const coveredFieldsMatches: RegExpExecArray | null = /sig=\((.+?)\);/.exec(signatureInputHeaderValue);
  const signatureMatches: RegExpExecArray | null = /sig=:(.+?):/.exec(signatureHeaderValue);

  if (!keyidMatches || !createdMatches || !signatureMatches || !coveredFieldsMatches) {
    return err("Signature input string is missing a required field");
  }
  return ok({
    keyid: keyidMatches[1],
    created: Number(createdMatches[1]),
    signature: signatureMatches[1],
    coveredFields: coveredFieldsMatches[1].replace(/"/g, ""),
  });
};
