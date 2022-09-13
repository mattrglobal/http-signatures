/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { ok, err, Result } from "neverthrow";
import { toLower } from "ramda";
import { parseDictionary, Item, InnerList } from "structured-headers";

type SignatureInputSetParams = {
  [signatureId: string]: ResponseParams;
};

type SignatureInputParams = {
  keyid: string;
  created: number;
  expiry?: number;
  coveredFields?: string[];
};

type ResponseParams = SignatureInputParams & {
  readonly signature: string;
};
/**
 * Parses the values in the signature-input and signature headers
 */
export const getSignatureData = (
  signatureHeaderValue: string,
  signatureInputHeaderValue: string
): Result<SignatureInputSetParams, string> => {
  const signatureInputHeaderMap: Map<string, Item | InnerList> = parseDictionary(signatureInputHeaderValue);
  const signatureHeaderMap: Map<string, Item | InnerList> = parseDictionary(signatureHeaderValue);

  let signatureData: SignatureInputSetParams = {};

  for (const entry of signatureInputHeaderMap) {
    const signatureId: string = entry[0];
    if (signatureId in signatureData) {
      // duplicate keys in signature-input field
      return err("Invalid signature data");
    }

    const signatureFields = entry[1];

    const coveredFields: string[] = Object.values(signatureFields[0]).map((a) => toLower(a[0]));
    const signatureParams = signatureFields[1];

    const keyid: string | undefined = signatureParams.get("keyid") as string;
    const created: number | undefined = signatureParams.get("created") as number;
    // const alg: string | undefined = signatureParams.get("alg") as string;
    // const expires: number | undefined = signatureParams.get("expires") as number;
    // const nonce: string | undefined = signatureParams.get("nonce") as string;

    if (!keyid || !created || !coveredFields.length || !signatureId) {
      return err("Signature input string is missing a required field");
    }

    const signatureMap = signatureHeaderMap.get(signatureId);

    if (!signatureMap) {
      return err("One or more signatures is invalid");
    }

    const signature: string = Object.values(signatureMap[0])[0] as string;

    signatureData = {
      ...signatureData,
      [signatureId]: {
        keyid,
        created,
        coveredFields,
        signature,
      },
    };
  }

  return ok(signatureData);
};

// export const getParamsForOneSignature = (
//   signatureHeaderValue: string,
//   signatureInputHeaderValue: string,
//   signatureId: string
// ): Result<ResponseParams, string> => {
//   const keyidMatches: RegExpExecArray | null = /keyid="(.+?)"/.exec(signatureInputHeaderValue);
//   const createdMatches: RegExpExecArray | null = /created=(\d+?)(,|$)/.exec(signatureInputHeaderValue);
//   const coveredFieldsMatches: RegExpExecArray | null = /sig=\((.+?)\);/.exec(signatureInputHeaderValue);
//   const signatureMatches: RegExpExecArray | null = /sig=:(.+?):/.exec(signatureHeaderValue);

//   if (!keyidMatches || !createdMatches || !signatureMatches || !coveredFieldsMatches) {
//     return err("Signature input string is missing a required field");
//   }
//   return ok(
//     {
//     keyid: keyidMatches[1],
//     created: Number(createdMatches[1]),
//     signature: signatureMatches[1],
//     coveredFields: [coveredFieldsMatches[1].replace(/"/g, "")],
//   });
// }
