/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { Item } from "structured-headers";

export type VerifyData = {
  readonly [key: string]: string | string[];
};
export type VerifyDataEntry = [Item, string | string[] | number | undefined];

export type HttpHeaders = { readonly [key: string]: string | string[] | undefined };

export enum VerifyFailureReasonType {
  MissingOrInvalidSignature = "MissingOrInvalidSignature",
  SignatureParseFailure = "SignatureParseFailure",
  MissingSignatureKey = "MissingSignatureKey",
  MissingKey = "MissingKey",
  UndefinedAlgorithm = "UndefinedAlgorithm",
  SignatureExpired = "SignatureExpired",
  GenerateVerifyDataFail = "GenerateVerifyDataFail",
  InvalidContentDigest = "InvalidContentDigest",
  ContentDigestMismatch = "ContentDigestMismatch",
  SignatureDecodeFailure = "SignatureDecodeFailure",
  FailedToVerify = "FailedToVerify",
}

export interface VerifyFailedResultReasonDetails {
  readonly cause?: unknown;
  readonly [key: string]: unknown;
}

export interface VerifySuccessResult {
  readonly verified: true;
}

export interface VerifyFailResult {
  readonly verified: false;
  readonly reason: {
    readonly type: VerifyFailureReasonType;
    readonly message: string;
    readonly details?: VerifyFailedResultReasonDetails;
  };
}

export type VerifyResult = VerifySuccessResult | VerifyFailResult;
