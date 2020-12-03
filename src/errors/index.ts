/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
type Error = { type: "Error"; message: string };
type MalformedInput = { type: "MalformedInput"; message: string };
type SignFailed = { type: "SignFailed"; message: string };
type VerifyFailed = { type: "VerifyFailed"; message: string };

export type CreateSignatureHeaderError = Error | MalformedInput | SignFailed;
export type VerifySignatureHeaderError = Error | VerifyFailed;
