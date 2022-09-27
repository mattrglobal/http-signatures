/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

export type VerifyData = {
  readonly [key: string]: string | string[];
};
export type VerifyDataEntry = [string, string | string[] | undefined];

export type HttpHeaders = { readonly [key: string]: string | string[] | undefined };
