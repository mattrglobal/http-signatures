/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

export type VerifyData = {
  ["(request-target)"]: string;
  ["(created)"]: string;
  host: string;
  readonly [key: string]: string | string[];
};
export type VerifyDataEntry = [string, string | string[] | undefined];

export type HttpHeaders = { readonly [key: string]: string | string[] | undefined };
