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
