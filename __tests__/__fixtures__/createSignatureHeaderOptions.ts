/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { CreateSignatureHeaderOptions } from "../../src/sign";

export const createSignatureHeaderOptions: CreateSignatureHeaderOptions = {
  signer: {
    keyid: "key-1",
    sign: (): Promise<Uint8Array> => Promise.resolve(Uint8Array.from([])),
  },
  url: "http://example.com/foo?param=value&pet=dog",
  method: "POST",
  httpHeaders: {
    ["HOST"]: "example.com",
    ["Content-Type"]: "application/json",
  },
  body: `{"hello": "world"}`,
};
