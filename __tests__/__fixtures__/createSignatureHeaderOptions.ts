/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { CreateSignatureHeaderOptions } from "../../src/sign";

export const createSignatureHeaderOptions: CreateSignatureHeaderOptions = {
  signer: {
    keyId: "hs2019",
    sign: (): Promise<Uint8Array> => Promise.resolve(Uint8Array.from([])),
  },
  url: "http://www.host.com/test?query=1",
  method: "GET",
  headers: { ["Content-Type"]: "application/json", ["x-custom-header"]: "x-custom-header-value" },
  body: { hello: "hello" },
};
