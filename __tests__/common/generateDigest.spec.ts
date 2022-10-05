/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { generateDigest } from "../../src/common";

describe("generateDigest", () => {
  it("Should generate a digest for an object", async () => {
    expect(generateDigest({ a: 1, b: 2 }, "sha-256")).toEqual("sha-256=:QyWM/3g/5wNtikMDP4MK38YOwDc4JHNUisdCuIgpJ3c=:");
  });

  it("Should generate a digest for an string", async () => {
    expect(generateDigest("body string", "sha-256")).toEqual("sha-256=:Vge1353vPF/ryKey6UFOTrM/Pn4p31zzOE5c9rOPCfE=:");
  });
});
