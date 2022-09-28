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

  it("Should canonicalize an object when creating a digest", async () => {
    const digest1 = generateDigest({ a: 1, b: 2 }, "sha-256");
    const digest2 = generateDigest({ b: 2, a: 1 }, "sha-256");
    expect(digest1).toEqual("sha-256=:QyWM/3g/5wNtikMDP4MK38YOwDc4JHNUisdCuIgpJ3c=:");
    expect(digest1).toEqual(digest2);
  });

  it("Should generate a digest for an string", async () => {
    expect(generateDigest("body string", "sha-256")).toEqual("sha-256=:Vge1353vPF/ryKey6UFOTrM/Pn4p31zzOE5c9rOPCfE=:");
  });
});
