/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import { encodeURLSafe as encodeBase64Url } from "@stablelib/base64";

import { decodeBase64Url } from "../../src/common";

describe("base64Decode", () => {
  it("Should decode valid base64", (done) => {
    const bytes = new Uint8Array(10);
    const base64 = encodeBase64Url(bytes);
    const result = decodeBase64Url(base64);

    if (result.isErr()) {
      return done.fail(result.error);
    }

    expect(result.value).toEqual(bytes);
    done();
  });

  it("Should return an err with invalid base64", (done) => {
    const result = decodeBase64Url("Invalid base 64");

    if (result.isOk()) {
      return done.fail("Failed to decode base64 bytes");
    }

    expect(result.error).toEqual("Failed to decode base64 bytes");
    done();
  });
});
