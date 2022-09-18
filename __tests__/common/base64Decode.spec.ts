/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import { encode as encodeBase64 } from "@stablelib/base64";

import { decodeBase64 } from "../../src/common";
import { unwrap } from "../../src/errors";

describe("base64Decode", () => {
  it("Should decode valid base64", (done) => {
    const bytes = new Uint8Array(10);
    const base64 = encodeBase64(bytes);
    const result = decodeBase64(base64);

    expect(unwrap(result)).toEqual(bytes);
    done();
  });

  it("Should return an err with invalid base64", (done) => {
    const result = decodeBase64("Invalid base 64");

    if (result.isOk()) {
      return done.fail("Failed to decode base64 bytes");
    }

    expect(result.error).toEqual("Failed to decode base64 bytes");
    done();
  });
});
