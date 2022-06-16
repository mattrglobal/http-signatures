/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { generateSortedVerifyDataEntries } from "../../src/common";
import { verifyData } from "../__fixtures__/verifyData";

describe("generateSortedVerifyDataEntries", () => {
  it("Should sort data according to headers order", (done) => {
    const headers = "(request-target) (created) host key1";
    const result = generateSortedVerifyDataEntries(verifyData, headers);
    if (result.isErr()) {
      return done.fail("result was not ok");
    }
    expect(result.value).toEqual([
      ["(request-target)", "request target"],
      ["(created)", "created"],
      ["host", "host"],
      ["key1", "value"],
    ]);
    done();
  });

  it("Should sort with a default if no headers string is specified", (done) => {
    const result = generateSortedVerifyDataEntries(verifyData);
    if (result.isErr()) {
      return done.fail("result was not ok");
    }
    expect(result.value).toEqual([
      ["(created)", "created"],
      ["(request-target)", "request target"],
      ["host", "host"],
      ["key1", "value"],
    ]);
    done();
  });

  it("Should return an error if headers does not map to every key of verifyData", (done) => {
    const headers = "(request-target) (created) host key1 unknownKey";
    const result = generateSortedVerifyDataEntries(verifyData, headers);

    if (result.isOk()) {
      return done.fail("result was not an error");
    }

    expect(result.error).toEqual("Header string must include the exact keys within verifyData");
    done();
  });
});
