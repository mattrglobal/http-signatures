/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { generateSortedVerifyDataEntries } from "../../src/common";
import { unwrap } from "../../src/errors";
import { verifyData } from "../__fixtures__/verifyData";

describe("generateSortedVerifyDataEntries", () => {
  it("Should sort data according to coveredfields order", (done) => {
    const coveredFields = ["@method", "@request-target", "host"];
    const result = generateSortedVerifyDataEntries(verifyData, coveredFields);
    expect(unwrap(result)).toEqual([
      ["@method", "POST"],
      ["@request-target", "request target"],
      ["host", "host"],
    ]);
    done();
  });

  it("Should sort with a default if no covered fields list is specified", (done) => {
    const result = generateSortedVerifyDataEntries(verifyData);
    expect(unwrap(result)).toEqual([
      ["@method", "POST"],
      ["@request-target", "request target"],
      ["host", "host"],
    ]);
    done();
  });

  it("Should return an error if covered fields do not map to every key of verifyData", (done) => {
    const coveredFields = ["@method", "@request-target", "host", "unknownkey"];
    const result = generateSortedVerifyDataEntries(verifyData, coveredFields);

    if (result.isOk()) {
      return done("result was not an error");
    }

    expect(result.error).toEqual("Covered fields list must include the exact keys within verifyData");
    done();
  });
});
