/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import { Parameters } from "structured-headers";

import { generateVerifyData } from "../../src/common";
import { unwrap } from "../../src/errors";

describe("generateVerifyData", () => {
  Date.now = jest.fn(() => 1577836800); //01.01.2020

  const coveredFields: [string, Parameters][] = [
    ["@request-target", new Map()],
    ["@method", new Map()],
    ["header1", new Map()],
    ["header2", new Map()],
  ];

  const validOptions = {
    method: "GET",
    created: Date.now(),
    url: "http://www.test.com/test?query=1",
    httpHeaders: { header1: "value", HEADER2: "value" },
    coveredFields,
  };

  it("Should return a list of entries containing custom spec values and headers when given valid input", (done) => {
    const result = generateVerifyData(validOptions);

    expect(unwrap(result)).toEqual([
      [["@request-target", new Map()], "/test?query=1"],
      [["@method", new Map()], "GET"],
      [["header1", new Map()], "value"],
      [["header2", new Map()], "value"],
    ]);
    done();
  });

  it("Should return an error when duplicate case insensitive headers are used", (done) => {
    const options = {
      ...validOptions,
      httpHeaders: { header1: "value", HEADER1: "value" },
    };
    const result = generateVerifyData(options);
    if (result.isOk()) {
      return done("result is not an error");
    }

    expect(result.error).toEqual("Duplicate case insensitive header keys detected, specify an array of values instead");
    done();
  });

  it("Should return an error when url cannot be resolved", (done) => {
    const options = {
      ...validOptions,
      url: "bad url",
    };

    const result = generateVerifyData(options);

    if (result.isOk()) {
      return done("result is not an error");
    }

    expect(result.error).toEqual("Cannot resolve host, path, protocol and/or query from url");
    done();
  });
});
