/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import { generateVerifyData } from "../../src/common";

describe("generateVerifyData", () => {
  Date.now = jest.fn(() => 1577836800); //01.01.2020

  const validOptions = {
    method: "GET",
    created: Date.now(),
    url: "http://www.test.com/test?query=1",
    httpHeaders: { header1: "value", HEADER2: "value" },
  };

  it("Should return an object containing custom spec values and headers when given valid input", (done) => {
    const result = generateVerifyData(validOptions);

    if (result.isErr()) {
      return fail(result.error);
    }
    expect(result.value).toMatchObject({
      ["@request-target"]: "/test?query=1",
      ["@method"]: "GET",
      host: "www.test.com",
      header1: "value",
      header2: "value",
    });
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

    expect(result.error).toEqual("Cannot resolve host and path from url");
    done();
  });
});
