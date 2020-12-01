/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import { generateVerifyDataEntries } from "../../src/common";

describe("generateVerifyDataEntries", () => {
  Date.now = jest.fn(() => 1577836800); //01.01.2020

  const validOptions = {
    method: "GET",
    created: Date.now(),
    url: "http://www.test.com/test?query=1",
    httpHeaders: { header1: "value", HEADER2: "value" },
  };

  it("Should return entries of custom spec values and headers when given valid input", async () => {
    expect(generateVerifyDataEntries(validOptions)).toEqual([
      ["(created)", "1577836800"],
      ["(request-target)", "get /test?query=1"],
      ["HEADER2", "value"],
      ["header1", "value"],
      ["host", "www.test.com"],
    ]);
  });

  it("Should throw an error when duplicate case insensitive headers are used", async () => {
    const options = {
      ...validOptions,
      httpHeaders: { header1: "value", HEADER1: "value" },
    };
    expect(() => generateVerifyDataEntries(options)).toThrow(
      Error("duplicate case insensitive header keys detected. Specify an array of values instead.")
    );
  });

  it("Should throw an error when created date is in the future", async () => {
    const options = {
      ...validOptions,
      created: Date.now() + Date.now(),
    };
    expect(() => generateVerifyDataEntries(options)).toThrow(Error("created date cannot be in the future"));
  });

  it("Should throw an error when url cannot be resolved", async () => {
    const options = {
      ...validOptions,
      url: "bad url",
    };
    expect(() => generateVerifyDataEntries(options)).toThrow(Error("cannot resolve host and path from url"));
  });
});
