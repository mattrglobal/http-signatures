/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
/* eslint-disable functional/immutable-data,no-undef */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const pack = require("./package");
module.exports = {
  collectCoverage: true,
  coverageDirectory: "jest_results/coverage/",
  coverageReporters: ["html", "lcov"],
  coveragePathIgnorePatterns: ["/node_modules/", "/__tests__/"],
  displayName: pack.name,
  name: pack.name,
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: ["**/*.spec.ts", "**/*.test.ts"],
  testPathIgnorePatterns: ["/node_modules/", "/lib/"],
};
