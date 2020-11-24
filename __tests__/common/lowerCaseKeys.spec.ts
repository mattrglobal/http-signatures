/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { lowerCaseObjectKeys } from "../../src/common";

describe("lowerCaseKeys", () => {
  it("Should lower case keys and retain values", async () => {
    const testObject = {
      UPPERCASE: true,
      MiXeD: "two",
      lowercase: 3,
      Numb3r5: 0.4,
      ["WITH spaces "]: 555,
    };
    expect(lowerCaseObjectKeys(testObject)).toMatchObject({
      uppercase: true,
      mixed: "two",
      lowercase: 3,
      numb3r5: 0.4,
      ["with spaces "]: 555,
    });
  });
});
