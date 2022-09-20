/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import crypto from "crypto";

export const signECDSA =
  (privateKey: crypto.KeyObject) =>
  async (data: Uint8Array): Promise<Uint8Array> => {
    return await crypto.createSign("SHA256").update(data).sign({ key: privateKey, dsaEncoding: "ieee-p1363" });
  };

export const verifyECDSA =
  (keyMap: { [keyid: string]: crypto.KeyObject }) =>
  async (keyid: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> => {
    return await crypto
      .createVerify("SHA256")
      .update(data)
      .verify({ key: keyMap[keyid], dsaEncoding: "ieee-p1363" }, signature);
  };
