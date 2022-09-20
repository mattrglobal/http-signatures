/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import crypto from "crypto";
import { sign, verify } from "@stablelib/ed25519";

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

export const signEd25519 =
  (privateKey: Uint8Array) =>
  async (data: Uint8Array): Promise<Uint8Array> => {
    return await sign(privateKey, data);
  };

export const verifyEd25519 =
  (keyMap: { [keyid: string]: Uint8Array }) =>
  async (keyid: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> => {
    return await verify(keyMap[keyid], data, signature);
  };

export const algMap: {
  [key: string]: { sign: (privateKey: any) => (data: Uint8Array) => Promise<Uint8Array>; verify: (keymap: any) => any };
} = {
  // ["rsa-pss-sha512"] = "rsa-pss-sha512",
  // ["rsa-v1_5-sha256"] = "rsa-v1_5-sha256",
  // ["hmac-sha256"] = "hmac-sha256",
  ["ecdsa-p256-sha256"]: {
    sign: signECDSA,
    verify: verifyECDSA,
  },
  ["ed25519"]: {
    sign: signEd25519,
    verify: verifyEd25519,
  },
};
