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

export const signEd25519 =
  (privateKey: crypto.KeyObject) =>
  async (data: Uint8Array): Promise<Uint8Array> => {
    return await crypto.sign(null, data, privateKey);
  };

export const verifyEd25519 =
  (keyMap: { [keyid: string]: crypto.KeyObject }) =>
  async (keyid: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> => {
    return await crypto.verify(null, data, keyMap[keyid], signature);
  };

type keyMap = {
  [keyid: string]: crypto.KeyObject;
};

type VerifyFunctionWrapper = (keyMap: keyMap) => VerifyFunction;

type VerifyFunction = (keyid: string, data: Uint8Array, signature: Uint8Array) => Promise<boolean>;

type SignFunctionWrapper = (privateKey: crypto.KeyObject) => SignFunction;

type SignFunction = (data: Uint8Array) => Promise<Uint8Array>;

export const algMap: {
  [key: string]: {
    sign: SignFunctionWrapper;
    verify: VerifyFunctionWrapper;
  };
} = {
  // ["rsa-pss-sha512"] = "rsa-pss-sha512",
  // ["rsa-v1_5-sha256"] = "rsa-v1_5-sha256",
  // ["hmac-sha256"] = "hmac-sha256",
  // ["ecdsa-p384-sha384"] = "ecdsa-p384-sha384",
  ["ecdsa-p256-sha256"]: {
    sign: signECDSA,
    verify: verifyECDSA,
  },
  ["ed25519"]: {
    sign: signEd25519,
    verify: verifyEd25519,
  },
};
