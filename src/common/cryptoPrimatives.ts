/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import crypto from "crypto";

export const signSha256 =
  (privateKey: crypto.KeyObject) =>
  async (data: Uint8Array): Promise<Uint8Array> => {
    return await crypto.createSign("SHA256").update(data).sign({ key: privateKey, dsaEncoding: "ieee-p1363" });
  };

export const verifySha256 =
  (keyMap: { [keyid: string]: crypto.KeyObject }) =>
  async (keyid: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> => {
    return await crypto
      .createVerify("SHA256")
      .update(data)
      .verify({ key: keyMap[keyid], dsaEncoding: "ieee-p1363" }, signature);
  };

export const signHmacSha256 =
  (privateKey: crypto.KeyObject) =>
  async (data: Uint8Array): Promise<Uint8Array> => {
    const hmac = crypto.createHmac("SHA256", privateKey);
    hmac.write(data);
    hmac.end();
    return hmac.read();
  };

export const verifyHmacSha256 =
  (keyMap: { [keyid: string]: crypto.KeyObject }) =>
  async (keyid: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> => {
    const hmac = crypto.createHmac("SHA256", keyMap[keyid]);
    hmac.write(data);
    hmac.end();
    return Buffer.compare(hmac.read(), signature) == 0;
  };

export const signEcdsaSha384 =
  (privateKey: crypto.KeyObject) =>
  async (data: Uint8Array): Promise<Uint8Array> => {
    return await crypto.createSign("SHA384").update(data).sign({ key: privateKey, dsaEncoding: "ieee-p1363" });
  };

export const verifyEcdsaSha384 =
  (keyMap: { [keyid: string]: crypto.KeyObject }) =>
  async (keyid: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> => {
    return await crypto
      .createVerify("SHA384")
      .update(data)
      .verify({ key: keyMap[keyid], dsaEncoding: "ieee-p1363" }, signature);
  };

export const signRsaPssSha512 =
  (privateKey: crypto.KeyObject) =>
  async (data: Uint8Array): Promise<Uint8Array> => {
    return await crypto
      .createSign("SHA512")
      .update(data)
      .sign({ key: privateKey, dsaEncoding: "ieee-p1363", padding: crypto.constants.RSA_PKCS1_PSS_PADDING });
  };

export const verifyRsaPssSha512 =
  (keyMap: { [keyid: string]: crypto.KeyObject }) =>
  async (keyid: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> => {
    return crypto
      .createVerify("SHA512")
      .update(data)
      .verify(
        { key: keyMap[keyid], dsaEncoding: "ieee-p1363", padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
        signature
      );
  };

export const signEd25519 =
  (privateKey: crypto.KeyObject) =>
  async (data: Uint8Array): Promise<Uint8Array> => {
    return crypto.sign(null, data, privateKey);
  };

export const verifyEd25519 =
  (keyMap: { [keyid: string]: crypto.KeyObject }) =>
  async (keyid: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> => {
    return crypto.verify(null, data, keyMap[keyid], signature);
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
  ["rsa-pss-sha512"]: {
    sign: signRsaPssSha512,
    verify: verifyRsaPssSha512,
  },
  // TODO implement remaining algorithms and corresponding tests from the spec
  // ["rsa-v1_5-sha256"]: {
  //   sign: signSha256,
  //   verify: verifySha256,
  // },
  ["hmac-sha256"]: {
    sign: signHmacSha256,
    verify: verifyHmacSha256,
  },
  ["ecdsa-p384-sha384"]: {
    sign: signEcdsaSha384,
    verify: verifyEcdsaSha384,
  },
  ["ecdsa-p256-sha256"]: {
    sign: signSha256,
    verify: verifySha256,
  },
  ["ed25519"]: {
    sign: signEd25519,
    verify: verifyEd25519,
  },
};
