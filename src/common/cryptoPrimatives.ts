/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import crypto, { JsonWebKey } from "crypto";

import { AlgorithmTypes } from "../sign";

export const signEcdsaSha256 =
  (key: JsonWebKey) =>
  async (data: Uint8Array): Promise<Uint8Array> => {
    const keyObject = crypto.createPrivateKey({ key, format: "jwk" });
    return crypto.createSign("SHA256").update(data).sign({ key: keyObject, dsaEncoding: "ieee-p1363" });
  };

export const verifyEcdsaSha256 =
  (key: JsonWebKey) =>
  async (data: Uint8Array, signature: Uint8Array): Promise<boolean> => {
    const keyObject = crypto.createPublicKey({ key, format: "jwk" });
    return crypto.createVerify("SHA256").update(data).verify({ key: keyObject, dsaEncoding: "ieee-p1363" }, signature);
  };

export const signRssV1_5Sha256 =
  (key: JsonWebKey) =>
  async (data: Uint8Array): Promise<Uint8Array> => {
    const keyObject = crypto.createPrivateKey({ key, format: "jwk" });
    return crypto
      .createSign("SHA256")
      .update(data)
      .sign({ key: keyObject, dsaEncoding: "ieee-p1363", padding: crypto.constants.RSA_PKCS1_PADDING });
  };

export const verifyRssV1_5Sha256 =
  (key: JsonWebKey) =>
  async (data: Uint8Array, signature: Uint8Array): Promise<boolean> => {
    const keyObject = crypto.createPublicKey({ key, format: "jwk" });
    return crypto
      .createVerify("SHA256")
      .update(data)
      .verify({ key: keyObject, dsaEncoding: "ieee-p1363", padding: crypto.constants.RSA_PKCS1_PADDING }, signature);
  };

export const signHmacSha256 = (key: JsonWebKey) => {
  return async (data: Uint8Array): Promise<Uint8Array> => {
    const keyObject = key.k ? crypto.createSecretKey(key.k, "base64") : undefined;
    if (keyObject == undefined) {
      throw Error("Unable to parse key object");
    }
    const hmac = crypto.createHmac("SHA256", keyObject);
    hmac.write(data);
    hmac.end();
    return hmac.read();
  };
};

export const verifyHmacSha256 =
  (key: JsonWebKey) =>
  async (data: Uint8Array, signature: Uint8Array): Promise<boolean> => {
    const keyObject = key.k ? crypto.createSecretKey(key.k, "base64") : undefined;
    if (keyObject == undefined) {
      throw Error("Unable to parse key object");
    }
    const hmac = crypto.createHmac("SHA256", keyObject);
    hmac.write(data);
    hmac.end();
    return Buffer.compare(hmac.read(), signature) == 0;
  };

export const signEcdsaSha384 =
  (key: JsonWebKey) =>
  async (data: Uint8Array): Promise<Uint8Array> => {
    const keyObject = crypto.createPrivateKey({ key, format: "jwk" });
    return crypto.createSign("SHA384").update(data).sign({ key: keyObject, dsaEncoding: "ieee-p1363" });
  };

export const verifyEcdsaSha384 =
  (key: JsonWebKey) =>
  async (data: Uint8Array, signature: Uint8Array): Promise<boolean> => {
    const keyObject = crypto.createPublicKey({ key, format: "jwk" });
    return await crypto
      .createVerify("SHA384")
      .update(data)
      .verify({ key: keyObject, dsaEncoding: "ieee-p1363" }, signature);
  };

export const signRsaPssSha512 =
  (key: JsonWebKey) =>
  async (data: Uint8Array): Promise<Uint8Array> => {
    const keyObject = crypto.createPrivateKey({ key, format: "jwk" });
    return await crypto
      .createSign("SHA512")
      .update(data)
      .sign({ key: keyObject, dsaEncoding: "ieee-p1363", padding: crypto.constants.RSA_PKCS1_PSS_PADDING });
  };

export const verifyRsaPssSha512 =
  (key: JsonWebKey) =>
  async (data: Uint8Array, signature: Uint8Array): Promise<boolean> => {
    const keyObject = crypto.createPublicKey({ key, format: "jwk" });
    return crypto
      .createVerify("SHA512")
      .update(data)
      .verify(
        { key: keyObject, dsaEncoding: "ieee-p1363", padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
        signature
      );
  };

export const signEd25519 =
  (key: JsonWebKey) =>
  async (data: Uint8Array): Promise<Uint8Array> => {
    const keyObject = crypto.createPrivateKey({ key, format: "jwk" });
    return crypto.sign(null, data, keyObject);
  };

export const verifyEd25519 =
  (key: JsonWebKey) =>
  async (data: Uint8Array, signature: Uint8Array): Promise<boolean> => {
    const keyObject = crypto.createPublicKey({ key, format: "jwk" });
    return crypto.verify(null, data, keyObject, signature);
  };

type VerifyFunctionWrapper = (privateKey: JsonWebKey) => VerifyFunction;

type VerifyFunction = (data: Uint8Array, signature: Uint8Array) => Promise<boolean>;

type SignFunctionWrapper = (privateKey: JsonWebKey) => SignFunction;

type SignFunction = (data: Uint8Array) => Promise<Uint8Array>;

export const verifyDefault =
  (keyMap: { [keyid: string]: { key: JsonWebKey } }) =>
  async (
    signatureParams: { keyid: string; alg: AlgorithmTypes },
    data: Uint8Array,
    signature: Uint8Array
  ): Promise<boolean> => {
    return algMap[signatureParams.alg].verify(keyMap[signatureParams.keyid].key)(data, signature);
  };

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
  ["rsa-v1_5-sha256"]: {
    sign: signRssV1_5Sha256,
    verify: verifyRssV1_5Sha256,
  },
  ["hmac-sha256"]: {
    sign: signHmacSha256,
    verify: verifyHmacSha256,
  },
  ["ecdsa-p384-sha384"]: {
    sign: signEcdsaSha384,
    verify: verifyEcdsaSha384,
  },
  ["ecdsa-p256-sha256"]: {
    sign: signEcdsaSha256,
    verify: verifyEcdsaSha256,
  },
  ["ed25519"]: {
    sign: signEd25519,
    verify: verifyEd25519,
  },
};
