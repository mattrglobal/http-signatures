import { algMap } from "../common/cryptoPrimatives";

import { ClientRequest } from "http";
import { createSignatureHeader, AlgorithmTypes } from "./createSignatureHeader";
import { KeyObject } from "crypto";
import { err, ok, Result } from "neverthrow";

export type SignRequestOptions = {
  /*
   * Algorithm with which to encrypt the signature base.
   */
  alg: AlgorithmTypes;
  /*
   * Private key used for encryption.
   */
  key: KeyObject | Uint8Array;
  /*
   * Identifier for the key used for encryption.
   */
  keyid: string;
  /*
   * The request that you intend to sign
   */
  request: ClientRequest;
};
export const signRequest = async (options: SignRequestOptions): Promise<Result<ClientRequest, Error>> => {
  const { alg, key, keyid, request } = options;

  const test = await createSignatureHeader({
    signer: {
      keyid: keyid,
      sign: algMap[alg].sign(key),
    },
    url: `${request.protocol}//${request.host}${request.path}`,
    method: `${request.method}`,
    httpHeaders: request.getHeaders() as { [key: string]: string | string[] | undefined },
    alg,
  });

  if (test.isErr()) {
    return err({ name: "Error", message: "failed to create signature header" });
  }

  request.setHeader("Signature", test.value.signature);
  request.setHeader("Signature-Input", test.value.signatureInput);
  test.value.digest && request.setHeader("Content-Digest", test.value.digest);

  return ok(request);
};
