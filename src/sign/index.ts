/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

export * from "./createSignatureHeader";

import { signECDSA } from "./cryptoPrimatives";

import { ClientRequest } from "http";
import { createSignatureHeader, AlgorithmTypes } from "./createSignatureHeader";
import { KeyObject } from "crypto";
import { err, ok, Result } from "neverthrow";

/*
{
        signal?: AbortSignal | undefined;
        protocol?: string | null | undefined;
        host?: string | null | undefined;
        hostname?: string | null | undefined;
        family?: number | undefined;
        port?: number | string | null | undefined;
        defaultPort?: number | string | undefined;
        localAddress?: string | undefined;
        socketPath?: string | undefined;
         maxHeaderSize?: number | undefined;
         method?: string | undefined;
         path?: string | null | undefined;
         headers?: OutgoingHttpHeaders | undefined;
         auth?: string | null | undefined;
         agent?: Agent | boolean | undefined;
         _defaultAgent?: Agent | undefined;
         timeout?: number | undefined;
         setHost?: boolean | undefined;
         // https://github.com/nodejs/node/blob/master/lib/_http_client.js#L278
         createConnection?: ((options: ClientRequestArgs, oncreate: (err: Error, socket: Socket) => void) => Socket) | undefined;
         lookup?: LookupFunction | undefined;
     }
*/

export type SignRequestOptions = {
  /*
   * Algorithm with which to encrypt the signature base.
   */
  alg: AlgorithmTypes;
  /*
   * Private key used for encryption.
   */
  key: KeyObject;
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
      sign: signECDSA(key), // todo
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
