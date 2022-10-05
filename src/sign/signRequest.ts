/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import { JsonWebKey } from "crypto";
import { ClientRequest } from "http";
import { err, ok, Result } from "neverthrow";
import { SuperAgentRequest } from "superagent";

import { algMap } from "../common/cryptoPrimatives";

import { createSignatureHeader, AlgorithmTypes } from "./createSignatureHeader";

export type SignOptions = { alg: AlgorithmTypes; key: JsonWebKey; keyid: string; data?: string };
export type SignHttpOptions = {
  alg: AlgorithmTypes;
  key: JsonWebKey;
  keyid: string;
  data?: string;
  request: ClientRequest;
};
export type SignSuperAgentOptons = {
  alg: AlgorithmTypes;
  key: JsonWebKey;
  keyid: string;
  data?: string;
  request: SuperAgentRequest;
};

function isSuperAgentRequest(req: SuperAgentRequest | ClientRequest): req is SuperAgentRequest {
  return (
    (<SuperAgentRequest>req).agent !== undefined &&
    (<SuperAgentRequest>req).cookies !== undefined &&
    (<SuperAgentRequest>req).method !== undefined &&
    (<SuperAgentRequest>req).url !== undefined
  );
}

type SignRequestOptions<T> = SignOptions & { request: T };

export async function signRequest(
  options: SignRequestOptions<SuperAgentRequest>
): Promise<Result<SuperAgentRequest, Error>>;
export async function signRequest(options: SignRequestOptions<ClientRequest>): Promise<Result<ClientRequest, Error>>;
export async function signRequest(
  options: SignRequestOptions<ClientRequest> | SignRequestOptions<SuperAgentRequest>
): Promise<Result<ClientRequest | SuperAgentRequest, Error>> {
  const { request } = options;

  if (request instanceof ClientRequest) {
    return signHttpRequest({ ...options, request });
  } else if (isSuperAgentRequest(request)) {
    return signSuperAgentRequest({ ...options, request });
  }
  return err({ name: "Error", message: "Signing request failed, unable to determine request type" });
}

/*
  Signs an outgoing node http request.
*/
const signHttpRequest = async <T extends ClientRequest>(options: SignRequestOptions<T>): Promise<Result<T, Error>> => {
  const { alg, key, keyid, request, data } = options;

  const signResult = await createSignatureHeader({
    signer: {
      keyid: keyid,
      sign: algMap[alg].sign(key),
    },
    url: `${request.protocol}//${request.host}${request.path}`,
    method: request.method,
    httpHeaders: request.getHeaders() as { [key: string]: string | string[] | undefined },
    alg,
    ...(data ? { body: data } : {}),
  });

  if (signResult.isErr()) {
    return err({ name: "Error", message: "failed to create signature header" });
  }

  request.setHeader("Signature", signResult.value.signature);
  request.setHeader("Signature-Input", signResult.value.signatureInput);
  signResult.value.digest && request.setHeader("Content-Digest", signResult.value.digest);

  if (data) {
    request.write(data);
  }

  return ok(request);
};

/*
  Signs an outgoing SuperAgent request.
*/
const signSuperAgentRequest = async <T extends SuperAgentRequest>(
  options: SignRequestOptions<T>
): Promise<Result<T, Error>> => {
  const { alg, key, keyid, request } = options;

  const signResult = await createSignatureHeader({
    signer: {
      keyid: keyid,
      sign: algMap[alg].sign(key),
    },
    url: request.url,
    method: request.method,
    httpHeaders: JSON.parse(JSON.stringify(request)).headers, // Workaround for inability to access superagent request proprties directly
    alg,
    body: JSON.parse(JSON.stringify(request)).data, // Workaround for inability to access superagent request proprties directly
  });

  if (signResult.isErr()) {
    return err({ name: "Error", message: "failed to create signature header" });
  }

  request.set("Signature", signResult.value.signature);
  request.set("Signature-Input", signResult.value.signatureInput);
  signResult.value.digest && request.set("Content-Digest", signResult.value.digest);

  return ok(request);
};
