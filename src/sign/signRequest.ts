/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */ import { KeyObject } from "crypto";
import { ClientRequest } from "http";
import { err, ok, Result } from "neverthrow";
import { SuperAgentRequest } from "superagent";

import { algMap } from "../common/cryptoPrimatives";

import { createSignatureHeader, AlgorithmTypes } from "./createSignatureHeader";

function isSuperAgentRequest(req: SuperAgentRequest | ClientRequest): req is SuperAgentRequest {
  return (
    (<SuperAgentRequest>req).agent !== undefined &&
    (<SuperAgentRequest>req).cookies !== undefined &&
    (<SuperAgentRequest>req).method !== undefined &&
    (<SuperAgentRequest>req).url !== undefined
  );
}

export type SignOptions = { alg: AlgorithmTypes; key: KeyObject; keyid: string; data?: string };

type SignRequestOptions<T> = SignOptions & { request: T };

export const signRequest = async <T extends ClientRequest | SuperAgentRequest>(
  options: SignRequestOptions<T>
): Promise<Result<T, Error>> => {
  const { alg, key, keyid, request, data } = options;

  // node http ClientRequest
  if (request instanceof ClientRequest) {
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
  }
  // SuperAgent SuperAgentRequest
  else if (isSuperAgentRequest(request)) {
    const signResult = await createSignatureHeader({
      signer: {
        keyid: keyid,
        sign: algMap[alg].sign(key),
      },
      url: request.url,
      method: request.method,
      httpHeaders: JSON.parse(JSON.stringify(request)).headers, // TODO
      alg,
      body: JSON.parse(JSON.stringify(request)).data, // TODO
    });

    if (signResult.isErr()) {
      return err({ name: "Error", message: "failed to create signature header" });
    }

    request.set("Signature", signResult.value.signature);
    request.set("Signature-Input", signResult.value.signatureInput);
    signResult.value.digest && request.set("Content-Digest", signResult.value.digest);

    return ok(request);
  }
  return err(new Error("could not identify request type"));
};
