/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import { Result } from "neverthrow";

type Error = { type: "Error"; message: string };
type MalformedInput = { type: "MalformedInput"; message: string };
type SignFailed = { type: "SignFailed"; message: string };
type VerifyFailed = { type: "VerifyFailed"; message: string };

/**
 * A utility function to get the value from a {@link Result} or throw if there was an error
 *
 * @remarks
 * Allows you to get the value of a result directly or handle an error {@link Result} as an exception
 *
 * @param result - The {@link Result} to unwrap
 * @param errMessage - Error message used when unwrap failed
 * @typeParam T - the expected value of an ok result
 */
export const unwrap = <T = unknown>(result: Result<T, unknown>, errMessage?: string): T => {
  if (result.isOk()) {
    return result.value;
  }

  throw new Exception(errMessage || "Error unwrapping result", result.error);
};

/**
 * Instance of an exception
 *
 * @remarks
 * Used to raise exception when something unexpeced occurs
 *
 * @example
 * ```
 * throw new Exception();
 * throw new Exception(erorr);
 * throw new Exception("Unexpected error occur signing", error);
 * ```
 */
export class Exception extends Error {
  public readonly cause?: unknown;

  constructor(message: string);
  constructor(cause: unknown);
  constructor(message: string | unknown, cause: unknown);

  constructor(messageOrCause: string | unknown, cause?: unknown) {
    const message = typeof messageOrCause === "string" ? messageOrCause : "Exception";
    super(message);
    Object.setPrototypeOf(this, new.target.prototype); // restore prototype chain
    this.cause = cause || messageOrCause;
    Error.captureStackTrace(this);
  }
}

export type CreateSignatureHeaderError = Error | MalformedInput | SignFailed;
export type VerifySignatureHeaderError = Error | VerifyFailed;
