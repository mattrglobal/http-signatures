/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import http from "http";
import express from "express";
import axios from "axios";

describe("verifySignatureHeader", () => {
  let server: http.Server;
  let hostname: string;
  let port: number;

  const app = express();
  app.use("/test", (req, res) => {
    const request = {
      url: req.url,
      path: req.path,
      method: req.method,
      params: req.params,
      headers: req.headers,
      httpVersion: req.httpVersion,
    };

    try {
      res.send({ request });
    } catch (error) {
      res.send({ request, error });
    }
  });

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      server = app.listen(() => resolve());
    });

    const address = server.address();
    if (typeof address !== "object") {
      throw new Error("Unexpected server address");
    }
    hostname = "127.0.0.1";
    port = address?.port!;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it("should pass", async () => {
    const resp = await axios.request({
      url: `http://${hostname}:${port}/test`,
      method: "GET",
      headers: {
        "Content-Type": "text/plain",
      },
    });
    console.info("--- resp", resp.data);
  });
});
