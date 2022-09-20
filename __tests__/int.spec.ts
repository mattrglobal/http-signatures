/*
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */
import http from "http";

describe("verifySignatureHeader", () => {
  let server: http.Server;
  let host: string;
  let port: number;

  type Response = {
    headers: Record<string, unknown>;
    statusCode: number | undefined;
    body: unknown;
  };
  const request = (options: http.RequestOptions): Promise<Response> => {
    return new Promise<Response>((resolve, reject) => {
      const req = http.request(options, (res) => {
        // NOTE: This is an example of collecting response body, useful when testing
        //       signature verification
        const chunks: unknown[] = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          resolve({
            headers: res.headers,
            statusCode: res.statusCode,
            body: JSON.parse(chunks.join("")),
          });
        });
      });

      // TODO generate http signature, this is fake value
      const signature = JSON.stringify(req.getHeaders());
      req.setHeader("signature-params", signature);

      req.on("error", (error) => reject(error));
      req.end();
    });
  };

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      if (req.url === "/test") {
        const data = {
          headers: req.headers,
        };
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(data));
      } else {
        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end(JSON.stringify({ error: "Not Found" }));
      }
    });

    await new Promise<void>((resolve) => {
      server.listen(() => resolve());
    });

    const address = server.address();
    if (typeof address !== "object") {
      throw new Error("Unexpected server address");
    }
    host = "127.0.0.1";
    port = address?.port!;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it("should respond 200 OK", async () => {
    const res = await request({
      host,
      port,
      path: "/test",
      method: "GET",
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers).toEqual({
      connection: "close",
      date: expect.any(String),
      "content-type": "application/json",
      "transfer-encoding": "chunked",
    });
  });

  it("should respond 404 Not Found", async () => {
    const res = await request({
      host,
      port,
      path: "/",
      method: "GET",
    });
    expect(res.statusCode).toBe(404);
  });
});
