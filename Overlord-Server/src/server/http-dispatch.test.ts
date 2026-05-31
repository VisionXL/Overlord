import { beforeEach, describe, expect, test } from "bun:test";
import { clearRequestRateLimitsForTests } from "../rateLimit";
import { createHttpFetchHandler } from "./http-dispatch";

const metrics = {
  withHttpMetrics: (fn: () => Promise<Response>) => fn(),
};

function makeServer(ip: string) {
  return {
    requestIP: () => ({ address: ip }),
    upgrade: () => false,
  };
}

beforeEach(() => {
  clearRequestRateLimitsForTests();
});

describe("createHttpFetchHandler rate limiting", () => {
  test("throttles repeated unauthorized responses from the same IP", async () => {
    const handler = createHttpFetchHandler({
      metrics,
      CORS_HEADERS: {},
      routes: [async () => new Response("Unauthorized", { status: 401 })],
    });

    for (let i = 0; i < 120; i += 1) {
      const res = await handler(new Request("https://localhost/api/private"), makeServer("203.0.113.10"));
      expect(res.status).toBe(401);
    }

    const limited = await handler(new Request("https://localhost/api/private"), makeServer("203.0.113.10"));
    expect(limited.status).toBe(429);
    expect(limited.headers.get("Retry-After")).toBeTruthy();
  });
});
