import { wrapServerWithClientIp, type RequestServerLike } from "./client-ip";
import { consumeUnauthorizedRateLimit } from "../rateLimit";

export type RouteHandler = (req: Request, url: URL, server: unknown) => Promise<Response | null>;

function tooManyRequestsResponse(retryAfter = 60): Response {
  return new Response("Too many requests", {
    status: 429,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Retry-After": String(retryAfter),
    },
  });
}

export function createHttpFetchHandler(deps: {
  metrics: { withHttpMetrics: (fn: () => Promise<Response>) => Promise<Response> };
  CORS_HEADERS: Record<string, string>;
  routes: RouteHandler[];
}) {
  return async function fetchHandler(req: Request, server: unknown): Promise<Response> {
    return deps.metrics.withHttpMetrics(async () => {
      if (req.method === "OPTIONS") {
        return new Response("", { headers: deps.CORS_HEADERS });
      }
      const url = new URL(req.url);
      const wrapped = wrapServerWithClientIp(server as RequestServerLike);
      const ip = wrapped.requestIP(req)?.address || "unknown";

      for (const route of deps.routes) {
        const response = await route(req, url, wrapped);
        if (response) {
          if (response.status === 401) {
            const limited = consumeUnauthorizedRateLimit(ip);
            if (limited.limited) return tooManyRequestsResponse(limited.retryAfter);
          }
          return response;
        }
      }
      return new Response("Not found", { status: 404 });
    });
  };
}
