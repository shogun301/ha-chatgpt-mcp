const ALLOWED_PATHS = [
  "/mcp",
  "/healthz",
  "/oauth/authorize",
  "/oauth/authorize/decision",
  "/oauth/token",
  "/oauth/register",
  "/solaredge/oauth/callback",
  "/.well-known/oauth-authorization-server",
  "/.well-known/openid-configuration",
  "/.well-known/oauth-protected-resource",
  "/.well-known/oauth-protected-resource/mcp"
];

export default {
  async fetch(request, env) {
    if (!env.ORIGIN_URL || !env.ORIGIN_SHARED_SECRET) {
      return new Response("Worker configuration incomplete", { status: 503 });
    }
    const incoming = new URL(request.url);
    if (!ALLOWED_PATHS.includes(incoming.pathname)) {
      return new Response("Not found", { status: 404 });
    }
    const contentLength = Number(request.headers.get("content-length") || "0");
    if (contentLength > 1024 * 1024) {
      return new Response("Request too large", { status: 413 });
    }
    const origin = new URL(incoming.pathname + incoming.search, env.ORIGIN_URL);
    const headers = new Headers(request.headers);
    headers.set("x-origin-shared-secret", env.ORIGIN_SHARED_SECRET);
    headers.set("x-forwarded-host", incoming.host);
    headers.set("x-forwarded-proto", "https");
    headers.delete("cf-access-jwt-assertion");
    const response = await fetch(origin, {
      method: request.method,
      headers,
      body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
      redirect: "manual"
    });
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set("strict-transport-security", "max-age=31536000; includeSubDomains");
    responseHeaders.set("x-content-type-options", "nosniff");
    responseHeaders.delete("server");
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
  }
};
