const TARGET_BASE = (Netlify.env.get("TARGET_DOMAIN") || "").replace(/\/$/, "");

// hop-by-hop + risky headers
const STRIP_HEADERS = new Set([
  "host",
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "forwarded",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
]);

export default async function handler(request) {
  if (!TARGET_BASE) {
    return new Response("Misconfigured: TARGET_DOMAIN is not set", { status: 500 });
  }

  try {
    const url = new URL(request.url);
    const targetUrl = new URL(url.pathname + url.search, TARGET_BASE).toString();

    const headers = new Headers();
    let clientIp = null;

    // --- sanitize request headers ---
    for (const [key, value] of request.headers) {
      const k = key.toLowerCase();

      if (STRIP_HEADERS.has(k)) continue;
      if (k.startsWith("x-nf-") || k.startsWith("x-netlify-")) continue;

      if (k === "x-real-ip") {
        clientIp = value;
        continue;
      }

      if (k === "x-forwarded-for") {
        if (!clientIp) clientIp = value.split(",")[0].trim();
        continue;
      }

      headers.set(k, value);
    }

    if (clientIp) {
      headers.set("x-forwarded-for", clientIp);
      headers.set("x-real-ip", clientIp);
    }

    // optional: preserve original host info
    headers.set("x-forwarded-host", url.host);
    headers.set("x-forwarded-proto", url.protocol.replace(":", ""));

    const method = request.method;
    const hasBody = method !== "GET" && method !== "HEAD";

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000); // 15s timeout

    const upstream = await fetch(targetUrl, {
      method,
      headers,
      body: hasBody ? request.body : undefined,
      redirect: "manual",
      signal: controller.signal,
    });

    clearTimeout(timeout);

    // --- sanitize response headers ---
    const responseHeaders = new Headers();

    for (const [key, value] of upstream.headers) {
      const k = key.toLowerCase();

      if (
        k === "transfer-encoding" ||
        k === "connection" ||
        k === "keep-alive" ||
        k === "proxy-authenticate" ||
        k === "proxy-authorization" ||
        k === "te" ||
        k === "trailer" ||
        k === "upgrade"
      ) continue;

      responseHeaders.set(key, value);
    }

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders,
    });

  } catch (error) {
    const msg =
      error.name === "AbortError"
        ? "Upstream timeout"
        : "Bad Gateway";

    return new Response(msg, { status: 502 });
  }
}
