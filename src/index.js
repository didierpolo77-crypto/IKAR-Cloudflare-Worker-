const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return json({
        service: "IKAR Assistant API",
        status: "online",
        ai: "not_configured"
      });
    }

    if (url.pathname !== "/v1/chat") {
      return json({ error: "not_found" }, 404);
    }

    if (request.method !== "POST") {
      return json({ error: "method_not_allowed" }, 405);
    }

    const token = env.IKAR_API_TOKEN;
    const authorization = request.headers.get("Authorization") || "";
    if (!token || !constantTimeEqual(authorization, `Bearer ${token}`)) {
      return json({ error: "unauthorized" }, 401);
    }

    const declaredLength = Number(request.headers.get("Content-Length") || "0");
    if (declaredLength > 12000) {
      return json({ error: "request_too_large" }, 413);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: "invalid_json" }, 400);
    }

    if (!body || typeof body.message !== "string" ||
        body.message.trim().length === 0 || body.message.length > 4000) {
      return json({ error: "invalid_message" }, 400);
    }

    // The API shell is ready. Connect a model provider before returning AI answers.
    return json({
      error: "ai_not_configured",
      service: "IKAR Assistant API",
      message: "Le serveur fonctionne, mais le moteur IA en ligne n'est pas encore configuré."
    }, 503);
  }
};
