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

const SYSTEM_PROMPT = `Tu es IKAR, un assistant numérique francophone, utile, calme et honnête.
Réponds en français sauf demande contraire. Sois clair, pratique et concis.
N'affirme jamais avoir effectué une action sur le téléphone si elle n'a pas réellement été exécutée.
Explique les limites d'Android et demande une confirmation avant toute action sensible.
Pour les questions de sécurité, distingue les indices d'une preuve et recommande des étapes prudentes.`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return json({
        service: "IKAR Assistant API",
        status: "online",
        ai: env.AI ? "binding_configured" : "not_configured"
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

    if (!env.AI || typeof env.AI.run !== "function") {
      return json({ error: "ai_binding_missing" }, 503);
    }

    const declaredLength = Number(request.headers.get("Content-Length") || "0");
    if (declaredLength > 12000) {
      return json({ error: "request_too_large" }, 413);
    }

    let raw;
    try {
      raw = await request.text();
      if (raw.length > 12000) return json({ error: "request_too_large" }, 413);
    } catch {
      return json({ error: "invalid_request" }, 400);
    }

    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      return json({ error: "invalid_json" }, 400);
    }

    if (!body || typeof body.message !== "string" ||
        body.message.trim().length === 0 || body.message.length > 4000) {
      return json({ error: "invalid_message" }, 400);
    }

    const history = Array.isArray(body.history) ? body.history.slice(-10) : [];
    const messages = [{ role: "system", content: SYSTEM_PROMPT }];

    for (const item of history) {
      if (!item || !["user", "assistant"].includes(item.role) ||
          typeof item.content !== "string" || item.content.length > 2000) {
        return json({ error: "invalid_history" }, 400);
      }
      messages.push({ role: item.role, content: item.content });
    }
    messages.push({ role: "user", content: body.message });

    try {
      const result = await env.AI.run("@cf/google/gemma-4-26b-a4b-it", {
        messages,
        max_tokens: 512,
        temperature: 0.6
      });

      const reply = result?.choices?.[0]?.message?.content ??
        result?.response ??
        result?.output_text;

      if (typeof reply !== "string" || !reply.trim()) {
        return json({ error: "empty_model_response" }, 502);
      }

      return json({
        service: "IKAR Assistant API",
        model: "@cf/google/gemma-4-26b-a4b-it",
        reply: reply.trim()
      });
    } catch {
      return json({
        error: "ai_request_failed",
        message: "Le moteur IA n'a pas pu traiter cette demande. Réessaie plus tard."
      }, 502);
    }
  }
};
