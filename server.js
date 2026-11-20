import http from "node:http";
import { timingSafeEqual } from "node:crypto";

const PORT = Number(process.env.PORT || 10000);
const HOST = "0.0.0.0";
const HF_URL = "https://router.huggingface.co/v1/chat/completions";
const DEFAULT_MODEL = "deepseek-ai/DeepSeek-V4.1-Flash:cheapest";
const SYSTEM_PROMPT = `Tu es IKAR, un assistant numérique francophone, utile, calme et honnête.
Réponds en français sauf demande contraire. Sois clair, pratique et concis.
N'affirme jamais avoir effectué une action sur le téléphone si elle n'a pas réellement été exécutée.
Explique les limites d'Android et demande une confirmation avant toute action sensible.
Pour les questions de sécurité, distingue les indices d'une preuve et recommande des étapes prudentes.`;

function send(res, status, data) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer"
  });
  res.end(JSON.stringify(data));
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

async function readBody(req, maxBytes = 12000) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw Object.assign(new Error("request_too_large"), { status: 413 });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function handle(req, res) {
  const url = new URL(req.url, "http://localhost");

  if (req.method === "GET" && url.pathname === "/health") {
    return send(res, 200, {
      service: "IKAR Assistant API",
      status: "online",
      provider: "huggingface-inference-providers",
      authentication_configured: Boolean(process.env.IKAR_API_TOKEN),
      model_configured: Boolean(process.env.HF_MODEL || DEFAULT_MODEL),
      hf_token_configured: Boolean(process.env.HF_TOKEN)
    });
  }

  if (url.pathname !== "/v1/chat") {
    return send(res, 404, { error: "not_found" });
  }
  if (req.method !== "POST") {
    return send(res, 405, { error: "method_not_allowed" });
  }

  const apiToken = process.env.IKAR_API_TOKEN || "";
  const authorization = req.headers.authorization || "";
  if (!apiToken || !safeEqual(authorization, `Bearer ${apiToken}`)) {
    return send(res, 401, { error: "unauthorized" });
  }

  if (!process.env.HF_TOKEN) {
    return send(res, 503, { error: "ai_not_configured", message: "Le jeton Hugging Face n'est pas configuré sur le serveur." });
  }

  let body;
  try {
    const raw = await readBody(req);
    body = JSON.parse(raw);
  } catch (error) {
    return send(res, error.status || 400, { error: error.status ? error.message : "invalid_json" });
  }

  if (!body || typeof body.message !== "string" ||
      !body.message.trim() || body.message.length > 4000) {
    return send(res, 400, { error: "invalid_message" });
  }

  const history = Array.isArray(body.history) ? body.history.slice(-10) : [];
  const messages = [{ role: "system", content: SYSTEM_PROMPT }];
  for (const item of history) {
    if (!item || !["user", "assistant"].includes(item.role) ||
        typeof item.content !== "string" || item.content.length > 2000) {
      return send(res, 400, { error: "invalid_history" });
    }
    messages.push({ role: item.role, content: item.content });
  }
  messages.push({ role: "user", content: body.message.trim() });

  const model = process.env.HF_MODEL || DEFAULT_MODEL;
  let upstream;
  try {
    upstream = await fetch(HF_URL, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${process.env.HF_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ model, messages, max_tokens: 512, temperature: 0.6 }),
      signal: AbortSignal.timeout(55000)
    });
  } catch {
    return send(res, 502, { error: "ai_connection_failed", message: "Impossible de joindre le fournisseur IA. Réessaie plus tard." });
  }

  if (!upstream.ok) {
    // Do not forward provider response bodies or credentials to the client.
    const status = upstream.status === 429 ? 503 : 502;
    return send(res, status, {
      error: upstream.status === 429 ? "ai_rate_limited" : "ai_provider_error",
      message: upstream.status === 401 || upstream.status === 403
        ? "Le fournisseur IA a refusé l'authentification ou l'accès au modèle."
        : "Le fournisseur IA n'a pas pu traiter la demande."
    });
  }

  let result;
  try {
    result = await upstream.json();
  } catch {
    return send(res, 502, { error: "invalid_ai_response" });
  }

  const reply = result?.choices?.[0]?.message?.content;
  if (typeof reply !== "string" || !reply.trim()) {
    return send(res, 502, { error: "empty_ai_response" });
  }

  return send(res, 200, {
    service: "IKAR Assistant API",
    model,
    reply: reply.trim()
  });
}

const server = http.createServer((req, res) => {
  handle(req, res).catch(() => {
    if (!res.headersSent) send(res, 500, { error: "internal_server_error" });
    else res.destroy();
  });
});

server.listen(PORT, HOST, () => {
  console.log(`IKAR API listening on ${HOST}:${PORT}`);
});
