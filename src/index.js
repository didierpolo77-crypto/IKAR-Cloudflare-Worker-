const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });

const MODEL = "@cf/google/gemma-4-26b-a4b-it";

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function htmlResponse(content, status = 200) {
  return new Response(content, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    }
  });
}

function testPage(result = "") {
  return `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Test sécurisé IKAR</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;padding:24px 16px;background:#101827;color:#f3f4f6;font:16px system-ui,sans-serif}
main{max-width:620px;margin:24px auto;padding:24px;background:#1b2638;border:1px solid #35445c;border-radius:16px}
h1{margin-top:0;font-size:1.6rem}p{line-height:1.5;color:#cbd5e1}
label{display:block;margin:18px 0 7px;font-weight:600}input,textarea{width:100%;padding:13px;border:1px solid #64748b;border-radius:9px;background:#0f172a;color:#fff;font:inherit}
textarea{min-height:110px;resize:vertical}button{margin-top:18px;width:100%;padding:14px;border:0;border-radius:9px;background:#3b82f6;color:white;font:inherit;font-weight:700}
.note{font-size:.9rem;color:#aab8ca}.result{margin-top:22px;padding:16px;border-radius:10px;background:#0f172a;border:1px solid #475569;white-space:pre-wrap;overflow-wrap:anywhere}
</style>
</head>
<body><main>
<h1>Test du moteur IA IKAR</h1>
<p>Cette page permet de tester le serveur sans Termux. La clé est envoyée dans le corps du formulaire par HTTPS, jamais dans l'URL. Le Worker ne l'enregistre pas.</p>
<form method="POST" action="/test">
<label for="token">Clé secrète IKAR_API_TOKEN</label>
<input id="token" name="token" type="password" autocomplete="off" required>
<label for="message">Ton message à IKAR</label>
<textarea id="message" name="message" maxlength="4000" required>Bonjour IKAR, présente-toi et explique ce que tu peux faire.</textarea>
<button type="submit">Envoyer à IKAR</button>
</form>
<p class="note">Ne partage jamais ta clé. Cette page doit rester utilisée uniquement par toi.</p>
${result ? `<section class="result" aria-live="polite">${escapeHtml(result)}</section>` : ""}
</main></body></html>`;
}

const SYSTEM_PROMPT = `Tu es IKAR, un assistant numérique francophone, utile, calme et honnête.
Réponds en français sauf demande contraire. Sois clair, pratique et concis.
N'affirme jamais avoir effectué une action sur le téléphone si elle n'a pas réellement été exécutée.
Explique les limites d'Android et demande une confirmation avant toute action sensible.
Pour les questions de sécurité, distingue les indices d'une preuve et recommande des étapes prudentes.`;

async function generateReply(env, message, history = []) {
  if (!env.AI || typeof env.AI.run !== "function") {
    return { error: "ai_binding_missing", status: 503 };
  }

  const messages = [{ role: "system", content: SYSTEM_PROMPT }];
  for (const item of history) {
    if (!item || !["user", "assistant"].includes(item.role) ||
        typeof item.content !== "string" || item.content.length > 2000) {
      return { error: "invalid_history", status: 400 };
    }
    messages.push({ role: item.role, content: item.content });
  }
  messages.push({ role: "user", content: message });

  try {
    const result = await env.AI.run(MODEL, {
      messages,
      max_tokens: 512,
      temperature: 0.6
    });
    const reply = result?.choices?.[0]?.message?.content ??
      result?.response ??
      result?.output_text;

    if (typeof reply !== "string" || !reply.trim()) {
      return { error: "empty_model_response", status: 502 };
    }
    return { reply: reply.trim(), model: MODEL };
  } catch {
    return {
      error: "ai_request_failed",
      message: "Le moteur IA n'a pas pu traiter cette demande. Vérifie le modèle et réessaie.",
      status: 502
    };
  }
}

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

    // Private browser test page. The secret is entered by the owner and is never stored.
    if (url.pathname === "/test" && request.method === "GET") {
      return htmlResponse(testPage());
    }

    if (url.pathname === "/test" && request.method === "POST") {
      if (request.headers.get("Origin") !== url.origin) {
        return htmlResponse(testPage("Requête refusée : origine non autorisée."), 403);
      }

      let form;
      try {
        form = await request.formData();
      } catch {
        return htmlResponse(testPage("Formulaire invalide."), 400);
      }

      const token = form.get("token");
      const message = form.get("message");
      if (typeof token !== "string" || !env.IKAR_API_TOKEN ||
          !constantTimeEqual(token, env.IKAR_API_TOKEN)) {
        return htmlResponse(testPage("Clé refusée (401). Vérifie la valeur enregistrée dans Cloudflare."), 401);
      }
      if (typeof message !== "string" || !message.trim() || message.length > 4000) {
        return htmlResponse(testPage("Message invalide. Limite : 4 000 caractères."), 400);
      }

      const result = await generateReply(env, message.trim());
      if (!result.reply) {
        return htmlResponse(testPage(`Erreur : ${result.error || "échec"} — ${result.message || "Le moteur IA n'a pas répondu."}`), result.status || 502);
      }
      return htmlResponse(testPage(`Réponse IKAR (HTTP 200) — ${result.model}\n\n${result.reply}`));
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
    const result = await generateReply(env, body.message.trim(), history);
    if (!result.reply) {
      return json({
        error: result.error || "ai_request_failed",
        message: result.message
      }, result.status || 502);
    }

    return json({
      service: "IKAR Assistant API",
      model: result.model,
      reply: result.reply
    });
  }
};
