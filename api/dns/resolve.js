const ALLOWED_TYPES = new Set(["A", "AAAA", "CNAME", "MX", "NS", "TXT"]);
const ADGUARD_DOH = "https://dns.adguard-dns.com/resolve";

function send(res, status, data) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.end(JSON.stringify(data));
}

function authorized(req) {
  const expected = process.env.IKAR_API_TOKEN || "";
  const supplied = req.headers.authorization || "";
  if (!expected || !supplied.startsWith("Bearer ")) return false;
  const actual = supplied.slice(7);
  const left = Buffer.from(actual);
  const right = Buffer.from(expected);
  return left.length === right.length && require("node:crypto").timingSafeEqual(left, right);
}

function validDomain(name) {
  if (typeof name !== "string" || name.length < 1 || name.length > 253) return false;
  const normalized = name.trim().replace(/\.$/, "");
  if (!normalized || normalized.includes("://") || normalized.includes("/") || normalized.includes(":")) return false;
  return normalized.split(".").every(label =>
    label.length >= 1 && label.length <= 63 &&
    /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label)
  );
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return send(res, 405, { error: "method_not_allowed" });
  }

  if (!authorized(req)) return send(res, 401, { error: "unauthorized" });

  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { return send(res, 400, { error: "invalid_json" }); }
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return send(res, 400, { error: "invalid_json" });
  }

  const name = typeof body.name === "string" ? body.name.trim().toLowerCase() : "";
  const type = typeof body.type === "string" ? body.type.trim().toUpperCase() : "A";
  if (!validDomain(name)) return send(res, 400, { error: "invalid_domain" });
  if (!ALLOWED_TYPES.has(type)) return send(res, 400, { error: "unsupported_record_type" });

  const query = new URL(ADGUARD_DOH);
  query.searchParams.set("name", name);
  query.searchParams.set("type", type);

  let upstream;
  try {
    upstream = await fetch(query, {
      method: "GET",
      headers: { "Accept": "application/dns-json" },
      signal: AbortSignal.timeout(8000)
    });
  } catch {
    return send(res, 502, { error: "adguard_dns_unreachable" });
  }

  if (!upstream.ok) return send(res, 502, { error: "adguard_dns_error" });

  let result;
  try { result = await upstream.json(); }
  catch { return send(res, 502, { error: "invalid_adguard_response" }); }

  if (!Number.isInteger(result.Status)) {
    return send(res, 502, { error: "unexpected_adguard_response" });
  }

  return send(res, 200, {
    service: "IKAR AdGuard DNS-over-HTTPS",
    provider: "AdGuard Public DNS",
    transport: "DNS-over-HTTPS",
    queried_name: name,
    record_type: type,
    dns_status: result.Status,
    answers: Array.isArray(result.Answer)
      ? result.Answer.slice(0, 20).map(record => ({
          name: record.name,
          type: record.type,
          ttl: record.TTL,
          data: record.data
        }))
      : [],
    authenticated_data: result.AD === true,
    recursion_available: result.RA === true
  });
}
