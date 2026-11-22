export async function lookupUrlhausHost(host, fetchImpl = fetch, authKey = (process.env.URLHAUS_AUTH_KEY || "").trim()) {
  if (!authKey) return { status: "unavailable", reason: "urlhaus_key_not_configured" };
  const form = new URLSearchParams({ host });
  let response;
  try {
    response = await fetchImpl("https://urlhaus-api.abuse.ch/v1/host/", {
      method: "POST",
      headers: {
        "Auth-Key": authKey,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: form,
      signal: AbortSignal.timeout(10000)
    });
  } catch {
    return { status: "unavailable", reason: "urlhaus_connection_failed" };
  }
  if (!response.ok) return { status: "unavailable", reason: "urlhaus_http_error" };
  let data;
  try { data = await response.json(); }
  catch { return { status: "unavailable", reason: "urlhaus_invalid_response" }; }
  if (data.query_status === "no_results") {
    return { provider: "URLhaus (abuse.ch)", status: "not_listed", checked_host: host };
  }
  if (data.query_status !== "ok") {
    return { status: "unavailable", reason: "urlhaus_query_error" };
  }
  const urls = Array.isArray(data.urls) ? data.urls : [];
  const online = urls.filter(item => item && item.url_status === "online");
  return {
    provider: "URLhaus (abuse.ch)",
    status: "listed",
    checked_host: host,
    first_seen: data.firstseen || null,
    url_count: Number.parseInt(data.url_count, 10) || urls.length,
    online_url_count: online.length,
    sample_urls: urls.slice(0, 5).map(item => ({
      url: typeof item.url === "string" ? item.url.slice(0, 500) : null,
      status: item.url_status || null,
      threat: item.threat || null,
      date_added: item.date_added || null
    })),
    blacklists: data.blacklists && typeof data.blacklists === "object" ? data.blacklists : null,
    reference: typeof data.urlhaus_reference === "string" ? data.urlhaus_reference : null
  };
}


export async function lookupThreatFoxIoc(ioc, authKey = (process.env.URLHAUS_AUTH_KEY || "").trim(), fetchImpl = fetch) {
  if (!authKey) return { status: "unavailable", reason: "threatfox_key_not_configured", checked_ioc: ioc };
  let response;
  try {
    response = await fetchImpl("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: {
        "Auth-Key": authKey,
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({ query: "search_ioc", search_term: ioc, exact_match: true }),
      signal: AbortSignal.timeout(9000)
    });
  } catch {
    return { status: "unavailable", reason: "threatfox_connection_failed", checked_ioc: ioc };
  }
  if (!response.ok) return { status: "unavailable", reason: "threatfox_http_error", checked_ioc: ioc };
  let data;
  try { data = await response.json(); }
  catch { return { status: "unavailable", reason: "threatfox_invalid_response", checked_ioc: ioc }; }
  if (data.query_status === "no_result" || data.query_status === "no_results") {
    return { provider: "ThreatFox (abuse.ch)", status: "not_listed", checked_ioc: ioc };
  }
  if (data.query_status !== "ok") {
    return { status: "unavailable", reason: "threatfox_query_error", checked_ioc: ioc };
  }
  const matches = Array.isArray(data.data) ? data.data.slice(0, 5) : [];
  if (!matches.length) return { provider: "ThreatFox (abuse.ch)", status: "not_listed", checked_ioc: ioc };
  return {
    provider: "ThreatFox (abuse.ch)",
    status: "listed",
    checked_ioc: ioc,
    match_count: Array.isArray(data.data) ? data.data.length : matches.length,
    matches: matches.map(item => ({
      ioc: typeof item.ioc === "string" ? item.ioc.slice(0, 300) : null,
      ioc_type: item.ioc_type || null,
      threat_type: item.threat_type || null,
      malware: item.malware_printable || item.malware || null,
      confidence_level: Number.isFinite(Number(item.confidence_level)) ? Number(item.confidence_level) : null,
      first_seen: item.first_seen || null,
      last_seen: item.last_seen || null,
      reference: typeof item.reference === "string" ? item.reference.slice(0, 500) : null
    }))
  };
}
