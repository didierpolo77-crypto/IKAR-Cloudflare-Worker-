function parseDate(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function classifyFreshness(lastSeen, checkedAtMs) {
  if (!lastSeen) return { status: "unknown", last_seen: null, age_days: null };
  const ageDays = Math.max(0, Math.floor((checkedAtMs - lastSeen) / 86400000));
  return {
    status: ageDays <= 30 ? "recent" : ageDays <= 90 ? "aging" : "stale",
    last_seen: new Date(lastSeen).toISOString(),
    age_days: ageDays
  };
}

function providerCoverage(results) {
  const expected = results.length;
  const answered = results.filter(item => ["listed", "not_listed"].includes(item?.status)).length;
  return {
    checked_at: null,
    status: expected > 0 && answered === expected ? "available" : answered > 0 ? "partial" : "unavailable",
    indicators_checked: expected,
    indicators_answered: answered,
    coverage_percent: expected ? Math.round((answered / expected) * 100) : 0
  };
}

export function assessReputation(urlhausResults = [], threatfoxResults = [], options = {}) {
  const checkedAt = typeof options.checkedAt === "string" && Number.isFinite(Date.parse(options.checkedAt))
    ? new Date(options.checkedAt).toISOString() : new Date().toISOString();
  const checkedAtMs = Date.parse(checkedAt);
  const urlhausMatches = urlhausResults.filter(item => item?.status === "listed");
  const threatfoxMatches = threatfoxResults.filter(item => item?.status === "listed");
  const urlhausResponded = urlhausResults.some(item => ["listed", "not_listed"].includes(item?.status));
  const threatfoxResponded = threatfoxResults.some(item => ["listed", "not_listed"].includes(item?.status));
  const urlhausAvailable = urlhausResults.length > 0 && urlhausResults.every(item => ["listed", "not_listed"].includes(item?.status));
  const threatfoxAvailable = threatfoxResults.length > 0 && threatfoxResults.every(item => ["listed", "not_listed"].includes(item?.status));

  const reasons = [];
  const divergences = [];
  let hasHighRiskEvidence = false;

  for (const item of urlhausMatches) {
    const activeCount = Math.max(0, Number(item.online_url_count) || 0);
    if (activeCount > 0) {
      hasHighRiskEvidence = true;
      reasons.push({
        code: "urlhaus_active_malicious_urls",
        severity: "high",
        provider: item.provider || "URLhaus (abuse.ch)",
        indicator: item.checked_host || null,
        message: `URLhaus signale ${activeCount} URL(s) encore active(s) pour cet hôte.`,
        evidence: {
          online_url_count: activeCount,
          url_count: Number(item.url_count) || null,
          first_seen: item.first_seen || null,
          sample_urls: Array.isArray(item.sample_urls) ? item.sample_urls.slice(0, 3) : []
        }
      });
    } else {
      reasons.push({
        code: "urlhaus_historical_or_inactive_match",
        severity: "info",
        provider: item.provider || "URLhaus (abuse.ch)",
        indicator: item.checked_host || null,
        message: "URLhaus a une entrée pour cet hôte, mais aucune URL active n'est confirmée dans le résultat actuel.",
        evidence: {
          online_url_count: 0,
          url_count: Number(item.url_count) || null,
          first_seen: item.first_seen || null
        }
      });
    }
  }

  for (const item of threatfoxMatches) {
    const matches = Array.isArray(item.matches) ? item.matches : [];
    if (!matches.length) {
      reasons.push({
        code: "threatfox_match_without_details",
        severity: "elevated",
        provider: item.provider || "ThreatFox (abuse.ch)",
        indicator: item.checked_ioc || null,
        message: "ThreatFox signale une correspondance, mais ne fournit pas de détail exploitable pour confirmer un niveau de confiance élevé.",
        evidence: { match_count: Number(item.match_count) || null }
      });
    }
    for (const match of matches) {
      const confidence = match.confidence_level !== null && match.confidence_level !== undefined &&
        match.confidence_level !== "" && Number.isFinite(Number(match.confidence_level))
        ? Number(match.confidence_level) : null;
      const highConfidence = confidence !== null && confidence >= 70;
      if (highConfidence) hasHighRiskEvidence = true;
      reasons.push({
        code: highConfidence ? "threatfox_high_confidence_match" : "threatfox_match_lower_confidence",
        severity: highConfidence ? "high" : "elevated",
        provider: item.provider || "ThreatFox (abuse.ch)",
        indicator: item.checked_ioc || match.ioc || null,
        message: confidence === null
          ? "ThreatFox signale une correspondance sans niveau de confiance exploitable."
          : `ThreatFox signale une correspondance avec une confiance de ${confidence}/100.`,
        evidence: {
          confidence_level: confidence,
          ioc: match.ioc || null,
          ioc_type: match.ioc_type || null,
          threat_type: match.threat_type || null,
          malware: match.malware || null,
          first_seen: match.first_seen || null,
          last_seen: match.last_seen || null,
          reference: match.reference || null
        }
      });
    }
  }

  const urlhausByIndicator = new Map(urlhausResults.filter(item => item?.checked_host).map(item => [item.checked_host.toLowerCase(), item]));
  const threatfoxByIndicator = new Map(threatfoxResults.filter(item => item?.checked_ioc).map(item => [item.checked_ioc.toLowerCase(), item]));
  for (const [indicator, urlhaus] of urlhausByIndicator) {
    const threatfox = threatfoxByIndicator.get(indicator);
    if (!threatfox) continue;
    const opposite = (urlhaus.status === "listed" && threatfox.status === "not_listed") ||
      (urlhaus.status === "not_listed" && threatfox.status === "listed");
    if (opposite) {
      divergences.push({
        indicator,
        urlhaus: urlhaus.status,
        threatfox: threatfox.status,
        interpretation: "Les sources ne concordent pas. Elles ont des périmètres et des méthodes de collecte différents ; ce désaccord ne suffit pas à invalider une correspondance."
      });
      reasons.push({
        code: "source_disagreement",
        severity: "info",
        indicator,
        message: "URLhaus et ThreatFox donnent des résultats différents pour le même indicateur ; les deux résultats doivent être examinés séparément."
      });
    }
  }

  const anyMatch = urlhausMatches.length > 0 || threatfoxMatches.length > 0;
  if (!urlhausAvailable) reasons.push({
    code: "urlhaus_unavailable", severity: "info", provider: "URLhaus (abuse.ch)",
    message: "URLhaus n'a pas fourni de réponse exploitable pour tous les indicateurs interrogés."
  });
  if (!threatfoxAvailable) reasons.push({
    code: "threatfox_unavailable", severity: "info", provider: "ThreatFox (abuse.ch)",
    message: "ThreatFox n'a pas fourni de réponse exploitable pour tous les indicateurs interrogés."
  });

  let risk = "undetermined";
  let note = "Les sources de réputation n'ont pas fourni assez de données pour conclure.";
  if (hasHighRiskEvidence) {
    risk = "high";
    note = "Au moins un indicateur répond à un critère de risque élevé : URL malveillante encore active dans URLhaus ou correspondance ThreatFox avec confiance d'au moins 70/100.";
  } else if (anyMatch) {
    const onlyHistoricalUrlhausMatches = urlhausMatches.length > 0 &&
      threatfoxMatches.length === 0 &&
      urlhausMatches.every(item => Math.max(0, Number(item.online_url_count) || 0) === 0);
    if (onlyHistoricalUrlhausMatches && urlhausAvailable && threatfoxAvailable) {
      risk = "historical";
      note = "Une entrée historique existe dans URLhaus, mais aucune URL active n'est confirmée et ThreatFox ne signale aucune correspondance. Cette information mérite une vérification, sans être assimilée à une menace active.";
    } else {
      risk = "elevated";
      note = "Une correspondance existe, mais les éléments disponibles ne remplissent pas les critères de risque élevé.";
    }
  } else if (urlhausAvailable && threatfoxAvailable) {
    risk = "no_known_match";
    note = "Aucune correspondance n'a été trouvée dans les deux sources interrogées pour les indicateurs vérifiés. Cela ne garantit pas que l'indicateur est sûr.";
    reasons.push({ code: "no_match_in_available_sources", severity: "info", message: "Aucune correspondance retournée par URLhaus et ThreatFox pour les indicateurs interrogés." });
  } else if (urlhausResponded || threatfoxResponded) {
    note = "La couverture des sources est incomplète : certaines vérifications ont échoué ou une source n'a pas répondu pour tous les indicateurs.";
  }

  const urlhausCoverage = providerCoverage(urlhausResults);
  const threatfoxCoverage = providerCoverage(threatfoxResults);
  urlhausCoverage.checked_at = checkedAt;
  threatfoxCoverage.checked_at = checkedAt;
  const expectedChecks = urlhausResults.length + threatfoxResults.length;
  const answeredChecks = urlhausCoverage.indicators_answered + threatfoxCoverage.indicators_answered;
  const confidenceScore = expectedChecks ? Math.round((answeredChecks / expectedChecks) * 100) : 0;

  const threatfoxLastSeen = threatfoxMatches.flatMap(item =>
    (Array.isArray(item.matches) ? item.matches : []).map(match => parseDate(match.last_seen))
  ).filter(Boolean).sort((a, b) => b - a)[0] || null;
  const urlhausActive = urlhausMatches.some(item => Number(item.online_url_count) > 0);

  return {
    risk, note, urlhausAvailable, threatfoxAvailable,
    sourceStatus: {
      urlhaus: urlhausAvailable ? "available" : (urlhausResponded ? "partial" : "unavailable"),
      threatfox: threatfoxAvailable ? "available" : (threatfoxResponded ? "partial" : "unavailable")
    },
    sourceFreshness: {
      checked_at: checkedAt,
      urlhaus: {
        ...urlhausCoverage,
        activity: urlhausActive ? "active_url_reported" : "no_active_url_confirmed",
        freshness: "unknown",
        explanation: "URLhaus fournit ici une date de première observation et/ou d'ajout, pas nécessairement une date de dernière activité. L'ancienneté de ces dates ne permet donc pas de conclure à la fraîcheur."
      },
      threatfox: {
        ...threatfoxCoverage,
        activity: threatfoxLastSeen ? "last_seen_available" : "no_last_seen_available",
        freshness: classifyFreshness(threatfoxLastSeen, checkedAtMs),
        explanation: "La fraîcheur est estimée à partir du champ last_seen de ThreatFox lorsqu'il est disponible."
      }
    },
    confidence: {
      score: confidenceScore,
      label: confidenceScore === 100 ? "couverture complète" : confidenceScore > 0 ? "couverture partielle" : "aucune réponse exploitable",
      meaning: "Ce score mesure uniquement la proportion de requêtes de sources ayant répondu de façon exploitable. Ce n'est ni une probabilité que le domaine soit malveillant, ni une garantie de sécurité."
    },
    divergences,
    urlhausMatches, threatfoxMatches,
    matchesFound: urlhausMatches.length + threatfoxMatches.length,
    reasons,
    criteria: {
      high_risk: [
        "URLhaus : au moins une URL avec statut online",
        "ThreatFox : confiance d'une correspondance supérieure ou égale à 70/100"
      ],
      historical_risk: [
        "URLhaus conserve une entrée, mais aucune URL active n'est confirmée et ThreatFox ne signale aucune correspondance"
      ],
      elevated_risk: [
        "Correspondance ThreatFox avec confiance inférieure à 70/100 ou non renseignée",
        "Correspondance URLhaus accompagnée d'autres éléments de risque ou d'une couverture incomplète"
      ]
    },
    limitations: [
      "Une absence de correspondance ne prouve pas qu'un domaine ou une adresse IP est sûr.",
      "Les résultats dépendent des indicateurs effectivement interrogés et de la fraîcheur des bases.",
      "Une source indisponible ne compte jamais comme une réponse négative.",
      "Le score de confiance mesure la couverture des requêtes, pas la probabilité réelle de menace.",
      "Les divergences entre sources peuvent provenir de leurs périmètres et méthodes de collecte différents.",
      "La date de vérification par IKAR est distincte de la date de dernière activité enregistrée par une source."
    ]
  };
}
