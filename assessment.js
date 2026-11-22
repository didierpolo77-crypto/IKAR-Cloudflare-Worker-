export function assessReputation(urlhausResults = [], threatfoxResults = []) {
  const urlhausMatches = urlhausResults.filter(item => item?.status === "listed");
  const threatfoxMatches = threatfoxResults.filter(item => item?.status === "listed");
  const urlhausAvailable = urlhausResults.some(item => ["listed", "not_listed"].includes(item?.status));
  const threatfoxAvailable = threatfoxResults.some(item => ["listed", "not_listed"].includes(item?.status));

  const reasons = [];
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
        severity: "elevated",
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
      const confidence = Number.isFinite(Number(match.confidence_level))
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

  const anyMatch = urlhausMatches.length > 0 || threatfoxMatches.length > 0;
  if (!urlhausAvailable) {
    reasons.push({
      code: "urlhaus_unavailable",
      severity: "info",
      provider: "URLhaus (abuse.ch)",
      message: "URLhaus n'a pas fourni de réponse exploitable ; son absence de résultat ne peut pas être interprétée comme un avis négatif."
    });
  }
  if (!threatfoxAvailable) {
    reasons.push({
      code: "threatfox_unavailable",
      severity: "info",
      provider: "ThreatFox (abuse.ch)",
      message: "ThreatFox n'a pas fourni de réponse exploitable ; son absence de résultat ne peut pas être interprétée comme un avis négatif."
    });
  }

  let risk = "undetermined";
  let note = "Les sources de réputation n'ont pas fourni assez de données pour conclure.";
  if (hasHighRiskEvidence) {
    risk = "high";
    note = "Au moins un indicateur répond à un critère de risque élevé : URL malveillante encore active dans URLhaus ou correspondance ThreatFox avec confiance d'au moins 70/100.";
  } else if (anyMatch) {
    risk = "elevated";
    note = "Une correspondance existe, mais les éléments disponibles ne remplissent pas les critères de risque élevé (activité URL confirmée ou confiance ThreatFox d'au moins 70/100).";
  } else if (urlhausAvailable && threatfoxAvailable) {
    risk = "no_known_match";
    note = "Aucune correspondance n'a été trouvée dans les deux sources interrogées pour les indicateurs vérifiés. Cela ne garantit pas que l'indicateur est sûr.";
    reasons.push({
      code: "no_match_in_available_sources",
      severity: "info",
      message: "Aucune correspondance retournée par URLhaus et ThreatFox pour les indicateurs interrogés."
    });
  } else if (urlhausAvailable || threatfoxAvailable) {
    risk = "undetermined";
    note = "Une seule des deux sources a répondu de façon exploitable ; les données sont insuffisantes pour conclure à l'absence de menace.";
  }

  return {
    risk,
    note,
    urlhausAvailable,
    threatfoxAvailable,
    sourceStatus: {
      urlhaus: urlhausAvailable ? "available" : "unavailable",
      threatfox: threatfoxAvailable ? "available" : "unavailable"
    },
    urlhausMatches,
    threatfoxMatches,
    matchesFound: urlhausMatches.length + threatfoxMatches.length,
    reasons,
    criteria: {
      high_risk: [
        "URLhaus : au moins une URL avec statut online",
        "ThreatFox : confiance d'une correspondance supérieure ou égale à 70/100"
      ],
      elevated_risk: [
        "Correspondance URLhaus sans URL active confirmée",
        "Correspondance ThreatFox avec confiance inférieure à 70/100 ou non renseignée"
      ]
    },
    limitations: [
      "Une absence de correspondance ne prouve pas qu'un domaine ou une adresse IP est sûr.",
      "Les résultats dépendent des indicateurs effectivement interrogés et de la fraîcheur des bases.",
      "Une source indisponible ne compte jamais comme une réponse négative."
    ]
  };
}
