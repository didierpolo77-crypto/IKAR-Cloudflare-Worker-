export function assessReputation(urlhausResults = [], threatfoxResults = []) {
  const urlhausMatches = urlhausResults.filter(item => item.status === "listed");
  const threatfoxMatches = threatfoxResults.filter(item => item.status === "listed");
  const urlhausAvailable = urlhausResults.some(item => item.status === "listed" || item.status === "not_listed");
  const threatfoxAvailable = threatfoxResults.some(item => item.status === "listed" || item.status === "not_listed");
  const anyMatch = urlhausMatches.length > 0 || threatfoxMatches.length > 0;
  const activeUrlhaus = urlhausMatches.some(item => Number(item.online_url_count) > 0);
  const highConfidenceThreatFox = threatfoxMatches.some(item =>
    Array.isArray(item.matches) && item.matches.some(match => Number(match.confidence_level) >= 70)
  );

  let risk = "undetermined";
  let note = "Les sources de réputation n'ont pas fourni assez de données pour conclure.";
  if (activeUrlhaus || highConfidenceThreatFox) {
    risk = "high";
    note = activeUrlhaus
      ? "URLhaus signale au moins une URL encore active pour cet indicateur. Risque élevé : évite de visiter cet hôte."
      : "ThreatFox signale un indicateur avec un niveau de confiance élevé (70 ou plus). Risque élevé : évite tout contact avec cet indicateur.";
  } else if (anyMatch) {
    risk = "elevated";
    note = "Une correspondance historique ou de confiance insuffisante a été trouvée, mais aucune activité malveillante actuelle n'est confirmée par les critères élevés. Prudence recommandée ; consulte les détails des sources.";
  } else if (urlhausAvailable && threatfoxAvailable) {
    risk = "no_known_match";
    note = "Aucune correspondance trouvée dans URLhaus et ThreatFox pour les indicateurs vérifiés. Cela ne garantit pas que le domaine ou l'adresse IP est sûr.";
  } else if (urlhausAvailable || threatfoxAvailable) {
    risk = "undetermined";
    note = "Une seule source de réputation a répondu. L'absence de correspondance dans cette source ne suffit pas pour conclure à la sécurité.";
  }

  return {
    risk,
    note,
    urlhausAvailable,
    threatfoxAvailable,
    urlhausMatches,
    threatfoxMatches,
    matchesFound: urlhausMatches.length + threatfoxMatches.length
  };
}
