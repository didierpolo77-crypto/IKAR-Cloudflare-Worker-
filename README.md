# IKAR Cloudflare Worker

Backend HTTPS de démarrage pour IKAR Assistant.

## Routes

- `GET /health` : vérifie que le Worker répond.
- `POST /v1/chat` : route protégée par le secret `IKAR_API_TOKEN`.

## Déploiement

Importer ce dépôt GitHub dans Cloudflare Workers & Pages et sélectionner le déploiement depuis Git. Le fichier `wrangler.toml` indique le point d'entrée `src/index.js`.

## Secret obligatoire

Dans les paramètres du Worker, créer un secret nommé `IKAR_API_TOKEN` avec une valeur longue, aléatoire et unique. Ne jamais placer ce secret dans GitHub, dans l'APK Android ou dans une conversation.

## État actuel

Cette version fournit le socle HTTPS et l'authentification. Elle ne contient pas encore de fournisseur IA : `POST /v1/chat` répond volontairement `503 ai_not_configured` jusqu'à la configuration et au test d'un modèle.

## Limites

- `/health` est public et ne révèle aucune donnée sensible.
- L'API ne réalise aucune action sur le téléphone.
- Ajouter ensuite une limite de débit, une politique de conservation minimale des journaux et un fournisseur IA avant une utilisation publique.
