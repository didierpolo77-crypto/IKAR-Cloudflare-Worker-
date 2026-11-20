# IKAR Assistant API

Backend HTTPS pour IKAR Assistant, compatible avec Render (Node.js) et Hugging Face Inference Providers.

## Déploiement Render

- Runtime : Node
- Branch : main
- Root Directory : laisser vide
- Build Command : `npm install`
- Start Command : `npm start`

Le serveur écoute sur `0.0.0.0` et utilise le port fourni par Render via `PORT`.

## Variables secrètes à configurer dans Render

Créer ces variables dans **Environment** du service Render (ne jamais les écrire dans GitHub, l'APK ou une conversation) :

- `IKAR_API_TOKEN` : une longue clé secrète aléatoire, choisie par le propriétaire et conservée en lieu sûr.
- `HF_TOKEN` : le jeton Hugging Face avec autorisation Inference Providers.
- `HF_MODEL` (facultatif) : modèle servi par un fournisseur compatible. Valeur par défaut : `deepseek-ai/DeepSeek-V4.1-Flash:cheapest`.

L'accès et le coût de l'inférence dépendent du modèle, du fournisseur et des crédits/limites du compte Hugging Face. L'hébergement Render gratuit ne rend pas l'inférence Hugging Face automatiquement gratuite.

## Routes

- `GET /health` : état du serveur et indicateurs de configuration (sans révéler les secrets).
- `POST /v1/chat` : API protégée par `Authorization: Bearer <IKAR_API_TOKEN>`.

Exemple de corps JSON :

```json
{
  "message": "Bonjour IKAR",
  "history": []
}
```

## Sécurité et limites

- Les secrets sont lus depuis les variables d'environnement du serveur.
- Les corps de requête et l'historique sont limités.
- Les erreurs du fournisseur ne transmettent pas son corps de réponse au client.
- L'API ne réalise aucune action sur le téléphone.
- Le fichier `src/index.js` et `wrangler.toml` sont conservés pour le déploiement Cloudflare Workers ; Render utilise `server.js`.
