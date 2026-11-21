# Déploiement IKAR sur Vercel (sans Cloudflare)

Ce dépôt contient maintenant des fonctions Node.js Vercel. Le backend conserve les routes :
- `GET /health`
- `POST /v1/chat`
- `POST /v1/security/analyze`
- `POST /v1/url/check`

## Importer le projet
1. Dans Vercel, importer le dépôt GitHub `IKAR-Cloudflare-Worker-`.
2. Sélectionner la branche `vercel-serverless-migration`.
3. Framework Preset : **Other**. Root Directory : `./`.
4. Ne pas ajouter de commande Build ni Output Directory. Déployer après avoir configuré les variables ci-dessous.

## Variables d'environnement Vercel
Ajouter dans Project Settings → Environment Variables, pour Production et Preview selon le besoin :
- `IKAR_API_TOKEN` : le même jeton Bearer déjà configuré dans l'application IKAR. Ne pas en générer un nouveau sans mettre à jour l'application.
- `HF_TOKEN` : jeton Hugging Face, à saisir directement dans Vercel. Ne jamais le committer ni le partager dans un chat.
- `HF_MODEL` : facultatif. Par défaut : `deepseek-ai/DeepSeek-V4.1-Flash:cheapest`.
- `URLHAUS_AUTH_KEY` : facultatif pour le chat, nécessaire à la route de vérification URLhaus.

Redéployer après l'ajout ou la modification des variables.

## Vérifications après déploiement
- Ouvrir `https://VOTRE-DOMAINE.vercel.app/health`. La réponse doit indiquer `status: online`.
- Tester les routes POST depuis l'application IKAR, avec son jeton Bearer existant.
- Un état `hf_token_configured: false` signifie que la variable HF_TOKEN manque.
- `urlhaus_configured: false` signifie que la clé URLhaus n'a pas été ajoutée ; seule cette fonction est alors indisponible.

## Notes
- Les fonctions s'exécutent à la demande : aucun serveur Node permanent n'est lancé.
- Le code ne dépend pas de Cloudflare Workers AI ni du binding `env.AI`.
- Le déploiement n'est pas effectué par ce commit. Les limites du plan Vercel et celles du fournisseur Hugging Face s'appliquent.
- Le dossier `src/` et `wrangler.toml` sont conservés comme anciens fichiers Worker ; ils ne sont pas utilisés par les routes Vercel.
