# IKAR Android

Application Android autonome, distincte de Sentinel IA.

## Fonctions réellement présentes dans v0.1.0
- Écran d'accueil natif.
- Sélection d'un fichier via le sélecteur Android.
- Calcul SHA-256 en flux, sans charger tout le fichier en mémoire.
- Vérification de domaine via l'API IKAR (URLhaus et ThreatFox), avec jeton saisi à l'exécution.
- Enregistrement local de tâches simples.
- Ouverture du calendrier, du composeur e-mail et du composeur SMS via les intents Android.

## Limites importantes
- SHA-256 identifie un fichier mais ne prouve pas qu'il est sain. Aucune base locale de signatures, règle YARA ou moteur ClamAV Android n'est encore intégré.
- La protection Web temps réel, l'analyse comportementale, le coffre et l'écran de conversation IA restent à construire ; l'application les indique comme tels.
- Le jeton API est saisi à l'exécution, effacé du champ après envoi et n'est ni intégré à l'APK ni sauvegardé par l'application.
- Les e-mails et SMS ne sont pas lus. Android ouvre simplement l'application choisie par l'utilisateur.
- L'URL API par défaut est https://ikar-cloudflare-worker-v4gl.vercel.app. Elle peut être modifiée dans MainActivity.java si le domaine de production change.

## Compilation
Java 17, Gradle 8.9, Android compile SDK 35.
Package : com.ikar.mobile
Minimum : Android 8.0 (API 26)

## Dépendance de déploiement à résoudre avant le test mobile
Le projet Vercel IKAR utilise actuellement une protection SSO sur les déploiements vercel.app. Le jeton API seul peut donc ne pas suffire depuis l'application Android. Il faudra configurer un point d'accès mobile public avec authentification API, sans désactiver la protection du tableau de bord ni exposer de secret dans l'APK.
