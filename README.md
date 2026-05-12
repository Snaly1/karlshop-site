# KarlShop – Deployment Guide

## Structure
```
karlshop/
├── public/          ← Site frontend (servi automatiquement)
│   └── index.html
├── src/
│   └── server.js    ← Backend Node.js
├── .env.example     ← Variables d'environnement
├── .gitignore
└── package.json
```

## Déploiement sur Railway

### 1. Créer un repo GitHub
```bash
git init
git add .
git commit -m "initial commit"
git branch -M main
git remote add origin https://github.com/TON_USERNAME/karlshop.git
git push -u origin main
```

### 2. Créer le projet Railway
1. Va sur railway.app → New Project → Deploy from GitHub
2. Sélectionne ton repo `karlshop`
3. Railway détecte automatiquement Node.js

### 3. Configurer les variables d'environnement dans Railway
Dans ton projet Railway → Settings → Variables, ajoute :

| Variable | Valeur |
|---|---|
| `NOWPAYMENTS_API_KEY` | Ta clé API NOWPayments |
| `NOWPAYMENTS_IPN_SECRET` | Ta clé IPN NOWPayments |
| `ADMIN_PASSWORD` | karlshop2026 (change-le !) |
| `FRONTEND_URL` | https://TON-PROJET.up.railway.app |

### 4. Récupérer l'URL Railway
Après déploiement → Settings → Networking → Generate Domain
→ Copie l'URL et mets-la dans FRONTEND_URL

### 5. Configurer le Webhook NOWPayments
Dans NOWPayments → Paramètres → Paiements → IPN Callback URL :
```
https://TON-PROJET.up.railway.app/webhook/nowpayments
```

## Accès Admin
URL : https://ton-site.up.railway.app
Footer → cliquer "Admin" → mot de passe : `karlshop2026`

## ⚠️ Sécurité
- Change le mot de passe admin dans les variables Railway
- Régénère tes clés NOWPayments (elles ont été partagées)
- Ne commite JAMAIS le fichier .env
