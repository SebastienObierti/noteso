# 🚀 Command Center - Dashboard Multi-Sites

Un tableau de bord complet en **PHP pur** (sans npm, sans dépendances) pour piloter tous vos sites web.

## ✨ Fonctionnalités

### 📊 Vue d'ensemble
- Stats globales (utilisateurs, paiements, revenus, MRR, ARR)
- Graphiques interactifs (Chart.js)
- Activité en temps réel
- Répartition des revenus par site

### 🌐 Gestion des Sites
- Ajouter, modifier, supprimer des sites
- Statut en temps réel (online, maintenance, offline)
- Clé API unique par site
- Statistiques par site

### 👥 Utilisateurs
- Liste complète avec filtres (site, statut, plan, recherche)
- Pagination
- Détails utilisateur avec historique paiements
- Export CSV

### 💳 Paiements
- Historique complet
- Filtres par site et statut
- Enregistrement manuel
- Remboursements
- Export CSV

### 🔄 Abonnements
- Vue d'ensemble (actifs, en retard, annulés)
- Gestion des annulations
- Calcul automatique MRR/ARR

### 📡 Monitoring
- Uptime par site
- Temps de réponse moyen
- Nombre d'incidents
- Historique 24h

### 📈 Rapports
- Génération de rapports mensuels
- Statistiques consolidées
- Historique des rapports

### ⚙️ Paramètres
- Thème sombre/clair
- Notifications (email, push)
- Intégrations (Stripe, PayPal)
- Gestion des administrateurs (multi-utilisateurs)
- Rôles : Super Admin, Admin, Lecteur

### 🔐 Authentification
- Login sécurisé avec sessions
- Gestion des permissions
- Déconnexion

## 📁 Structure

```
/srv/web/noteso/
├── index.html      # Dashboard frontend (HTML/CSS/JS)
├── api.php         # API backend (PHP pur)
├── .htaccess       # Configuration Apache
├── README.md       # Documentation
└── data/           # Données JSON (créé automatiquement)
    ├── admins.json
    ├── sites.json
    ├── users.json
    ├── payments.json
    ├── subscriptions.json
    ├── activities.json
    ├── monitoring.json
    ├── notifications.json
    ├── settings.json
    ├── widgets.json
    ├── reports.json
    └── sessions.json
```

## 🛠 Installation

### 1. Copier les fichiers
```bash
# Copier dans votre dossier web
cp -r noteso/* /srv/web/noteso/

# Ou avec Git
cd /srv/web
git clone <repo> noteso
```

### 2. Permissions
```bash
chmod 755 /srv/web/noteso
chmod 644 /srv/web/noteso/*.php
chmod 644 /srv/web/noteso/*.html
chmod 644 /srv/web/noteso/.htaccess

# Le dossier data sera créé automatiquement
# Assurez-vous que PHP peut écrire dedans
```

### 3. Configuration Apache
Assurez-vous que `mod_rewrite` est activé :
```bash
a2enmod rewrite
systemctl restart apache2
```

VirtualHost exemple :
```apache
<VirtualHost *:80>
    ServerName noteso.votredomaine.fr
    DocumentRoot /srv/web/noteso
    
    <Directory /srv/web/noteso>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

### 4. Configuration Nginx (alternative)
```nginx
server {
    listen 80;
    server_name noteso.votredomaine.fr;
    root /srv/web/noteso;
    index index.html;

    location /api {
        try_files $uri /api.php$is_args$args;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

### 5. Accéder au dashboard
```
http://noteso.votredomaine.fr
```

**Identifiants par défaut :**
- Email : `admin@noteso.fr`
- Mot de passe : `admin123`

## 📡 API Endpoints

### Authentification
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| POST | `/api/auth/login` | Connexion |
| POST | `/api/auth/logout` | Déconnexion |
| GET | `/api/auth/me` | Utilisateur connecté |

### Dashboard
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/dashboard/overview` | Stats globales |

### Sites
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/sites` | Liste des sites |
| GET | `/api/sites/{id}` | Détail d'un site |
| POST | `/api/sites` | Créer un site |
| PUT | `/api/sites/{id}` | Modifier un site |
| DELETE | `/api/sites/{id}` | Supprimer un site |

### Utilisateurs
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/users` | Liste (filtres: siteId, status, plan, search) |
| GET | `/api/users/{id}` | Détail avec paiements |
| POST | `/api/users` | Créer un utilisateur |
| DELETE | `/api/users/{id}` | Supprimer |

### Paiements
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/payments` | Liste (filtres: siteId, status) |
| POST | `/api/payments` | Enregistrer un paiement |
| POST | `/api/payments/{id}/refund` | Rembourser |

### Abonnements
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/subscriptions` | Liste des abonnements |
| POST | `/api/subscriptions/{id}/cancel` | Annuler |

### Analytics
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/analytics/revenue` | Revenus par jour |
| GET | `/api/analytics/users` | Inscriptions par jour |
| GET | `/api/analytics/breakdown` | Répartition par site |
| GET | `/api/analytics/plans` | Répartition par plan |

### Monitoring
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/monitoring` | État des sites |
| GET | `/api/monitoring/{siteId}/history` | Historique |

### Exports
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/export/users?format=csv` | Export utilisateurs |
| GET | `/api/export/payments?format=csv` | Export paiements |

### Webhook (pour vos sites)
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| POST | `/api/webhook/{siteId}` | Recevoir des événements |

## 🔗 Intégration avec vos sites

### Envoyer un événement (JavaScript)
```javascript
// Nouvelle inscription
fetch('https://noteso.votredomaine.fr/api/webhook/SITE_ID', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-API-Key': 'VOTRE_CLE_API'
    },
    body: JSON.stringify({
        event: 'user.created',
        data: {
            email: 'client@example.com',
            firstName: 'Jean',
            lastName: 'Dupont',
            plan: 'pro'
        }
    })
});

// Nouveau paiement
fetch('https://noteso.votredomaine.fr/api/webhook/SITE_ID', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-API-Key': 'VOTRE_CLE_API'
    },
    body: JSON.stringify({
        event: 'payment.completed',
        data: {
            userId: 'user_123',
            amount: 49.99,
            method: 'card',
            description: 'Abonnement Pro'
        }
    })
});
```

### Envoyer un événement (PHP)
```php
<?php
$siteId = 'site_xxx';
$apiKey = 'ek_xxx';

function sendEvent($siteId, $apiKey, $event, $data) {
    $ch = curl_init("https://noteso.votredomaine.fr/api/webhook/$siteId");
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            "X-API-Key: $apiKey"
        ],
        CURLOPT_POSTFIELDS => json_encode([
            'event' => $event,
            'data' => $data
        ])
    ]);
    $response = curl_exec($ch);
    curl_close($ch);
    return json_decode($response, true);
}

// Nouvelle inscription
sendEvent($siteId, $apiKey, 'user.created', [
    'email' => 'client@example.com',
    'firstName' => 'Jean',
    'lastName' => 'Dupont',
    'plan' => 'starter'
]);

// Nouveau paiement
sendEvent($siteId, $apiKey, 'payment.completed', [
    'amount' => 29.99,
    'method' => 'card',
    'description' => 'Abonnement Starter'
]);
```

## 🔒 Sécurité

- Mots de passe hashés (bcrypt)
- Sessions avec tokens sécurisés
- Expiration automatique des sessions (7 jours)
- Validation des clés API pour les webhooks
- Protection CORS

### Recommandations
1. Changez les mots de passe par défaut immédiatement
2. Utilisez HTTPS en production
3. Restreignez l'accès au dossier `data/`
4. Sauvegardez régulièrement les fichiers JSON

## 🎨 Personnalisation

### Changer le thème par défaut
Dans `index.html`, modifiez les variables CSS dans `:root` pour le thème sombre et `[data-theme="light"]` pour le thème clair.

### Ajouter des widgets
Les widgets sont configurables dans l'API via `/api/widgets`.

## 📝 Notes

- **Pas de base de données requise** : Tout est stocké en JSON
- **Pas de npm/node** : PHP pur côté serveur
- **Responsive** : Fonctionne sur mobile et desktop
- **Temps réel** : Rafraîchissement automatique toutes les 30s

## 🐛 Dépannage

### L'API retourne 404
- Vérifiez que `mod_rewrite` est activé
- Vérifiez le fichier `.htaccess`

### Erreur de permissions
```bash
chown -R www-data:www-data /srv/web/noteso/data
chmod 755 /srv/web/noteso/data
```

### Les données ne se sauvegardent pas
- Vérifiez que PHP peut écrire dans le dossier `data/`
- Vérifiez les logs PHP pour les erreurs

## 📄 Licence

MIT - Utilisez comme vous le souhaitez!
