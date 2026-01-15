// Noteso Service Worker v1.4
const CACHE_NAME = 'noteso-v1.4';
const STATIC_ASSETS = [
    '/',
    '/index.html',
    '/manifest.json',
    'https://cdn.jsdelivr.net/npm/chart.js',
    'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js'
];

// Installation - mise en cache des assets statiques
self.addEventListener('install', (event) => {
    console.log('[SW] Installation...');
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => {
                console.log('[SW] Mise en cache des assets');
                return cache.addAll(STATIC_ASSETS);
            })
            .then(() => self.skipWaiting())
    );
});

// Activation - nettoyage des anciens caches
self.addEventListener('activate', (event) => {
    console.log('[SW] Activation...');
    event.waitUntil(
        caches.keys()
            .then(cacheNames => {
                return Promise.all(
                    cacheNames
                        .filter(name => name !== CACHE_NAME)
                        .map(name => {
                            console.log('[SW] Suppression ancien cache:', name);
                            return caches.delete(name);
                        })
                );
            })
            .then(() => self.clients.claim())
    );
});

// Fetch - stratégie Network First avec fallback cache
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    
    // Ignorer les requêtes non-GET
    if (event.request.method !== 'GET') {
        return;
    }
    
    // Pour les requêtes API - Network only (pas de cache)
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/auth/')) {
        event.respondWith(
            fetch(event.request)
                .catch(() => new Response(JSON.stringify({ error: 'Offline' }), {
                    status: 503,
                    headers: { 'Content-Type': 'application/json' }
                }))
        );
        return;
    }
    
    // Pour les assets statiques - Cache First
    if (STATIC_ASSETS.some(asset => url.href.includes(asset) || url.pathname === asset)) {
        event.respondWith(
            caches.match(event.request)
                .then(cachedResponse => {
                    if (cachedResponse) {
                        // Mettre à jour en arrière-plan
                        fetch(event.request).then(response => {
                            caches.open(CACHE_NAME).then(cache => {
                                cache.put(event.request, response);
                            });
                        });
                        return cachedResponse;
                    }
                    return fetch(event.request).then(response => {
                        const responseClone = response.clone();
                        caches.open(CACHE_NAME).then(cache => {
                            cache.put(event.request, responseClone);
                        });
                        return response;
                    });
                })
        );
        return;
    }
    
    // Pour tout le reste - Network First
    event.respondWith(
        fetch(event.request)
            .then(response => {
                // Mettre en cache si succès
                if (response.ok) {
                    const responseClone = response.clone();
                    caches.open(CACHE_NAME).then(cache => {
                        cache.put(event.request, responseClone);
                    });
                }
                return response;
            })
            .catch(() => {
                return caches.match(event.request).then(cachedResponse => {
                    if (cachedResponse) {
                        return cachedResponse;
                    }
                    // Page offline de fallback
                    if (event.request.headers.get('accept').includes('text/html')) {
                        return new Response(`
                            <!DOCTYPE html>
                            <html>
                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>Noteso - Hors ligne</title>
                                <style>
                                    body { font-family: -apple-system, sans-serif; background: #0a0a0b; color: #fafafa; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
                                    .container { text-align: center; padding: 40px; }
                                    h1 { font-size: 48px; margin-bottom: 16px; }
                                    p { color: #a1a1aa; margin-bottom: 24px; }
                                    button { background: #3b82f6; color: white; border: none; padding: 12px 24px; border-radius: 8px; font-size: 16px; cursor: pointer; }
                                </style>
                            </head>
                            <body>
                                <div class="container">
                                    <h1>📡</h1>
                                    <h2>Vous êtes hors ligne</h2>
                                    <p>Vérifiez votre connexion internet et réessayez.</p>
                                    <button onclick="location.reload()">Réessayer</button>
                                </div>
                            </body>
                            </html>
                        `, {
                            status: 200,
                            headers: { 'Content-Type': 'text/html' }
                        });
                    }
                });
            })
    );
});

// Push notifications
self.addEventListener('push', (event) => {
    const data = event.data?.json() || {};
    
    const options = {
        body: data.body || 'Nouvelle notification',
        icon: data.icon || '/icon-192.png',
        badge: '/badge.png',
        vibrate: [100, 50, 100],
        data: data.url || '/',
        actions: data.actions || []
    };
    
    event.waitUntil(
        self.registration.showNotification(data.title || 'Noteso', options)
    );
});

// Click sur notification
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    
    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true })
            .then(clientList => {
                // Ouvrir l'app si déjà ouverte
                for (const client of clientList) {
                    if (client.url.includes(self.location.origin) && 'focus' in client) {
                        return client.focus();
                    }
                }
                // Sinon ouvrir une nouvelle fenêtre
                if (clients.openWindow) {
                    return clients.openWindow(event.notification.data || '/');
                }
            })
    );
});

// Background sync pour les requêtes offline
self.addEventListener('sync', (event) => {
    if (event.tag === 'sync-data') {
        event.waitUntil(syncOfflineData());
    }
});

async function syncOfflineData() {
    // À implémenter: synchroniser les données mises en file d'attente offline
    console.log('[SW] Synchronisation des données offline...');
}
