<?php
/**
 * Rate Limiter - Protection contre les abus API
 * Utilise la base de données MySQL pour le stockage
 */

class RateLimiter {
    // Limites par défaut
    private const DEFAULT_LIMITS = [
        'global' => ['requests' => 100, 'window' => 60],      // 100 req/min global
        'auth' => ['requests' => 5, 'window' => 60],           // 5 req/min pour auth
        'webhook' => ['requests' => 30, 'window' => 60],       // 30 req/min pour webhooks
        'export' => ['requests' => 5, 'window' => 300],        // 5 req/5min pour exports
        'api_heavy' => ['requests' => 20, 'window' => 60],     // 20 req/min pour opérations lourdes
    ];
    
    // Durée de blocage en secondes
    private const BLOCK_DURATION = 300; // 5 minutes
    
    // Endpoints sensibles avec leur catégorie
    private const SENSITIVE_ENDPOINTS = [
        '/auth/login' => 'auth',
        '/auth/forgot-password' => 'auth',
        '/auth/reset-password' => 'auth',
        '/auth/2fa/verify' => 'auth',
        '/webhook/' => 'webhook',
        '/export/' => 'export',
        '/reports/generate' => 'api_heavy',
    ];
    
    /**
     * Vérifie si la requête est autorisée
     * @return array ['allowed' => bool, 'remaining' => int, 'reset' => int, 'blocked_until' => ?string]
     */
    public static function check(string $ip, string $endpoint, ?string $token = null): array {
        // Déterminer la catégorie de limite
        $category = self::getEndpointCategory($endpoint);
        $limits = self::DEFAULT_LIMITS[$category];
        
        // Clé unique: IP + token si disponible
        $key = $token ? "{$ip}:{$token}" : $ip;
        
        // Vérifier si déjà bloqué
        $blocked = Database::fetch(
            "SELECT blocked_until FROM rate_limits 
             WHERE `key` = ? AND endpoint = ? AND blocked_until > NOW()",
            [$key, $category]
        );
        
        if ($blocked) {
            $blockedUntil = strtotime($blocked['blocked_until']);
            return [
                'allowed' => false,
                'remaining' => 0,
                'reset' => $blockedUntil - time(),
                'blocked_until' => $blocked['blocked_until'],
                'category' => $category
            ];
        }
        
        // Calculer la fenêtre actuelle
        $windowStart = date('Y-m-d H:i:s', time() - $limits['window']);
        
        // Récupérer ou créer l'entrée
        $entry = Database::fetch(
            "SELECT * FROM rate_limits 
             WHERE `key` = ? AND endpoint = ? AND window_start > ?",
            [$key, $category, $windowStart]
        );
        
        if (!$entry) {
            // Nouvelle fenêtre
            Database::query(
                "INSERT INTO rate_limits (`key`, endpoint, hits, window_start) 
                 VALUES (?, ?, 1, NOW())
                 ON DUPLICATE KEY UPDATE hits = 1, window_start = NOW(), blocked_until = NULL",
                [$key, $category]
            );
            
            return [
                'allowed' => true,
                'remaining' => $limits['requests'] - 1,
                'reset' => $limits['window'],
                'blocked_until' => null,
                'category' => $category
            ];
        }
        
        // Incrémenter le compteur
        $newHits = $entry['hits'] + 1;
        
        if ($newHits > $limits['requests']) {
            // Limite atteinte - bloquer
            $blockedUntil = date('Y-m-d H:i:s', time() + self::BLOCK_DURATION);
            
            Database::query(
                "UPDATE rate_limits SET hits = ?, blocked_until = ? WHERE id = ?",
                [$newHits, $blockedUntil, $entry['id']]
            );
            
            // Logger l'événement
            self::logRateLimitExceeded($ip, $endpoint, $category, $token);
            
            return [
                'allowed' => false,
                'remaining' => 0,
                'reset' => self::BLOCK_DURATION,
                'blocked_until' => $blockedUntil,
                'category' => $category
            ];
        }
        
        // Incrémenter
        Database::query(
            "UPDATE rate_limits SET hits = ? WHERE id = ?",
            [$newHits, $entry['id']]
        );
        
        $windowAge = time() - strtotime($entry['window_start']);
        
        return [
            'allowed' => true,
            'remaining' => $limits['requests'] - $newHits,
            'reset' => $limits['window'] - $windowAge,
            'blocked_until' => null,
            'category' => $category
        ];
    }
    
    /**
     * Détermine la catégorie d'un endpoint
     */
    private static function getEndpointCategory(string $endpoint): string {
        foreach (self::SENSITIVE_ENDPOINTS as $pattern => $category) {
            if (strpos($endpoint, $pattern) === 0) {
                return $category;
            }
        }
        return 'global';
    }
    
    /**
     * Enregistre un dépassement de limite
     */
    private static function logRateLimitExceeded(string $ip, string $endpoint, string $category, ?string $token): void {
        Database::insert('security_events', [
            'admin_id' => null,
            'event_type' => 'rate_limit_exceeded',
            'severity' => 'warning',
            'ip_address' => $ip,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'details' => json_encode([
                'endpoint' => $endpoint,
                'category' => $category,
                'token_present' => $token !== null
            ])
        ]);
    }
    
    /**
     * Ajoute les headers de rate limit à la réponse
     */
    public static function addHeaders(array $result): void {
        header('X-RateLimit-Limit: ' . (self::DEFAULT_LIMITS[$result['category']]['requests'] ?? 100));
        header('X-RateLimit-Remaining: ' . $result['remaining']);
        header('X-RateLimit-Reset: ' . $result['reset']);
        
        if ($result['blocked_until']) {
            header('Retry-After: ' . $result['reset']);
        }
    }
    
    /**
     * Nettoie les anciennes entrées
     */
    public static function cleanup(): int {
        $result = Database::query(
            "DELETE FROM rate_limits WHERE window_start < DATE_SUB(NOW(), INTERVAL 2 HOUR)"
        );
        return $result->rowCount();
    }
    
    /**
     * Réinitialise le rate limit pour une IP/clé
     */
    public static function reset(string $key, ?string $category = null): bool {
        if ($category) {
            Database::query(
                "DELETE FROM rate_limits WHERE `key` = ? AND endpoint = ?",
                [$key, $category]
            );
        } else {
            Database::query(
                "DELETE FROM rate_limits WHERE `key` = ?",
                [$key]
            );
        }
        return true;
    }
    
    /**
     * Vérifie et bloque si nécessaire, renvoie une erreur si bloqué
     */
    public static function enforce(string $ip, string $endpoint, ?string $token = null): void {
        $result = self::check($ip, $endpoint, $token);
        self::addHeaders($result);
        
        if (!$result['allowed']) {
            http_response_code(429);
            echo json_encode([
                'error' => 'Trop de requêtes. Réessayez dans ' . $result['reset'] . ' secondes.',
                'retry_after' => $result['reset']
            ]);
            exit;
        }
    }
}
