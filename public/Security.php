<?php
/**
 * NOTESO - Security Module
 * 2FA, Rate Limiting, Password Policy
 */

class Security {
    
    // ==================== RATE LIMITING ====================
    
    public static function checkRateLimit(string $key, int $maxAttempts = 5, int $windowSeconds = 900): bool {
        $now = date('Y-m-d H:i:s');
        $windowStart = date('Y-m-d H:i:s', time() - $windowSeconds);
        
        // Nettoyer les anciennes entrées
        Database::query(
            "DELETE FROM rate_limits WHERE window_start < ?",
            [$windowStart]
        );
        
        // Vérifier si bloqué
        $blocked = Database::fetch(
            "SELECT blocked_until FROM rate_limits WHERE `key` = ? AND blocked_until > NOW()",
            [$key]
        );
        
        if ($blocked) {
            return false; // Bloqué
        }
        
        // Compter les tentatives
        $record = Database::fetch(
            "SELECT id, hits FROM rate_limits WHERE `key` = ? AND endpoint IS NULL AND window_start > ?",
            [$key, $windowStart]
        );
        
        if ($record) {
            $newHits = $record['hits'] + 1;
            
            if ($newHits >= $maxAttempts) {
                // Bloquer
                Database::query(
                    "UPDATE rate_limits SET hits = ?, blocked_until = DATE_ADD(NOW(), INTERVAL ? SECOND) WHERE id = ?",
                    [$newHits, $windowSeconds, $record['id']]
                );
                return false;
            }
            
            Database::query("UPDATE rate_limits SET hits = ? WHERE id = ?", [$newHits, $record['id']]);
        } else {
            Database::insert('rate_limits', [
                'key' => $key,
                'hits' => 1,
                'window_start' => $now
            ]);
        }
        
        return true;
    }
    
    public static function resetRateLimit(string $key): void {
        Database::query("DELETE FROM rate_limits WHERE `key` = ?", [$key]);
    }
    
    public static function getRateLimitInfo(string $key): array {
        $record = Database::fetch(
            "SELECT hits, blocked_until, window_start FROM rate_limits WHERE `key` = ? ORDER BY id DESC LIMIT 1",
            [$key]
        );
        
        if (!$record) {
            return ['attempts' => 0, 'blocked' => false, 'blockedUntil' => null];
        }
        
        return [
            'attempts' => (int)$record['hits'],
            'blocked' => $record['blocked_until'] && strtotime($record['blocked_until']) > time(),
            'blockedUntil' => $record['blocked_until']
        ];
    }
    
    // ==================== PASSWORD POLICY ====================
    
    public static function validatePassword(string $password): array {
        $errors = [];
        
        if (strlen($password) < 8) {
            $errors[] = 'Le mot de passe doit contenir au moins 8 caractères';
        }
        
        if (strlen($password) > 128) {
            $errors[] = 'Le mot de passe ne doit pas dépasser 128 caractères';
        }
        
        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = 'Le mot de passe doit contenir au moins une minuscule';
        }
        
        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Le mot de passe doit contenir au moins une majuscule';
        }
        
        if (!preg_match('/[0-9]/', $password)) {
            $errors[] = 'Le mot de passe doit contenir au moins un chiffre';
        }
        
        // Vérifier les mots de passe communs
        $commonPasswords = ['password', '12345678', 'qwerty123', 'admin123', 'letmein', 'welcome'];
        if (in_array(strtolower($password), $commonPasswords)) {
            $errors[] = 'Ce mot de passe est trop courant';
        }
        
        return $errors;
    }
    
    public static function hashPassword(string $password): string {
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);
    }
    
    // ==================== 2FA / TOTP ====================
    
    public static function generateTOTPSecret(): string {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = '';
        for ($i = 0; $i < 32; $i++) {
            $secret .= $chars[random_int(0, 31)];
        }
        return $secret;
    }
    
    public static function getTOTPUri(string $secret, string $email, string $issuer = 'Noteso'): string {
        return sprintf(
            'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30',
            rawurlencode($issuer),
            rawurlencode($email),
            $secret,
            rawurlencode($issuer)
        );
    }
    
    public static function getQRCodeUrl(string $otpUri): string {
        // Utilise l'API Google Charts pour générer le QR code
        return 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=' . urlencode($otpUri);
    }
    
    public static function verifyTOTP(string $secret, string $code, int $window = 1): bool {
        $code = preg_replace('/\s+/', '', $code);
        if (strlen($code) !== 6 || !ctype_digit($code)) {
            return false;
        }
        
        $timestamp = floor(time() / 30);
        
        for ($i = -$window; $i <= $window; $i++) {
            $expectedCode = self::generateTOTPCode($secret, $timestamp + $i);
            if (hash_equals($expectedCode, $code)) {
                return true;
            }
        }
        
        return false;
    }
    
    public static function generateTOTPCode(string $secret, int $timestamp): string {
        $secretDecoded = self::base32Decode($secret);
        $time = pack('N*', 0, $timestamp);
        $hash = hash_hmac('sha1', $time, $secretDecoded, true);
        $offset = ord(substr($hash, -1)) & 0x0F;
        $code = (
            ((ord($hash[$offset]) & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) << 8) |
            (ord($hash[$offset + 3]) & 0xFF)
        ) % 1000000;
        
        return str_pad((string)$code, 6, '0', STR_PAD_LEFT);
    }
    
    private static function base32Decode(string $input): string {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $input = strtoupper(rtrim($input, '='));
        $output = '';
        $buffer = 0;
        $bitsLeft = 0;
        
        for ($i = 0; $i < strlen($input); $i++) {
            $val = strpos($alphabet, $input[$i]);
            if ($val === false) continue;
            
            $buffer = ($buffer << 5) | $val;
            $bitsLeft += 5;
            
            if ($bitsLeft >= 8) {
                $bitsLeft -= 8;
                $output .= chr(($buffer >> $bitsLeft) & 0xFF);
            }
        }
        
        return $output;
    }
    
    // ==================== BACKUP CODES ====================
    
    public static function generateBackupCodes(int $count = 10): array {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            // Format: XXXX-XXXX (8 caractères)
            $codes[] = strtoupper(bin2hex(random_bytes(2))) . '-' . strtoupper(bin2hex(random_bytes(2)));
        }
        return $codes;
    }
    
    public static function hashBackupCodes(array $codes): array {
        return array_map(function($code) {
            return [
                'hash' => hash('sha256', strtoupper(str_replace('-', '', $code))),
                'used' => false
            ];
        }, $codes);
    }
    
    public static function verifyBackupCode(string $code, array $hashedCodes): ?int {
        $codeHash = hash('sha256', strtoupper(str_replace('-', '', $code)));
        
        foreach ($hashedCodes as $index => $item) {
            if (!$item['used'] && hash_equals($item['hash'], $codeHash)) {
                return $index;
            }
        }
        
        return null;
    }
    
    // ==================== SESSION MANAGEMENT ====================
    
    public static function createSession(string $adminId, int $duration = null): array {
        $duration = $duration ?? SESSION_DURATION;
        $token = bin2hex(random_bytes(32));
        $sessionId = 'sess_' . bin2hex(random_bytes(12));
        
        // Détecter le device
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $deviceInfo = self::parseUserAgent($userAgent);
        
        Database::insert('sessions', [
            'id' => $sessionId,
            'admin_id' => $adminId,
            'token' => $token,
            'ip' => self::getClientIP(),
            'user_agent' => $userAgent,
            'device_name' => $deviceInfo['device'],
            'device_type' => $deviceInfo['type'],
            'location' => self::getLocationFromIP(self::getClientIP()),
            'created_at' => date('Y-m-d H:i:s'),
            'expires_at' => date('Y-m-d H:i:s', time() + $duration),
            'last_activity_at' => date('Y-m-d H:i:s')
        ]);
        
        return [
            'id' => $sessionId,
            'token' => $token,
            'expiresAt' => date('Y-m-d H:i:s', time() + $duration)
        ];
    }
    
    public static function getActiveSessions(string $adminId): array {
        return Database::fetchAll(
            "SELECT id, ip, user_agent, device_name, device_type, location, 
                    created_at, last_activity_at, token
             FROM sessions 
             WHERE admin_id = ? AND expires_at > NOW()
             ORDER BY last_activity_at DESC",
            [$adminId]
        );
    }
    
    public static function revokeSession(string $sessionId, string $adminId): bool {
        $result = Database::query(
            "DELETE FROM sessions WHERE id = ? AND admin_id = ?",
            [$sessionId, $adminId]
        );
        return $result->rowCount() > 0;
    }
    
    public static function revokeAllSessions(string $adminId, ?string $exceptToken = null): int {
        if ($exceptToken) {
            $result = Database::query(
                "DELETE FROM sessions WHERE admin_id = ? AND token != ?",
                [$adminId, $exceptToken]
            );
        } else {
            $result = Database::query(
                "DELETE FROM sessions WHERE admin_id = ?",
                [$adminId]
            );
        }
        return $result->rowCount();
    }
    
    private static function parseUserAgent(string $userAgent): array {
        $device = 'Inconnu';
        $type = 'unknown';
        
        // Détecter le type
        if (preg_match('/Mobile|Android|iPhone|iPad/i', $userAgent)) {
            $type = preg_match('/iPad|Tablet/i', $userAgent) ? 'tablet' : 'mobile';
        } else {
            $type = 'desktop';
        }
        
        // Détecter le navigateur
        if (preg_match('/Chrome\/[\d.]+/i', $userAgent)) {
            $device = 'Chrome';
        } elseif (preg_match('/Firefox\/[\d.]+/i', $userAgent)) {
            $device = 'Firefox';
        } elseif (preg_match('/Safari\/[\d.]+/i', $userAgent) && !preg_match('/Chrome/i', $userAgent)) {
            $device = 'Safari';
        } elseif (preg_match('/Edge\/[\d.]+/i', $userAgent)) {
            $device = 'Edge';
        }
        
        // Ajouter l'OS
        if (preg_match('/Windows/i', $userAgent)) {
            $device .= ' sur Windows';
        } elseif (preg_match('/Mac OS/i', $userAgent)) {
            $device .= ' sur Mac';
        } elseif (preg_match('/Linux/i', $userAgent)) {
            $device .= ' sur Linux';
        } elseif (preg_match('/Android/i', $userAgent)) {
            $device .= ' sur Android';
        } elseif (preg_match('/iPhone|iPad/i', $userAgent)) {
            $device .= ' sur iOS';
        }
        
        return ['device' => $device, 'type' => $type];
    }
    
    private static function getLocationFromIP(string $ip): string {
        // Simplification - en production, utiliser un service de géolocalisation
        if ($ip === '127.0.0.1' || $ip === '::1' || strpos($ip, '192.168.') === 0) {
            return 'Local';
        }
        return 'Inconnu';
    }
    
    private static function getClientIP(): string {
        return $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }
    
    // ==================== SECURITY EVENTS ====================
    
    public static function logEvent(string $type, ?string $adminId, ?string $tenantId = null, array $details = [], string $severity = 'info'): void {
        try {
            Database::query(
                "INSERT INTO security_events (admin_id, event_type, severity, ip_address, user_agent, details, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, NOW())",
                [
                    $adminId,
                    $type,
                    $severity,
                    self::getClientIP(),
                    $_SERVER['HTTP_USER_AGENT'] ?? null,
                    json_encode(array_merge($details, ['tenant_id' => $tenantId]))
                ]
            );
        } catch (Exception $e) {
            // Silently fail
        }
    }
    
    public static function getSecurityEvents(?string $adminId = null, int $limit = 50): array {
        if ($adminId) {
            return Database::fetchAll(
                "SELECT * FROM security_events WHERE admin_id = ? ORDER BY created_at DESC LIMIT ?",
                [$adminId, $limit]
            );
        }
        
        return Database::fetchAll(
            "SELECT se.*, a.email as admin_email 
             FROM security_events se
             LEFT JOIN admins a ON se.admin_id = a.id
             ORDER BY se.created_at DESC LIMIT ?",
            [$limit]
        );
    }
}
