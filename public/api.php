<?php
/**
 * NOTESO - API Backend Multi-Tenant
 * Dashboard Multi-Sites mutualisé
 */

ini_set('display_errors', 0);
error_reporting(E_ALL);

ob_start();

set_error_handler(function($severity, $message, $file, $line) {
    throw new ErrorException($message, 0, $severity, $file, $line);
});

set_exception_handler(function($e) {
    ob_end_clean();
    header('Content-Type: application/json; charset=utf-8');
    http_response_code(500);
    echo json_encode([
        'error' => 'Erreur serveur: ' . $e->getMessage(),
        'file' => basename($e->getFile()),
        'line' => $e->getLine()
    ]);
    exit;
});

define('BASE_DIR', __DIR__);
define('ROOT_DIR', dirname(__DIR__));

require_once __DIR__ . '/Database.php';

// Charger la configuration
$CONFIG = [];
$configPaths = [ROOT_DIR . '/config/config.php', ROOT_DIR . '/config.php', BASE_DIR . '/config.php'];
foreach ($configPaths as $configPath) {
    if (file_exists($configPath)) {
        $CONFIG = require $configPath;
        break;
    }
}

Database::configure([
    'host'     => $CONFIG['database']['host'] ?? 'localhost',
    'port'     => $CONFIG['database']['port'] ?? 3306,
    'database' => $CONFIG['database']['name'] ?? 'noteso',
    'username' => $CONFIG['database']['user'] ?? 'root',
    'password' => $CONFIG['database']['password'] ?? '',
    'charset'  => 'utf8mb4'
]);

define('SESSION_DURATION', $CONFIG['security']['session_duration'] ?? 604800);
define('BCRYPT_COST', $CONFIG['security']['bcrypt_cost'] ?? 12);
define('TRIAL_DAYS', 14);

date_default_timezone_set($CONFIG['app']['timezone'] ?? 'Europe/Paris');

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Helpers
function generateId(string $prefix = ''): string {
    return $prefix . bin2hex(random_bytes(12));
}

function generateSlug(string $name): string {
    $slug = strtolower(trim($name));
    $slug = preg_replace('/[^a-z0-9]+/', '-', $slug);
    $slug = trim($slug, '-');
    return $slug . '-' . substr(bin2hex(random_bytes(3)), 0, 6);
}

function jsonResponse($data, int $code = 200): void {
    ob_end_clean();
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function getAuthToken(): ?string {
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/Bearer\s+(.+)/i', $header, $m)) return $m[1];
    return $_GET['token'] ?? $_POST['token'] ?? null;
}

function getClientIP(): string {
    return $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function validateSession(): ?array {
    $token = getAuthToken();
    if (!$token) return null;
    
    $session = Database::fetch(
        "SELECT s.*, a.email, a.first_name, a.last_name, a.role, a.tenant_id, a.is_super_admin,
                a.two_factor_enabled, a.two_factor_secret,
                t.name as tenant_name, t.slug as tenant_slug, t.plan as tenant_plan, t.status as tenant_status,
                t.max_sites, t.max_admins, t.max_users
         FROM sessions s 
         JOIN admins a ON s.admin_id = a.id 
         LEFT JOIN tenants t ON a.tenant_id = t.id
         WHERE s.token = ? AND s.expires_at > NOW() AND a.is_active = 1",
        [$token]
    );
    
    if ($session) {
        // Vérifier le statut du tenant
        if ($session['tenant_status'] && !in_array($session['tenant_status'], ['active', 'trial'])) {
            return null;
        }
        
        Database::query("UPDATE sessions SET last_activity_at = NOW() WHERE id = ?", [$session['id']]);
        Database::query("UPDATE admins SET last_seen_at = NOW() WHERE id = ?", [$session['admin_id']]);
    }
    
    return $session;
}

function requireAuth(): array {
    $session = validateSession();
    if (!$session) jsonResponse(['error' => 'Non autorisé'], 401);
    return $session;
}

function requireSuperAdmin(): array {
    $session = requireAuth();
    if (!$session['is_super_admin']) jsonResponse(['error' => 'Accès super admin requis'], 403);
    return $session;
}

function getTenantId(array $session): ?string {
    return $session['is_super_admin'] ? null : $session['tenant_id'];
}

function logSecurityEvent(string $type, ?string $adminId, ?string $tenantId, array $details = []): void {
    try {
        Database::insert('security_events', [
            'admin_id' => $adminId,
            'event_type' => $type,
            'severity' => $details['severity'] ?? 'info',
            'ip_address' => getClientIP(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'details' => json_encode(array_merge($details, ['tenant_id' => $tenantId])),
            'created_at' => date('Y-m-d H:i:s')
        ]);
    } catch (Exception $e) {}
}

function verifyTOTP(string $secret, string $code, int $window = 1): bool {
    $code = preg_replace('/\s+/', '', $code);
    if (strlen($code) !== 6 || !ctype_digit($code)) return false;
    
    $timestamp = floor(time() / 30);
    for ($i = -$window; $i <= $window; $i++) {
        if (hash_equals(generateTOTPCode($secret, $timestamp + $i), $code)) return true;
    }
    return false;
}

function generateTOTPCode(string $secret, int $timestamp): string {
    $secret = base32Decode($secret);
    $time = pack('N*', 0, $timestamp);
    $hash = hash_hmac('sha1', $time, $secret, true);
    $offset = ord(substr($hash, -1)) & 0x0F;
    $code = (((ord($hash[$offset]) & 0x7F) << 24) | ((ord($hash[$offset + 1]) & 0xFF) << 16) |
             ((ord($hash[$offset + 2]) & 0xFF) << 8) | (ord($hash[$offset + 3]) & 0xFF)) % 1000000;
    return str_pad((string)$code, 6, '0', STR_PAD_LEFT);
}

function base32Decode(string $input): string {
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

function base32Decode(string $input): string {
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

function generateBase32Secret(int $length = 32): string {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = '';
    for ($i = 0; $i < $length; $i++) {
        $secret .= $chars[random_int(0, 31)];
    }
    return $secret;
}

function parseUserAgent(string $userAgent): string {
    $device = 'Navigateur inconnu';
    
    if (preg_match('/Chrome\/[\d.]+/i', $userAgent)) {
        $device = 'Chrome';
    } elseif (preg_match('/Firefox\/[\d.]+/i', $userAgent)) {
        $device = 'Firefox';
    } elseif (preg_match('/Safari\/[\d.]+/i', $userAgent) && !preg_match('/Chrome/i', $userAgent)) {
        $device = 'Safari';
    } elseif (preg_match('/Edge\/[\d.]+/i', $userAgent)) {
        $device = 'Edge';
    }
    
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
    
    return $device;
}

function checkRateLimit(string $key, int $maxAttempts = 5, int $windowSeconds = 900): bool {
    $windowStart = date('Y-m-d H:i:s', time() - $windowSeconds);
    
    // Compter les tentatives échouées récentes
    $attempts = Database::fetchColumn(
        "SELECT COUNT(*) FROM login_attempts WHERE email = ? AND success = 0 AND created_at > ?",
        [$key, $windowStart]
    );
    
    return $attempts < $maxAttempts;
}

function checkTenantLimits(string $tenantId, string $type): bool {
    $tenant = Database::fetch("SELECT * FROM tenants WHERE id = ?", [$tenantId]);
    if (!$tenant) return false;
    
    switch ($type) {
        case 'sites':
            $count = Database::fetchColumn("SELECT COUNT(*) FROM sites WHERE tenant_id = ?", [$tenantId]);
            return $count < $tenant['max_sites'];
        case 'admins':
            $count = Database::fetchColumn("SELECT COUNT(*) FROM admins WHERE tenant_id = ?", [$tenantId]);
            return $count < $tenant['max_admins'];
        case 'users':
            $count = Database::fetchColumn(
                "SELECT COUNT(*) FROM users u JOIN sites s ON u.site_id = s.id WHERE s.tenant_id = ?",
                [$tenantId]
            );
            return $count < $tenant['max_users'];
    }
    return true;
}

// Router
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$path = preg_replace('#^.*/api\.php#', '', $path);
$path = trim($path, '/') ?: ($_GET['action'] ?? '');
$path = preg_replace('#^api/?#', '', $path);

$input = json_decode(file_get_contents('php://input'), true) ?? [];
$input = array_merge($_GET, $_POST, $input);

try {
    switch ($path) {
        
        // ==================== AUTH ====================
        case 'login':
        case 'auth/login':
            if ($method !== 'POST') jsonResponse(['error' => 'Méthode non autorisée'], 405);
            
            $email = trim($input['email'] ?? '');
            $password = $input['password'] ?? '';
            
            if (!$email || !$password) jsonResponse(['error' => 'Email et mot de passe requis'], 400);
            
            // Rate limiting
            if (!checkRateLimit($email, 5, 900)) {
                logSecurityEvent('rate_limit_exceeded', null, null, ['email' => $email], 'warning');
                jsonResponse(['error' => 'Trop de tentatives. Réessayez dans 15 minutes.'], 429);
            }
            
            $admin = Database::fetch(
                "SELECT a.*, t.status as tenant_status, t.name as tenant_name 
                 FROM admins a 
                 LEFT JOIN tenants t ON a.tenant_id = t.id
                 WHERE a.email = ? AND a.is_active = 1",
                [$email]
            );
            
            if (!$admin || !password_verify($password, $admin['password'])) {
                Database::insert('login_attempts', [
                    'email' => $email, 'ip' => getClientIP(), 'success' => 0,
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null
                ]);
                logSecurityEvent('login_failed', null, null, ['email' => $email], 'warning');
                jsonResponse(['error' => 'Identifiants incorrects'], 401);
            }
            
            // Vérifier statut tenant
            if ($admin['tenant_id'] && $admin['tenant_status'] && 
                !in_array($admin['tenant_status'], ['active', 'trial']) && !$admin['is_super_admin']) {
                jsonResponse(['error' => 'Compte suspendu. Contactez le support.'], 403);
            }
            
            // Check 2FA
            if ($admin['two_factor_enabled'] && $admin['two_factor_secret']) {
                $totpCode = $input['totp_code'] ?? $input['code'] ?? null;
                
                if (!$totpCode) {
                    $tempToken = bin2hex(random_bytes(15));
                    Database::query(
                        "INSERT INTO sessions (id, admin_id, token, ip, user_agent, created_at, expires_at) 
                         VALUES (?, ?, ?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 5 MINUTE))",
                        [generateId('2fa_'), $admin['id'], $tempToken, getClientIP(), $_SERVER['HTTP_USER_AGENT'] ?? null]
                    );
                    jsonResponse(['requires_2fa' => true, 'temp_token' => $tempToken, 'message' => 'Code 2FA requis']);
                }
                
                // Vérifier si c'est un code TOTP ou un code de backup
                $isValidTOTP = verifyTOTP($admin['two_factor_secret'], $totpCode);
                $isValidBackup = false;
                
                if (!$isValidTOTP && strlen(preg_replace('/[^A-Z0-9]/i', '', $totpCode)) === 8) {
                    // Essayer comme code de backup
                    $backupCodes = json_decode($admin['backup_codes'] ?? '[]', true);
                    $cleanCode = strtoupper(preg_replace('/[^A-Z0-9]/i', '', $totpCode));
                    $codeIndex = array_search($cleanCode, $backupCodes);
                    
                    if ($codeIndex !== false) {
                        $isValidBackup = true;
                        // Supprimer le code utilisé
                        unset($backupCodes[$codeIndex]);
                        Database::query(
                            "UPDATE admins SET backup_codes = ? WHERE id = ?",
                            [json_encode(array_values($backupCodes)), $admin['id']]
                        );
                        logSecurityEvent('backup_code_used', $admin['id'], $admin['tenant_id'], [
                            'remaining_codes' => count($backupCodes)
                        ]);
                    }
                }
                
                if (!$isValidTOTP && !$isValidBackup) {
                    logSecurityEvent('2fa_failed', $admin['id'], $admin['tenant_id'], ['email' => $email]);
                    jsonResponse(['error' => 'Code 2FA invalide'], 401);
                }
            }
            
            // Créer session
            $token = bin2hex(random_bytes(32));
            $sessionId = generateId('sess_');
            
            Database::insert('sessions', [
                'id' => $sessionId, 'admin_id' => $admin['id'], 'token' => $token,
                'ip' => getClientIP(), 'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
                'created_at' => date('Y-m-d H:i:s'),
                'expires_at' => date('Y-m-d H:i:s', time() + SESSION_DURATION)
            ]);
            
            Database::query(
                "UPDATE admins SET last_login_at = NOW(), last_login_ip = ? WHERE id = ?",
                [getClientIP(), $admin['id']]
            );
            
            Database::insert('login_attempts', [
                'email' => $email, 'ip' => getClientIP(), 'success' => 1,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null
            ]);
            
            logSecurityEvent('login_success', $admin['id'], $admin['tenant_id'], []);
            
            jsonResponse([
                'success' => true,
                'token' => $token,
                'admin' => [
                    'id' => $admin['id'],
                    'email' => $admin['email'],
                    'firstName' => $admin['first_name'],
                    'lastName' => $admin['last_name'],
                    'role' => $admin['role'],
                    'isSuperAdmin' => (bool)$admin['is_super_admin'],
                    'tenantId' => $admin['tenant_id'],
                    'tenantName' => $admin['tenant_name']
                ]
            ]);
            break;
            
        // ==================== REGISTER (nouveau tenant) ====================
        case 'register':
        case 'auth/register':
            if ($method !== 'POST') jsonResponse(['error' => 'Méthode non autorisée'], 405);
            
            $orgName = trim($input['organization'] ?? $input['orgName'] ?? '');
            $email = trim($input['email'] ?? '');
            $password = $input['password'] ?? '';
            $firstName = trim($input['firstName'] ?? '');
            $lastName = trim($input['lastName'] ?? '');
            
            if (!$orgName || !$email || !$password || !$firstName || !$lastName) {
                jsonResponse(['error' => 'Tous les champs sont requis'], 400);
            }
            
            if (strlen($password) < 8) {
                jsonResponse(['error' => 'Le mot de passe doit contenir au moins 8 caractères'], 400);
            }
            
            // Vérifier si email existe
            $existing = Database::fetch("SELECT id FROM admins WHERE email = ?", [$email]);
            if ($existing) jsonResponse(['error' => 'Cet email est déjà utilisé'], 400);
            
            $existingTenant = Database::fetch("SELECT id FROM tenants WHERE email = ?", [$email]);
            if ($existingTenant) jsonResponse(['error' => 'Cette organisation existe déjà'], 400);
            
            // Créer le tenant
            $tenantId = generateId('tenant_');
            $slug = generateSlug($orgName);
            
            Database::insert('tenants', [
                'id' => $tenantId,
                'name' => $orgName,
                'slug' => $slug,
                'email' => $email,
                'plan' => 'free',
                'status' => 'trial',
                'trial_ends_at' => date('Y-m-d H:i:s', strtotime('+' . TRIAL_DAYS . ' days')),
                'max_sites' => 1,
                'max_admins' => 2,
                'max_users' => 100,
                'created_at' => date('Y-m-d H:i:s')
            ]);
            
            // Créer l'admin
            $adminId = generateId('admin_');
            $hashedPassword = password_hash($password, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);
            
            Database::insert('admins', [
                'id' => $adminId,
                'tenant_id' => $tenantId,
                'email' => $email,
                'password' => $hashedPassword,
                'first_name' => $firstName,
                'last_name' => $lastName,
                'role' => 'admin',
                'is_super_admin' => 0,
                'is_active' => 1,
                'created_at' => date('Y-m-d H:i:s')
            ]);
            
            // Créer une session
            $token = bin2hex(random_bytes(32));
            Database::insert('sessions', [
                'id' => generateId('sess_'),
                'admin_id' => $adminId,
                'token' => $token,
                'ip' => getClientIP(),
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
                'created_at' => date('Y-m-d H:i:s'),
                'expires_at' => date('Y-m-d H:i:s', time() + SESSION_DURATION)
            ]);
            
            logSecurityEvent('tenant_created', $adminId, $tenantId, ['org' => $orgName]);
            
            jsonResponse([
                'success' => true,
                'token' => $token,
                'tenant' => ['id' => $tenantId, 'name' => $orgName, 'slug' => $slug],
                'admin' => [
                    'id' => $adminId,
                    'email' => $email,
                    'firstName' => $firstName,
                    'lastName' => $lastName,
                    'role' => 'admin'
                ]
            ]);
            break;
            
        case 'logout':
        case 'auth/logout':
            $session = validateSession();
            if ($session) {
                Database::delete('sessions', 'token = ?', [getAuthToken()]);
                logSecurityEvent('logout', $session['admin_id'], $session['tenant_id'], []);
            }
            jsonResponse(['success' => true]);
            break;
            
        case 'me':
        case 'auth/me':
            $session = requireAuth();
            
            // Compter les sessions actives
            $sessionCount = Database::fetchColumn(
                "SELECT COUNT(*) FROM sessions WHERE admin_id = ? AND expires_at > NOW()",
                [$session['admin_id']]
            );
            
            // Dernier changement de mot de passe
            $admin = Database::fetch(
                "SELECT password_changed_at, backup_codes FROM admins WHERE id = ?",
                [$session['admin_id']]
            );
            
            $backupCodesCount = count(json_decode($admin['backup_codes'] ?? '[]', true));
            
            jsonResponse([
                'id' => $session['admin_id'],
                'email' => $session['email'],
                'firstName' => $session['first_name'],
                'lastName' => $session['last_name'],
                'role' => $session['role'],
                'isSuperAdmin' => (bool)$session['is_super_admin'],
                'security' => [
                    'twoFactorEnabled' => (bool)$session['two_factor_enabled'],
                    'backupCodesRemaining' => $backupCodesCount,
                    'activeSessions' => (int)$sessionCount,
                    'passwordChangedAt' => $admin['password_changed_at']
                ],
                'tenant' => $session['tenant_id'] ? [
                    'id' => $session['tenant_id'],
                    'name' => $session['tenant_name'],
                    'slug' => $session['tenant_slug'],
                    'plan' => $session['tenant_plan'],
                    'status' => $session['tenant_status'],
                    'limits' => [
                        'maxSites' => (int)$session['max_sites'],
                        'maxAdmins' => (int)$session['max_admins'],
                        'maxUsers' => (int)$session['max_users']
                    ]
                ] : null
            ]);
            break;
            
        // ==================== DASHBOARD ====================
        case 'dashboard':
        case 'stats':
            $session = requireAuth();
            $tenantId = getTenantId($session);
            $period = $input['period'] ?? '30d';
            
            $days = match($period) { '7d' => 7, '30d' => 30, '90d' => 90, '12m' => 365, default => 30 };
            $startDate = date('Y-m-d', strtotime("-{$days} days"));
            
            $tenantFilter = $tenantId ? "AND s.tenant_id = ?" : "";
            $params = $tenantId ? [$startDate, $tenantId] : [$startDate];
            
            $totalRevenue = Database::fetchColumn(
                "SELECT COALESCE(SUM(p.amount), 0) FROM payments p 
                 JOIN sites s ON p.site_id = s.id 
                 WHERE p.status = 'completed' AND p.created_at >= ? $tenantFilter",
                $params
            ) ?: 0;
            
            $totalUsers = Database::fetchColumn(
                "SELECT COUNT(*) FROM users u 
                 JOIN sites s ON u.site_id = s.id 
                 WHERE u.created_at >= ? $tenantFilter",
                $params
            ) ?: 0;
            
            $totalPayments = Database::fetchColumn(
                "SELECT COUNT(*) FROM payments p 
                 JOIN sites s ON p.site_id = s.id 
                 WHERE p.status = 'completed' AND p.created_at >= ? $tenantFilter",
                $params
            ) ?: 0;
            
            $subsParams = $tenantId ? [$tenantId] : [];
            $activeSubscriptions = Database::fetchColumn(
                "SELECT COUNT(*) FROM subscriptions sub 
                 JOIN sites s ON sub.site_id = s.id 
                 WHERE sub.status = 'active'" . ($tenantId ? " AND s.tenant_id = ?" : ""),
                $subsParams
            ) ?: 0;
            
            $mrr = Database::fetchColumn(
                "SELECT COALESCE(SUM(sub.amount), 0) FROM subscriptions sub 
                 JOIN sites s ON sub.site_id = s.id 
                 WHERE sub.status = 'active'" . ($tenantId ? " AND s.tenant_id = ?" : ""),
                $subsParams
            ) ?: 0;
            
            // Période précédente
            $prevStartDate = date('Y-m-d', strtotime("-" . ($days * 2) . " days"));
            $prevParams = $tenantId ? [$prevStartDate, $startDate, $tenantId] : [$prevStartDate, $startDate];
            
            $prevRevenue = Database::fetchColumn(
                "SELECT COALESCE(SUM(p.amount), 0) FROM payments p 
                 JOIN sites s ON p.site_id = s.id 
                 WHERE p.status = 'completed' AND p.created_at >= ? AND p.created_at < ? $tenantFilter",
                $prevParams
            ) ?: 0;
            
            $prevUsers = Database::fetchColumn(
                "SELECT COUNT(*) FROM users u 
                 JOIN sites s ON u.site_id = s.id 
                 WHERE u.created_at >= ? AND u.created_at < ? $tenantFilter",
                $prevParams
            ) ?: 0;
            
            $revenueChange = $prevRevenue > 0 ? round((($totalRevenue - $prevRevenue) / $prevRevenue) * 100, 1) : 0;
            $usersChange = $prevUsers > 0 ? round((($totalUsers - $prevUsers) / $prevUsers) * 100, 1) : 0;
            
            // Graphique
            $chartParams = $tenantId ? [$startDate, $tenantId] : [$startDate];
            $chartData = Database::fetchAll(
                "SELECT DATE(p.created_at) as date, SUM(p.amount) as revenue, COUNT(*) as payments
                 FROM payments p 
                 JOIN sites s ON p.site_id = s.id
                 WHERE p.status = 'completed' AND p.created_at >= ? $tenantFilter
                 GROUP BY DATE(p.created_at) ORDER BY date",
                $chartParams
            );
            
            // Activités
            $actParams = $tenantId ? [$tenantId] : [];
            $activities = Database::fetchAll(
                "SELECT a.*, s.name as site_name, s.color as site_color
                 FROM activities a
                 LEFT JOIN sites s ON a.site_id = s.id
                 " . ($tenantId ? "WHERE s.tenant_id = ?" : "") . "
                 ORDER BY a.created_at DESC LIMIT 20",
                $actParams
            );
            
            jsonResponse([
                'stats' => [
                    'revenue' => ['value' => (float)$totalRevenue, 'change' => $revenueChange, 'period' => $period],
                    'users' => ['value' => (int)$totalUsers, 'change' => $usersChange, 'period' => $period],
                    'payments' => ['value' => (int)$totalPayments, 'period' => $period],
                    'subscriptions' => ['value' => (int)$activeSubscriptions, 'mrr' => (float)$mrr]
                ],
                'chart' => $chartData,
                'activities' => array_map(fn($a) => [
                    'id' => $a['id'], 'type' => $a['type'], 'description' => $a['description'],
                    'siteName' => $a['site_name'], 'siteColor' => $a['site_color'],
                    'createdAt' => $a['created_at'], 'metadata' => json_decode($a['metadata'] ?? '{}', true)
                ], $activities)
            ]);
            break;
            
        // ==================== SITES ====================
        case 'sites':
            $session = requireAuth();
            $tenantId = getTenantId($session);
            
            if ($method === 'GET') {
                $params = $tenantId ? [$tenantId] : [];
                $sites = Database::fetchAll(
                    "SELECT s.*,
                            (SELECT COUNT(*) FROM users WHERE site_id = s.id) as user_count,
                            (SELECT COUNT(*) FROM payments WHERE site_id = s.id AND status = 'completed') as payment_count,
                            (SELECT COALESCE(SUM(amount), 0) FROM payments WHERE site_id = s.id AND status = 'completed') as total_revenue
                     FROM sites s " . ($tenantId ? "WHERE s.tenant_id = ?" : "") . " ORDER BY s.name",
                    $params
                );
                
                jsonResponse(array_map(fn($s) => [
                    'id' => $s['id'], 'name' => $s['name'], 'url' => $s['url'],
                    'status' => $s['status'], 'color' => $s['color'], 'apiKey' => $s['api_key'],
                    'userCount' => (int)$s['user_count'], 'paymentCount' => (int)$s['payment_count'],
                    'totalRevenue' => (float)$s['total_revenue'], 'createdAt' => $s['created_at']
                ], $sites));
            }
            
            if ($method === 'POST') {
                $tenantId = $session['tenant_id'];
                if (!$tenantId) jsonResponse(['error' => 'Tenant requis'], 400);
                
                if (!checkTenantLimits($tenantId, 'sites')) {
                    jsonResponse(['error' => 'Limite de sites atteinte. Passez à un plan supérieur.'], 403);
                }
                
                $name = trim($input['name'] ?? '');
                $url = trim($input['url'] ?? '');
                if (!$name || !$url) jsonResponse(['error' => 'Nom et URL requis'], 400);
                
                $siteId = generateId('site_');
                $apiKey = 'sk_' . bin2hex(random_bytes(16));
                
                Database::insert('sites', [
                    'id' => $siteId, 'tenant_id' => $tenantId, 'name' => $name, 'url' => $url,
                    'color' => $input['color'] ?? '#3b82f6', 'api_key' => $apiKey, 'status' => 'online'
                ]);
                
                jsonResponse(['success' => true, 'site' => ['id' => $siteId, 'name' => $name, 'url' => $url, 'apiKey' => $apiKey]]);
            }
            break;
            
        case (preg_match('#^sites/([^/]+)$#', $path, $m) ? true : false):
            $session = requireAuth();
            $tenantId = getTenantId($session);
            $siteId = $m[1];
            
            $tenantCheck = $tenantId ? " AND tenant_id = ?" : "";
            $params = $tenantId ? [$siteId, $tenantId] : [$siteId];
            
            if ($method === 'GET') {
                $site = Database::fetch("SELECT * FROM sites WHERE id = ? $tenantCheck", $params);
                if (!$site) jsonResponse(['error' => 'Site non trouvé'], 404);
                jsonResponse($site);
            }
            
            if ($method === 'PUT') {
                $updates = [];
                $updateParams = [];
                foreach (['name', 'url', 'color', 'status'] as $field) {
                    if (isset($input[$field])) {
                        $updates[] = "`{$field}` = ?";
                        $updateParams[] = $input[$field];
                    }
                }
                if ($updates) {
                    $updateParams = array_merge($updateParams, $params);
                    Database::query("UPDATE sites SET " . implode(', ', $updates) . " WHERE id = ? $tenantCheck", $updateParams);
                }
                jsonResponse(['success' => true]);
            }
            
            if ($method === 'DELETE') {
                Database::query("DELETE FROM sites WHERE id = ? $tenantCheck", $params);
                jsonResponse(['success' => true]);
            }
            break;
            
        // ==================== USERS ====================
        case 'users':
            $session = requireAuth();
            $tenantId = getTenantId($session);
            
            $page = max(1, (int)($input['page'] ?? 1));
            $limit = min(100, max(10, (int)($input['limit'] ?? 20)));
            $offset = ($page - 1) * $limit;
            $search = $input['search'] ?? '';
            
            $where = $tenantId ? ["s.tenant_id = ?"] : [];
            $params = $tenantId ? [$tenantId] : [];
            
            if ($search) {
                $where[] = "(u.email LIKE ? OR u.name LIKE ?)";
                $params[] = "%{$search}%";
                $params[] = "%{$search}%";
            }
            
            $whereClause = $where ? 'WHERE ' . implode(' AND ', $where) : '';
            
            $total = Database::fetchColumn("SELECT COUNT(*) FROM users u JOIN sites s ON u.site_id = s.id $whereClause", $params);
            
            $users = Database::fetchAll(
                "SELECT u.*, s.name as site_name, s.color as site_color
                 FROM users u JOIN sites s ON u.site_id = s.id $whereClause
                 ORDER BY u.created_at DESC LIMIT $limit OFFSET $offset",
                $params
            );
            
            jsonResponse([
                'users' => array_map(fn($u) => [
                    'id' => $u['id'], 'email' => $u['email'], 'name' => $u['name'],
                    'siteId' => $u['site_id'], 'siteName' => $u['site_name'], 'siteColor' => $u['site_color'],
                    'createdAt' => $u['created_at'], 'metadata' => json_decode($u['metadata'] ?? '{}', true)
                ], $users),
                'pagination' => ['page' => $page, 'limit' => $limit, 'total' => (int)$total, 'pages' => ceil($total / $limit)]
            ]);
            break;
            
        // ==================== PAYMENTS ====================
        case 'payments':
            $session = requireAuth();
            $tenantId = getTenantId($session);
            
            $page = max(1, (int)($input['page'] ?? 1));
            $limit = min(100, max(10, (int)($input['limit'] ?? 20)));
            $offset = ($page - 1) * $limit;
            $status = $input['status'] ?? null;
            
            $where = $tenantId ? ["s.tenant_id = ?"] : [];
            $params = $tenantId ? [$tenantId] : [];
            
            if ($status) {
                $where[] = "p.status = ?";
                $params[] = $status;
            }
            
            $whereClause = $where ? 'WHERE ' . implode(' AND ', $where) : '';
            
            $total = Database::fetchColumn("SELECT COUNT(*) FROM payments p JOIN sites s ON p.site_id = s.id $whereClause", $params);
            
            $payments = Database::fetchAll(
                "SELECT p.*, s.name as site_name, s.color as site_color, u.email as user_email
                 FROM payments p
                 JOIN sites s ON p.site_id = s.id
                 LEFT JOIN users u ON p.user_id = u.id
                 $whereClause ORDER BY p.created_at DESC LIMIT $limit OFFSET $offset",
                $params
            );
            
            jsonResponse([
                'payments' => array_map(fn($p) => [
                    'id' => $p['id'], 'amount' => (float)$p['amount'], 'currency' => $p['currency'],
                    'status' => $p['status'], 'provider' => $p['provider'],
                    'siteId' => $p['site_id'], 'siteName' => $p['site_name'], 'siteColor' => $p['site_color'],
                    'userEmail' => $p['user_email'], 'createdAt' => $p['created_at'], 'paidAt' => $p['paid_at']
                ], $payments),
                'pagination' => ['page' => $page, 'limit' => $limit, 'total' => (int)$total, 'pages' => ceil($total / $limit)]
            ]);
            break;
            
        // ==================== SUBSCRIPTIONS ====================
        case 'subscriptions':
            $session = requireAuth();
            $tenantId = getTenantId($session);
            
            $status = $input['status'] ?? null;
            
            $where = $tenantId ? ["s.tenant_id = ?"] : [];
            $params = $tenantId ? [$tenantId] : [];
            
            if ($status) {
                $where[] = "sub.status = ?";
                $params[] = $status;
            }
            
            $whereClause = $where ? 'WHERE ' . implode(' AND ', $where) : '';
            
            $subscriptions = Database::fetchAll(
                "SELECT sub.*, s.name as site_name, s.color as site_color, u.email as user_email
                 FROM subscriptions sub
                 JOIN sites s ON sub.site_id = s.id
                 LEFT JOIN users u ON sub.user_id = u.id
                 $whereClause ORDER BY sub.created_at DESC LIMIT 100",
                $params
            );
            
            jsonResponse([
                'subscriptions' => array_map(fn($sub) => [
                    'id' => $sub['id'], 'plan' => $sub['plan'], 'status' => $sub['status'],
                    'amount' => (float)$sub['amount'], 'currency' => $sub['currency'],
                    'billingCycle' => $sub['billing_cycle'],
                    'siteId' => $sub['site_id'], 'siteName' => $sub['site_name'], 'siteColor' => $sub['site_color'],
                    'userEmail' => $sub['user_email'], 'currentPeriodEnd' => $sub['current_period_end'],
                    'createdAt' => $sub['created_at']
                ], $subscriptions)
            ]);
            break;
            
        // ==================== TEAM (admins du tenant) ====================
        case 'team':
            $session = requireAuth();
            $tenantId = $session['tenant_id'];
            
            if (!$tenantId) jsonResponse(['error' => 'Tenant requis'], 400);
            
            if ($method === 'GET') {
                $admins = Database::fetchAll(
                    "SELECT id, email, first_name, last_name, role, is_active, created_at, last_login_at
                     FROM admins WHERE tenant_id = ? ORDER BY created_at",
                    [$tenantId]
                );
                
                jsonResponse(array_map(fn($a) => [
                    'id' => $a['id'], 'email' => $a['email'],
                    'firstName' => $a['first_name'], 'lastName' => $a['last_name'],
                    'role' => $a['role'], 'isActive' => (bool)$a['is_active'],
                    'createdAt' => $a['created_at'], 'lastLoginAt' => $a['last_login_at']
                ], $admins));
            }
            
            if ($method === 'POST') {
                if ($session['role'] !== 'admin' && $session['role'] !== 'super_admin') {
                    jsonResponse(['error' => 'Permission refusée'], 403);
                }
                
                if (!checkTenantLimits($tenantId, 'admins')) {
                    jsonResponse(['error' => 'Limite d\'administrateurs atteinte'], 403);
                }
                
                $email = trim($input['email'] ?? '');
                $password = $input['password'] ?? '';
                $firstName = trim($input['firstName'] ?? '');
                $lastName = trim($input['lastName'] ?? '');
                $role = $input['role'] ?? 'viewer';
                
                if (!$email || !$password || !$firstName || !$lastName) {
                    jsonResponse(['error' => 'Tous les champs sont requis'], 400);
                }
                
                $existing = Database::fetch("SELECT id FROM admins WHERE email = ?", [$email]);
                if ($existing) jsonResponse(['error' => 'Email déjà utilisé'], 400);
                
                $adminId = generateId('admin_');
                Database::insert('admins', [
                    'id' => $adminId, 'tenant_id' => $tenantId, 'email' => $email,
                    'password' => password_hash($password, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]),
                    'first_name' => $firstName, 'last_name' => $lastName,
                    'role' => $role, 'is_active' => 1, 'created_at' => date('Y-m-d H:i:s')
                ]);
                
                jsonResponse(['success' => true, 'admin' => ['id' => $adminId, 'email' => $email]]);
            }
            break;
            
        // ==================== TENANT SETTINGS ====================
        case 'tenant':
            $session = requireAuth();
            $tenantId = $session['tenant_id'];
            
            if (!$tenantId) jsonResponse(['error' => 'Tenant requis'], 400);
            
            if ($method === 'GET') {
                $tenant = Database::fetch("SELECT * FROM tenants WHERE id = ?", [$tenantId]);
                
                $siteCount = Database::fetchColumn("SELECT COUNT(*) FROM sites WHERE tenant_id = ?", [$tenantId]);
                $adminCount = Database::fetchColumn("SELECT COUNT(*) FROM admins WHERE tenant_id = ?", [$tenantId]);
                $userCount = Database::fetchColumn(
                    "SELECT COUNT(*) FROM users u JOIN sites s ON u.site_id = s.id WHERE s.tenant_id = ?",
                    [$tenantId]
                );
                
                jsonResponse([
                    'id' => $tenant['id'], 'name' => $tenant['name'], 'slug' => $tenant['slug'],
                    'email' => $tenant['email'], 'plan' => $tenant['plan'], 'status' => $tenant['status'],
                    'trialEndsAt' => $tenant['trial_ends_at'],
                    'limits' => [
                        'maxSites' => (int)$tenant['max_sites'], 'maxAdmins' => (int)$tenant['max_admins'],
                        'maxUsers' => (int)$tenant['max_users']
                    ],
                    'usage' => [
                        'sites' => (int)$siteCount, 'admins' => (int)$adminCount, 'users' => (int)$userCount
                    ]
                ]);
            }
            
            if ($method === 'PUT') {
                $updates = [];
                $params = [];
                if (isset($input['name'])) { $updates[] = "name = ?"; $params[] = $input['name']; }
                
                if ($updates) {
                    $params[] = $tenantId;
                    Database::query("UPDATE tenants SET " . implode(', ', $updates) . " WHERE id = ?", $params);
                }
                jsonResponse(['success' => true]);
            }
            break;
            
        // ==================== SUPER ADMIN: TENANTS ====================
        case 'admin/tenants':
            $session = requireSuperAdmin();
            
            if ($method === 'GET') {
                $tenants = Database::fetchAll(
                    "SELECT t.*,
                            (SELECT COUNT(*) FROM admins WHERE tenant_id = t.id) as admin_count,
                            (SELECT COUNT(*) FROM sites WHERE tenant_id = t.id) as site_count
                     FROM tenants t ORDER BY t.created_at DESC"
                );
                
                jsonResponse(array_map(fn($t) => [
                    'id' => $t['id'], 'name' => $t['name'], 'slug' => $t['slug'],
                    'email' => $t['email'], 'plan' => $t['plan'], 'status' => $t['status'],
                    'adminCount' => (int)$t['admin_count'], 'siteCount' => (int)$t['site_count'],
                    'trialEndsAt' => $t['trial_ends_at'], 'createdAt' => $t['created_at']
                ], $tenants));
            }
            break;
            
        case (preg_match('#^admin/tenants/([^/]+)$#', $path, $m) ? true : false):
            $session = requireSuperAdmin();
            $targetTenantId = $m[1];
            
            if ($method === 'PUT') {
                $updates = [];
                $params = [];
                
                foreach (['name', 'plan', 'status', 'max_sites', 'max_admins', 'max_users'] as $field) {
                    $inputField = lcfirst(str_replace('_', '', ucwords($field, '_')));
                    if (isset($input[$inputField]) || isset($input[$field])) {
                        $updates[] = "`{$field}` = ?";
                        $params[] = $input[$inputField] ?? $input[$field];
                    }
                }
                
                if ($updates) {
                    $params[] = $targetTenantId;
                    Database::query("UPDATE tenants SET " . implode(', ', $updates) . " WHERE id = ?", $params);
                }
                
                jsonResponse(['success' => true]);
            }
            
            if ($method === 'DELETE') {
                // Supprimer le tenant et toutes ses données
                Database::query("DELETE FROM admins WHERE tenant_id = ?", [$targetTenantId]);
                Database::query("DELETE FROM sites WHERE tenant_id = ?", [$targetTenantId]);
                Database::query("DELETE FROM tenants WHERE id = ?", [$targetTenantId]);
                jsonResponse(['success' => true]);
            }
            break;
            
        // ==================== SETTINGS ====================
        case 'settings':
            $session = requireAuth();
            
            if ($method === 'GET') {
                $settings = Database::fetch("SELECT * FROM settings WHERE admin_id = ?", [$session['admin_id']]);
                jsonResponse($settings ?: ['theme' => 'dark', 'language' => 'fr', 'currency' => 'EUR', 'timezone' => 'Europe/Paris']);
            }
            
            if ($method === 'PUT' || $method === 'POST') {
                $existing = Database::fetch("SELECT admin_id FROM settings WHERE admin_id = ?", [$session['admin_id']]);
                
                if ($existing) {
                    $updates = [];
                    $params = [];
                    foreach (['theme', 'language', 'currency', 'timezone'] as $field) {
                        if (isset($input[$field])) { $updates[] = "`{$field}` = ?"; $params[] = $input[$field]; }
                    }
                    if ($updates) {
                        $params[] = $session['admin_id'];
                        Database::query("UPDATE settings SET " . implode(', ', $updates) . " WHERE admin_id = ?", $params);
                    }
                } else {
                    Database::insert('settings', [
                        'admin_id' => $session['admin_id'],
                        'theme' => $input['theme'] ?? 'dark',
                        'language' => $input['language'] ?? 'fr',
                        'currency' => $input['currency'] ?? 'EUR',
                        'timezone' => $input['timezone'] ?? 'Europe/Paris'
                    ]);
                }
                jsonResponse(['success' => true]);
            }
            break;
            
        // ==================== NOTIFICATIONS ====================
        case 'notifications':
            $session = requireAuth();
            $tenantId = $session['tenant_id'];
            
            $notifications = Database::fetchAll(
                "SELECT * FROM notifications WHERE (admin_id = ? OR admin_id IS NULL)" .
                ($tenantId ? " AND (tenant_id = ? OR tenant_id IS NULL)" : "") .
                " ORDER BY created_at DESC LIMIT 50",
                $tenantId ? [$session['admin_id'], $tenantId] : [$session['admin_id']]
            );
            
            jsonResponse(array_map(fn($n) => [
                'id' => $n['id'], 'type' => $n['type'], 'title' => $n['title'],
                'message' => $n['message'], 'isRead' => (bool)$n['is_read'], 'createdAt' => $n['created_at']
            ], $notifications));
            break;
            
        // ==================== 2FA SETUP ====================
        case 'security/2fa/setup':
            $session = requireAuth();
            
            if ($session['two_factor_enabled']) {
                jsonResponse(['error' => '2FA déjà activé'], 400);
            }
            
            // Générer un secret
            $secret = generateBase32Secret();
            
            // Sauvegarder temporairement (non activé)
            Database::query(
                "UPDATE admins SET two_factor_secret = ? WHERE id = ?",
                [$secret, $session['admin_id']]
            );
            
            // Générer l'URL otpauth pour le QR code
            $issuer = 'Noteso';
            $otpauthUrl = sprintf(
                'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30',
                urlencode($issuer),
                urlencode($session['email']),
                $secret,
                urlencode($issuer)
            );
            
            jsonResponse([
                'secret' => $secret,
                'otpauthUrl' => $otpauthUrl,
                'qrCode' => 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' . urlencode($otpauthUrl)
            ]);
            break;
            
        case 'security/2fa/verify':
            $session = requireAuth();
            
            $code = $input['code'] ?? '';
            if (!$code) jsonResponse(['error' => 'Code requis'], 400);
            
            $admin = Database::fetch("SELECT two_factor_secret FROM admins WHERE id = ?", [$session['admin_id']]);
            
            if (!$admin['two_factor_secret']) {
                jsonResponse(['error' => 'Configurez d\'abord le 2FA'], 400);
            }
            
            if (!verifyTOTP($admin['two_factor_secret'], $code)) {
                jsonResponse(['error' => 'Code invalide'], 400);
            }
            
            // Générer les codes de backup
            $backupCodes = [];
            for ($i = 0; $i < 10; $i++) {
                $backupCodes[] = strtoupper(bin2hex(random_bytes(4)));
            }
            
            // Activer le 2FA
            Database::query(
                "UPDATE admins SET two_factor_enabled = 1, two_factor_verified_at = NOW(), backup_codes = ? WHERE id = ?",
                [json_encode($backupCodes), $session['admin_id']]
            );
            
            logSecurityEvent('2fa_enabled', $session['admin_id'], $session['tenant_id'], []);
            
            jsonResponse([
                'success' => true,
                'backupCodes' => $backupCodes,
                'message' => '2FA activé avec succès'
            ]);
            break;
            
        case 'security/2fa/disable':
            $session = requireAuth();
            
            $password = $input['password'] ?? '';
            if (!$password) jsonResponse(['error' => 'Mot de passe requis'], 400);
            
            $admin = Database::fetch("SELECT password FROM admins WHERE id = ?", [$session['admin_id']]);
            
            if (!password_verify($password, $admin['password'])) {
                jsonResponse(['error' => 'Mot de passe incorrect'], 400);
            }
            
            Database::query(
                "UPDATE admins SET two_factor_enabled = 0, two_factor_secret = NULL, backup_codes = NULL WHERE id = ?",
                [$session['admin_id']]
            );
            
            logSecurityEvent('2fa_disabled', $session['admin_id'], $session['tenant_id'], []);
            
            jsonResponse(['success' => true, 'message' => '2FA désactivé']);
            break;
            
        case 'security/2fa/backup-codes':
            $session = requireAuth();
            
            $password = $input['password'] ?? '';
            if (!$password) jsonResponse(['error' => 'Mot de passe requis'], 400);
            
            $admin = Database::fetch("SELECT password, backup_codes FROM admins WHERE id = ?", [$session['admin_id']]);
            
            if (!password_verify($password, $admin['password'])) {
                jsonResponse(['error' => 'Mot de passe incorrect'], 400);
            }
            
            if ($input['regenerate'] ?? false) {
                $backupCodes = [];
                for ($i = 0; $i < 10; $i++) {
                    $backupCodes[] = strtoupper(bin2hex(random_bytes(4)));
                }
                Database::query(
                    "UPDATE admins SET backup_codes = ? WHERE id = ?",
                    [json_encode($backupCodes), $session['admin_id']]
                );
                logSecurityEvent('backup_codes_regenerated', $session['admin_id'], $session['tenant_id'], []);
            } else {
                $backupCodes = json_decode($admin['backup_codes'] ?? '[]', true);
            }
            
            jsonResponse(['backupCodes' => $backupCodes]);
            break;
            
        // ==================== PASSWORD ====================
        case 'security/password':
            $session = requireAuth();
            
            $currentPassword = $input['currentPassword'] ?? '';
            $newPassword = $input['newPassword'] ?? '';
            
            if (!$currentPassword || !$newPassword) {
                jsonResponse(['error' => 'Mots de passe requis'], 400);
            }
            
            if (strlen($newPassword) < 8) {
                jsonResponse(['error' => 'Le mot de passe doit contenir au moins 8 caractères'], 400);
            }
            
            $admin = Database::fetch("SELECT password FROM admins WHERE id = ?", [$session['admin_id']]);
            
            if (!password_verify($currentPassword, $admin['password'])) {
                jsonResponse(['error' => 'Mot de passe actuel incorrect'], 400);
            }
            
            $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);
            
            Database::query(
                "UPDATE admins SET password = ?, password_changed_at = NOW() WHERE id = ?",
                [$hashedPassword, $session['admin_id']]
            );
            
            // Invalider les autres sessions
            Database::query(
                "DELETE FROM sessions WHERE admin_id = ? AND token != ?",
                [$session['admin_id'], getAuthToken()]
            );
            
            logSecurityEvent('password_changed', $session['admin_id'], $session['tenant_id'], []);
            
            jsonResponse(['success' => true, 'message' => 'Mot de passe modifié']);
            break;
            
        // ==================== SESSIONS ====================
        case 'security/sessions':
            $session = requireAuth();
            
            if ($method === 'GET') {
                $sessions = Database::fetchAll(
                    "SELECT id, ip, user_agent, device_name, device_type, location, 
                            created_at, last_activity_at, token
                     FROM sessions 
                     WHERE admin_id = ? AND expires_at > NOW()
                     ORDER BY last_activity_at DESC",
                    [$session['admin_id']]
                );
                
                $currentToken = getAuthToken();
                
                jsonResponse(array_map(function($s) use ($currentToken) {
                    return [
                        'id' => $s['id'],
                        'ip' => $s['ip'],
                        'userAgent' => $s['user_agent'],
                        'deviceName' => $s['device_name'] ?? parseUserAgent($s['user_agent']),
                        'deviceType' => $s['device_type'] ?? 'unknown',
                        'location' => $s['location'],
                        'isCurrent' => $s['token'] === $currentToken,
                        'createdAt' => $s['created_at'],
                        'lastActivityAt' => $s['last_activity_at']
                    ];
                }, $sessions));
            }
            break;
            
        case 'security/sessions/revoke':
            $session = requireAuth();
            
            $sessionId = $input['sessionId'] ?? null;
            
            if ($sessionId === 'all') {
                // Révoquer toutes les sessions sauf la courante
                Database::query(
                    "DELETE FROM sessions WHERE admin_id = ? AND token != ?",
                    [$session['admin_id'], getAuthToken()]
                );
                logSecurityEvent('all_sessions_revoked', $session['admin_id'], $session['tenant_id'], []);
            } elseif ($sessionId) {
                // Révoquer une session spécifique
                Database::query(
                    "DELETE FROM sessions WHERE id = ? AND admin_id = ? AND token != ?",
                    [$sessionId, $session['admin_id'], getAuthToken()]
                );
                logSecurityEvent('session_revoked', $session['admin_id'], $session['tenant_id'], ['session_id' => $sessionId]);
            }
            
            jsonResponse(['success' => true]);
            break;
            
        // ==================== SECURITY LOGS ====================
        case 'security/logs':
            $session = requireAuth();
            
            $logs = Database::fetchAll(
                "SELECT * FROM security_events 
                 WHERE admin_id = ? 
                 ORDER BY created_at DESC 
                 LIMIT 50",
                [$session['admin_id']]
            );
            
            jsonResponse(array_map(fn($l) => [
                'id' => $l['id'],
                'type' => $l['event_type'],
                'severity' => $l['severity'],
                'ip' => $l['ip_address'],
                'userAgent' => $l['user_agent'],
                'location' => $l['location'],
                'details' => json_decode($l['details'] ?? '{}', true),
                'createdAt' => $l['created_at']
            ], $logs));
            break;
            
        // ==================== HEALTH ====================
        case 'health':
        case 'ping':
            try {
                Database::fetchColumn("SELECT 1");
                jsonResponse(['status' => 'ok', 'database' => 'connected', 'timestamp' => date('c')]);
            } catch (Exception $e) {
                jsonResponse(['status' => 'error', 'database' => 'disconnected', 'error' => $e->getMessage()], 500);
            }
            break;
            
        default:
            jsonResponse(['error' => 'Endpoint non trouvé: ' . $path], 404);
    }
    
} catch (PDOException $e) {
    jsonResponse(['error' => 'Erreur base de données: ' . $e->getMessage()], 500);
} catch (Exception $e) {
    jsonResponse(['error' => $e->getMessage()], 500);
}
