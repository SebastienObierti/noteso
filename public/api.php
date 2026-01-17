<?php
/**
 * NOTESO - API Backend MySQL 8
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
$configPaths = [
    ROOT_DIR . '/config/config.php',
    ROOT_DIR . '/config.php',
    BASE_DIR . '/config.php',
];

foreach ($configPaths as $configPath) {
    if (file_exists($configPath)) {
        $CONFIG = require $configPath;
        break;
    }
}

// Configuration MySQL
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

function jsonResponse($data, int $code = 200): void {
    ob_end_clean();
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function getAuthToken(): ?string {
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/Bearer\s+(.+)/i', $header, $m)) {
        return $m[1];
    }
    return $_GET['token'] ?? $_POST['token'] ?? null;
}

function validateSession(): ?array {
    $token = getAuthToken();
    if (!$token) return null;
    
    $session = Database::fetch(
        "SELECT s.*, a.email, a.first_name, a.last_name, a.role, a.permissions,
                a.two_factor_enabled, a.two_factor_secret
         FROM sessions s 
         JOIN admins a ON s.admin_id = a.id 
         WHERE s.token = ? AND s.expires_at > NOW()",
        [$token]
    );
    
    if ($session) {
        Database::query(
            "UPDATE sessions SET last_activity_at = NOW() WHERE id = ?",
            [$session['id']]
        );
        Database::query(
            "UPDATE admins SET last_seen_at = NOW() WHERE id = ?",
            [$session['admin_id']]
        );
    }
    
    return $session;
}

function requireAuth(): array {
    $session = validateSession();
    if (!$session) {
        jsonResponse(['error' => 'Non autorisé'], 401);
    }
    return $session;
}

function getClientIP(): string {
    return $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function logSecurityEvent(string $type, ?string $adminId, array $details = []): void {
    try {
        Database::insert('security_events', [
            'admin_id' => $adminId,
            'event_type' => $type,
            'severity' => $details['severity'] ?? 'info',
            'ip_address' => getClientIP(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'details' => json_encode($details),
            'created_at' => date('Y-m-d H:i:s')
        ]);
    } catch (Exception $e) {}
}

function verifyTOTP(string $secret, string $code, int $window = 1): bool {
    $code = preg_replace('/\s+/', '', $code); // Supprimer espaces
    if (strlen($code) !== 6 || !ctype_digit($code)) {
        return false;
    }
    
    $timestamp = floor(time() / 30);
    
    for ($i = -$window; $i <= $window; $i++) {
        $expectedCode = generateTOTPCode($secret, $timestamp + $i);
        if (hash_equals($expectedCode, $code)) {
            return true;
        }
    }
    
    return false;
}

function generateTOTPCode(string $secret, int $timestamp): string {
    // Décoder le secret Base32
    $secret = base32Decode($secret);
    
    // Packer le timestamp
    $time = pack('N*', 0, $timestamp);
    
    // HMAC-SHA1
    $hash = hash_hmac('sha1', $time, $secret, true);
    
    // Extraire le code
    $offset = ord(substr($hash, -1)) & 0x0F;
    $code = (
        ((ord($hash[$offset]) & 0x7F) << 24) |
        ((ord($hash[$offset + 1]) & 0xFF) << 16) |
        ((ord($hash[$offset + 2]) & 0xFF) << 8) |
        (ord($hash[$offset + 3]) & 0xFF)
    ) % 1000000;
    
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

// Router
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$path = preg_replace('#^.*/api\.php#', '', $path);
$path = trim($path, '/') ?: ($_GET['action'] ?? '');

$input = json_decode(file_get_contents('php://input'), true) ?? [];
$input = array_merge($_GET, $_POST, $input);

// Routes
try {
    // Normaliser le path (supprimer api/ prefix si présent)
    $path = preg_replace('#^api/?#', '', $path);
    
    switch ($path) {
        
        // ==================== AUTH ====================
        case 'login':
        case 'auth/login':
            if ($method !== 'POST') jsonResponse(['error' => 'Méthode non autorisée'], 405);
            
            $email = trim($input['email'] ?? '');
            $password = $input['password'] ?? '';
            
            if (!$email || !$password) {
                jsonResponse(['error' => 'Email et mot de passe requis'], 400);
            }
            
            $admin = Database::fetch(
                "SELECT * FROM admins WHERE email = ? AND is_active = 1",
                [$email]
            );
            
            if (!$admin || !password_verify($password, $admin['password'])) {
                Database::insert('login_attempts', [
                    'email' => $email,
                    'ip' => getClientIP(),
                    'success' => 0,
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null
                ]);
                logSecurityEvent('login_failed', null, ['email' => $email]);
                jsonResponse(['error' => 'Identifiants incorrects'], 401);
            }
            
            // Check 2FA
            if ($admin['two_factor_enabled'] && $admin['two_factor_secret']) {
                $totpCode = $input['totp_code'] ?? $input['code'] ?? null;
                
                if (!$totpCode) {
                    // Pas de code fourni, demander le 2FA
                    // Token de 30 caractères pour rester sous 64 avec le préfixe
                    $tempToken = bin2hex(random_bytes(15));
                    
                    // Stocker le token temporaire dans la session
                    Database::query(
                        "INSERT INTO sessions (id, admin_id, token, ip, user_agent, created_at, expires_at) 
                         VALUES (?, ?, ?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 5 MINUTE))",
                        [
                            generateId('2fa_'),
                            $admin['id'],
                            $tempToken,
                            getClientIP(),
                            $_SERVER['HTTP_USER_AGENT'] ?? null
                        ]
                    );
                    
                    jsonResponse([
                        'requires_2fa' => true,
                        'temp_token' => $tempToken,
                        'message' => 'Code 2FA requis'
                    ]);
                }
                
                // Vérifier le code TOTP
                if (!verifyTOTP($admin['two_factor_secret'], $totpCode)) {
                    logSecurityEvent('2fa_failed', $admin['id'], ['email' => $email]);
                    jsonResponse(['error' => 'Code 2FA invalide'], 401);
                }
            }
            
            // Create session
            $token = bin2hex(random_bytes(32));
            $sessionId = generateId('sess_');
            
            Database::insert('sessions', [
                'id' => $sessionId,
                'admin_id' => $admin['id'],
                'token' => $token,
                'ip' => getClientIP(),
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
                'created_at' => date('Y-m-d H:i:s'),
                'expires_at' => date('Y-m-d H:i:s', time() + SESSION_DURATION)
            ]);
            
            Database::query(
                "UPDATE admins SET last_login_at = NOW(), last_login_ip = ? WHERE id = ?",
                [getClientIP(), $admin['id']]
            );
            
            Database::insert('login_attempts', [
                'email' => $email,
                'ip' => getClientIP(),
                'success' => 1,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null
            ]);
            
            logSecurityEvent('login_success', $admin['id'], []);
            
            jsonResponse([
                'success' => true,
                'token' => $token,
                'admin' => [
                    'id' => $admin['id'],
                    'email' => $admin['email'],
                    'firstName' => $admin['first_name'],
                    'lastName' => $admin['last_name'],
                    'role' => $admin['role']
                ]
            ]);
            break;
            
        case 'logout':
        case 'auth/logout':
            $session = validateSession();
            if ($session) {
                Database::delete('sessions', 'token = ?', [getAuthToken()]);
                logSecurityEvent('logout', $session['admin_id'], []);
            }
            jsonResponse(['success' => true]);
            break;
            
        case 'me':
        case 'auth/me':
            $session = requireAuth();
            jsonResponse([
                'id' => $session['admin_id'],
                'email' => $session['email'],
                'firstName' => $session['first_name'],
                'lastName' => $session['last_name'],
                'role' => $session['role'],
                'twoFactorEnabled' => (bool)$session['two_factor_enabled']
            ]);
            break;
            
        // ==================== DASHBOARD ====================
        case 'dashboard':
        case 'stats':
            $session = requireAuth();
            $period = $input['period'] ?? '30d';
            
            $days = match($period) {
                '7d' => 7,
                '30d' => 30,
                '90d' => 90,
                '12m' => 365,
                default => 30
            };
            
            $startDate = date('Y-m-d', strtotime("-{$days} days"));
            
            // Stats globales
            $totalRevenue = Database::fetchColumn(
                "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status = 'completed' AND created_at >= ?",
                [$startDate]
            ) ?: 0;
            
            $totalUsers = Database::fetchColumn(
                "SELECT COUNT(*) FROM users WHERE created_at >= ?",
                [$startDate]
            ) ?: 0;
            
            $totalPayments = Database::fetchColumn(
                "SELECT COUNT(*) FROM payments WHERE status = 'completed' AND created_at >= ?",
                [$startDate]
            ) ?: 0;
            
            $activeSubscriptions = Database::fetchColumn(
                "SELECT COUNT(*) FROM subscriptions WHERE status = 'active'"
            ) ?: 0;
            
            // MRR
            $mrr = Database::fetchColumn(
                "SELECT COALESCE(SUM(amount), 0) FROM subscriptions WHERE status = 'active'"
            ) ?: 0;
            
            // Période précédente pour comparaison
            $prevStartDate = date('Y-m-d', strtotime("-" . ($days * 2) . " days"));
            $prevEndDate = $startDate;
            
            $prevRevenue = Database::fetchColumn(
                "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status = 'completed' AND created_at >= ? AND created_at < ?",
                [$prevStartDate, $prevEndDate]
            ) ?: 0;
            
            $prevUsers = Database::fetchColumn(
                "SELECT COUNT(*) FROM users WHERE created_at >= ? AND created_at < ?",
                [$prevStartDate, $prevEndDate]
            ) ?: 0;
            
            // Calcul des variations
            $revenueChange = $prevRevenue > 0 ? round((($totalRevenue - $prevRevenue) / $prevRevenue) * 100, 1) : 0;
            $usersChange = $prevUsers > 0 ? round((($totalUsers - $prevUsers) / $prevUsers) * 100, 1) : 0;
            
            // Données pour le graphique
            $chartData = Database::fetchAll(
                "SELECT DATE(created_at) as date, 
                        SUM(amount) as revenue,
                        COUNT(*) as payments
                 FROM payments 
                 WHERE status = 'completed' AND created_at >= ?
                 GROUP BY DATE(created_at)
                 ORDER BY date",
                [$startDate]
            );
            
            // Activités récentes
            $activities = Database::fetchAll(
                "SELECT a.*, s.name as site_name, s.color as site_color
                 FROM activities a
                 LEFT JOIN sites s ON a.site_id = s.id
                 ORDER BY a.created_at DESC
                 LIMIT 20"
            );
            
            jsonResponse([
                'stats' => [
                    'revenue' => [
                        'value' => (float)$totalRevenue,
                        'change' => $revenueChange,
                        'period' => $period
                    ],
                    'users' => [
                        'value' => (int)$totalUsers,
                        'change' => $usersChange,
                        'period' => $period
                    ],
                    'payments' => [
                        'value' => (int)$totalPayments,
                        'period' => $period
                    ],
                    'subscriptions' => [
                        'value' => (int)$activeSubscriptions,
                        'mrr' => (float)$mrr
                    ]
                ],
                'chart' => $chartData,
                'activities' => array_map(function($a) {
                    return [
                        'id' => $a['id'],
                        'type' => $a['type'],
                        'description' => $a['description'],
                        'siteName' => $a['site_name'],
                        'siteColor' => $a['site_color'],
                        'createdAt' => $a['created_at'],
                        'metadata' => json_decode($a['metadata'] ?? '{}', true)
                    ];
                }, $activities)
            ]);
            break;
            
        // ==================== SITES ====================
        case 'sites':
            $session = requireAuth();
            
            if ($method === 'GET') {
                $sites = Database::fetchAll(
                    "SELECT s.*,
                            (SELECT COUNT(*) FROM users WHERE site_id = s.id) as user_count,
                            (SELECT COUNT(*) FROM payments WHERE site_id = s.id AND status = 'completed') as payment_count,
                            (SELECT COALESCE(SUM(amount), 0) FROM payments WHERE site_id = s.id AND status = 'completed') as total_revenue
                     FROM sites s
                     ORDER BY s.name"
                );
                
                jsonResponse(array_map(function($s) {
                    return [
                        'id' => $s['id'],
                        'name' => $s['name'],
                        'url' => $s['url'],
                        'status' => $s['status'],
                        'color' => $s['color'],
                        'apiKey' => $s['api_key'],
                        'userCount' => (int)$s['user_count'],
                        'paymentCount' => (int)$s['payment_count'],
                        'totalRevenue' => (float)$s['total_revenue'],
                        'createdAt' => $s['created_at']
                    ];
                }, $sites));
            }
            
            if ($method === 'POST') {
                $name = trim($input['name'] ?? '');
                $url = trim($input['url'] ?? '');
                
                if (!$name || !$url) {
                    jsonResponse(['error' => 'Nom et URL requis'], 400);
                }
                
                $siteId = generateId('site_');
                $apiKey = 'sk_' . bin2hex(random_bytes(16));
                
                Database::insert('sites', [
                    'id' => $siteId,
                    'name' => $name,
                    'url' => $url,
                    'color' => $input['color'] ?? '#3b82f6',
                    'api_key' => $apiKey,
                    'status' => 'online'
                ]);
                
                jsonResponse([
                    'success' => true,
                    'site' => [
                        'id' => $siteId,
                        'name' => $name,
                        'url' => $url,
                        'apiKey' => $apiKey
                    ]
                ]);
            }
            break;
            
        case (preg_match('#^sites/([^/]+)$#', $path, $m) ? true : false):
            $session = requireAuth();
            $siteId = $m[1];
            
            if ($method === 'GET') {
                $site = Database::fetch("SELECT * FROM sites WHERE id = ?", [$siteId]);
                if (!$site) jsonResponse(['error' => 'Site non trouvé'], 404);
                jsonResponse($site);
            }
            
            if ($method === 'PUT') {
                $updates = [];
                $params = [];
                
                foreach (['name', 'url', 'color', 'status'] as $field) {
                    if (isset($input[$field])) {
                        $updates[] = "`{$field}` = ?";
                        $params[] = $input[$field];
                    }
                }
                
                if ($updates) {
                    $params[] = $siteId;
                    Database::query(
                        "UPDATE sites SET " . implode(', ', $updates) . " WHERE id = ?",
                        $params
                    );
                }
                
                jsonResponse(['success' => true]);
            }
            
            if ($method === 'DELETE') {
                Database::delete('sites', 'id = ?', [$siteId]);
                jsonResponse(['success' => true]);
            }
            break;
            
        // ==================== USERS ====================
        case 'users':
            $session = requireAuth();
            
            $page = max(1, (int)($input['page'] ?? 1));
            $limit = min(100, max(10, (int)($input['limit'] ?? 20)));
            $offset = ($page - 1) * $limit;
            $siteId = $input['site_id'] ?? null;
            $search = $input['search'] ?? '';
            
            $where = [];
            $params = [];
            
            if ($siteId) {
                $where[] = "u.site_id = ?";
                $params[] = $siteId;
            }
            
            if ($search) {
                $where[] = "(u.email LIKE ? OR u.name LIKE ?)";
                $params[] = "%{$search}%";
                $params[] = "%{$search}%";
            }
            
            $whereClause = $where ? 'WHERE ' . implode(' AND ', $where) : '';
            
            $total = Database::fetchColumn(
                "SELECT COUNT(*) FROM users u {$whereClause}",
                $params
            );
            
            $users = Database::fetchAll(
                "SELECT u.*, s.name as site_name, s.color as site_color
                 FROM users u
                 LEFT JOIN sites s ON u.site_id = s.id
                 {$whereClause}
                 ORDER BY u.created_at DESC
                 LIMIT {$limit} OFFSET {$offset}",
                $params
            );
            
            jsonResponse([
                'users' => array_map(function($u) {
                    return [
                        'id' => $u['id'],
                        'email' => $u['email'],
                        'name' => $u['name'],
                        'siteId' => $u['site_id'],
                        'siteName' => $u['site_name'],
                        'siteColor' => $u['site_color'],
                        'createdAt' => $u['created_at'],
                        'metadata' => json_decode($u['metadata'] ?? '{}', true)
                    ];
                }, $users),
                'pagination' => [
                    'page' => $page,
                    'limit' => $limit,
                    'total' => (int)$total,
                    'pages' => ceil($total / $limit)
                ]
            ]);
            break;
            
        // ==================== PAYMENTS ====================
        case 'payments':
            $session = requireAuth();
            
            $page = max(1, (int)($input['page'] ?? 1));
            $limit = min(100, max(10, (int)($input['limit'] ?? 20)));
            $offset = ($page - 1) * $limit;
            $siteId = $input['site_id'] ?? null;
            $status = $input['status'] ?? null;
            
            $where = [];
            $params = [];
            
            if ($siteId) {
                $where[] = "p.site_id = ?";
                $params[] = $siteId;
            }
            
            if ($status) {
                $where[] = "p.status = ?";
                $params[] = $status;
            }
            
            $whereClause = $where ? 'WHERE ' . implode(' AND ', $where) : '';
            
            $total = Database::fetchColumn(
                "SELECT COUNT(*) FROM payments p {$whereClause}",
                $params
            );
            
            $payments = Database::fetchAll(
                "SELECT p.*, s.name as site_name, s.color as site_color, u.email as user_email
                 FROM payments p
                 LEFT JOIN sites s ON p.site_id = s.id
                 LEFT JOIN users u ON p.user_id = u.id
                 {$whereClause}
                 ORDER BY p.created_at DESC
                 LIMIT {$limit} OFFSET {$offset}",
                $params
            );
            
            jsonResponse([
                'payments' => array_map(function($p) {
                    return [
                        'id' => $p['id'],
                        'amount' => (float)$p['amount'],
                        'currency' => $p['currency'],
                        'status' => $p['status'],
                        'provider' => $p['provider'],
                        'siteId' => $p['site_id'],
                        'siteName' => $p['site_name'],
                        'siteColor' => $p['site_color'],
                        'userEmail' => $p['user_email'],
                        'createdAt' => $p['created_at'],
                        'paidAt' => $p['paid_at']
                    ];
                }, $payments),
                'pagination' => [
                    'page' => $page,
                    'limit' => $limit,
                    'total' => (int)$total,
                    'pages' => ceil($total / $limit)
                ]
            ]);
            break;
            
        // ==================== SUBSCRIPTIONS ====================
        case 'subscriptions':
            $session = requireAuth();
            
            $page = max(1, (int)($input['page'] ?? 1));
            $limit = min(100, max(10, (int)($input['limit'] ?? 20)));
            $offset = ($page - 1) * $limit;
            $status = $input['status'] ?? null;
            
            $where = [];
            $params = [];
            
            if ($status) {
                $where[] = "sub.status = ?";
                $params[] = $status;
            }
            
            $whereClause = $where ? 'WHERE ' . implode(' AND ', $where) : '';
            
            $subscriptions = Database::fetchAll(
                "SELECT sub.*, s.name as site_name, s.color as site_color, u.email as user_email
                 FROM subscriptions sub
                 LEFT JOIN sites s ON sub.site_id = s.id
                 LEFT JOIN users u ON sub.user_id = u.id
                 {$whereClause}
                 ORDER BY sub.created_at DESC
                 LIMIT {$limit} OFFSET {$offset}",
                $params
            );
            
            jsonResponse([
                'subscriptions' => array_map(function($sub) {
                    return [
                        'id' => $sub['id'],
                        'plan' => $sub['plan'],
                        'status' => $sub['status'],
                        'amount' => (float)$sub['amount'],
                        'currency' => $sub['currency'],
                        'billingCycle' => $sub['billing_cycle'],
                        'siteId' => $sub['site_id'],
                        'siteName' => $sub['site_name'],
                        'siteColor' => $sub['site_color'],
                        'userEmail' => $sub['user_email'],
                        'currentPeriodEnd' => $sub['current_period_end'],
                        'createdAt' => $sub['created_at']
                    ];
                }, $subscriptions)
            ]);
            break;
            
        // ==================== NOTIFICATIONS ====================
        case 'notifications':
            $session = requireAuth();
            
            if ($method === 'GET') {
                $notifications = Database::fetchAll(
                    "SELECT * FROM notifications 
                     WHERE admin_id = ? OR admin_id IS NULL
                     ORDER BY created_at DESC
                     LIMIT 50",
                    [$session['admin_id']]
                );
                
                jsonResponse(array_map(function($n) {
                    return [
                        'id' => $n['id'],
                        'type' => $n['type'],
                        'title' => $n['title'],
                        'message' => $n['message'],
                        'isRead' => (bool)$n['is_read'],
                        'createdAt' => $n['created_at']
                    ];
                }, $notifications));
            }
            break;
            
        case 'notifications/read':
            $session = requireAuth();
            $notificationId = $input['id'] ?? null;
            
            if ($notificationId) {
                Database::query(
                    "UPDATE notifications SET is_read = 1, read_at = NOW() WHERE id = ?",
                    [$notificationId]
                );
            } else {
                Database::query(
                    "UPDATE notifications SET is_read = 1, read_at = NOW() WHERE admin_id = ? OR admin_id IS NULL",
                    [$session['admin_id']]
                );
            }
            
            jsonResponse(['success' => true]);
            break;
            
        // ==================== SETTINGS ====================
        case 'settings':
            $session = requireAuth();
            
            if ($method === 'GET') {
                $settings = Database::fetch(
                    "SELECT * FROM settings WHERE admin_id = ?",
                    [$session['admin_id']]
                );
                
                jsonResponse($settings ?: [
                    'theme' => 'dark',
                    'language' => 'fr',
                    'currency' => 'EUR',
                    'timezone' => 'Europe/Paris'
                ]);
            }
            
            if ($method === 'PUT' || $method === 'POST') {
                $existing = Database::fetch(
                    "SELECT admin_id FROM settings WHERE admin_id = ?",
                    [$session['admin_id']]
                );
                
                if ($existing) {
                    $updates = [];
                    $params = [];
                    
                    foreach (['theme', 'language', 'currency', 'timezone'] as $field) {
                        if (isset($input[$field])) {
                            $updates[] = "`{$field}` = ?";
                            $params[] = $input[$field];
                        }
                    }
                    
                    if ($updates) {
                        $params[] = $session['admin_id'];
                        Database::query(
                            "UPDATE settings SET " . implode(', ', $updates) . " WHERE admin_id = ?",
                            $params
                        );
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
            
        // ==================== ADMINS ====================
        case 'admins':
            $session = requireAuth();
            
            if ($session['role'] !== 'super_admin') {
                jsonResponse(['error' => 'Accès refusé'], 403);
            }
            
            if ($method === 'GET') {
                $admins = Database::fetchAll(
                    "SELECT id, email, first_name, last_name, role, is_active, 
                            two_factor_enabled, created_at, last_login_at
                     FROM admins
                     ORDER BY created_at DESC"
                );
                
                jsonResponse(array_map(function($a) {
                    return [
                        'id' => $a['id'],
                        'email' => $a['email'],
                        'firstName' => $a['first_name'],
                        'lastName' => $a['last_name'],
                        'role' => $a['role'],
                        'isActive' => (bool)$a['is_active'],
                        'twoFactorEnabled' => (bool)$a['two_factor_enabled'],
                        'createdAt' => $a['created_at'],
                        'lastLoginAt' => $a['last_login_at']
                    ];
                }, $admins));
            }
            
            if ($method === 'POST') {
                $email = trim($input['email'] ?? '');
                $password = $input['password'] ?? '';
                $firstName = trim($input['firstName'] ?? '');
                $lastName = trim($input['lastName'] ?? '');
                $role = $input['role'] ?? 'admin';
                
                if (!$email || !$password || !$firstName || !$lastName) {
                    jsonResponse(['error' => 'Tous les champs sont requis'], 400);
                }
                
                $existing = Database::fetch("SELECT id FROM admins WHERE email = ?", [$email]);
                if ($existing) {
                    jsonResponse(['error' => 'Cet email existe déjà'], 400);
                }
                
                $adminId = generateId('admin_');
                $hashedPassword = password_hash($password, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);
                
                Database::insert('admins', [
                    'id' => $adminId,
                    'email' => $email,
                    'password' => $hashedPassword,
                    'first_name' => $firstName,
                    'last_name' => $lastName,
                    'role' => $role,
                    'is_active' => 1
                ]);
                
                jsonResponse([
                    'success' => true,
                    'admin' => [
                        'id' => $adminId,
                        'email' => $email,
                        'firstName' => $firstName,
                        'lastName' => $lastName,
                        'role' => $role
                    ]
                ]);
            }
            break;
            
        // ==================== SECURITY ====================
        case 'security/events':
            $session = requireAuth();
            
            $events = Database::fetchAll(
                "SELECT * FROM security_events 
                 ORDER BY created_at DESC 
                 LIMIT 100"
            );
            
            jsonResponse(array_map(function($e) {
                return [
                    'id' => $e['id'],
                    'type' => $e['event_type'],
                    'severity' => $e['severity'],
                    'ipAddress' => $e['ip_address'],
                    'details' => json_decode($e['details'] ?? '{}', true),
                    'createdAt' => $e['created_at']
                ];
            }, $events));
            break;
            
        case 'security/sessions':
            $session = requireAuth();
            
            $sessions = Database::fetchAll(
                "SELECT * FROM sessions 
                 WHERE admin_id = ? AND expires_at > NOW()
                 ORDER BY created_at DESC",
                [$session['admin_id']]
            );
            
            jsonResponse(array_map(function($s) use ($session) {
                return [
                    'id' => $s['id'],
                    'ip' => $s['ip'],
                    'userAgent' => $s['user_agent'],
                    'deviceName' => $s['device_name'],
                    'isCurrent' => $s['token'] === getAuthToken(),
                    'createdAt' => $s['created_at'],
                    'lastActivityAt' => $s['last_activity_at']
                ];
            }, $sessions));
            break;
            
        // ==================== HEALTH CHECK ====================
        case 'health':
        case 'ping':
            try {
                Database::fetchColumn("SELECT 1");
                jsonResponse([
                    'status' => 'ok',
                    'database' => 'connected',
                    'timestamp' => date('c')
                ]);
            } catch (Exception $e) {
                jsonResponse([
                    'status' => 'error',
                    'database' => 'disconnected',
                    'error' => $e->getMessage()
                ], 500);
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
