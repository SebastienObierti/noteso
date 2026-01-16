<?php
/**
 * NOTESO - API Backend MySQL 8
 * Dashboard Multi-Sites complet en PHP pur + PDO
 * v1.2 - Avec stats journalières
 */

// Empêcher l'affichage d'erreurs dans la sortie JSON
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

// Charger les classes
require_once __DIR__ . '/Database.php';
if (file_exists(__DIR__ . '/TOTP.php')) require_once __DIR__ . '/TOTP.php';
if (file_exists(__DIR__ . '/RateLimiter.php')) require_once __DIR__ . '/RateLimiter.php';
if (file_exists(__DIR__ . '/WebhookValidator.php')) require_once __DIR__ . '/WebhookValidator.php';

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

// Constantes de configuration
define('SESSION_DURATION', $CONFIG['security']['session_duration'] ?? 604800);
define('MAX_LOGIN_ATTEMPTS', $CONFIG['security']['max_login_attempts'] ?? 5);
define('LOCKOUT_DURATION', $CONFIG['security']['lockout_duration'] ?? 900);
define('MIN_PASSWORD_LENGTH', $CONFIG['security']['min_password_length'] ?? 8);
define('REQUIRE_UPPERCASE', $CONFIG['security']['require_uppercase'] ?? true);
define('REQUIRE_LOWERCASE', $CONFIG['security']['require_lowercase'] ?? true);
define('REQUIRE_NUMBER', $CONFIG['security']['require_number'] ?? true);
define('REQUIRE_SPECIAL', $CONFIG['security']['require_special'] ?? false);
define('BCRYPT_COST', $CONFIG['security']['bcrypt_cost'] ?? 12);
define('RATE_LIMITING_ENABLED', $CONFIG['security']['rate_limiting'] ?? true);

date_default_timezone_set($CONFIG['app']['timezone'] ?? 'Europe/Paris');

// ============== CORS ==============
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key, X-HTTP-Method-Override');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// ============== HELPERS ==============

function response(mixed $data, int $code = 200): never {
    ob_end_clean();
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function error(string $message, int $code = 400): never {
    response(['error' => $message], $code);
}

function getInput(): array {
    return json_decode(file_get_contents('php://input'), true) ?: [];
}

function getClientIP(): string {
    return $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

if (!function_exists('addNotification')) {
    function addNotification(string $type, string $title, ?string $message = null, ?string $adminId = null): void {
        Database::insert('notifications', [
            'id' => generateId('notif'),
            'admin_id' => $adminId,
            'type' => $type,
            'title' => $title,
            'message' => $message,
            'is_read' => 0,
            'created_at' => date('Y-m-d H:i:s')
        ]);
    }
}

/**
 * Génère un ID unique préfixé
 */
if (!function_exists('generateId')) {
    function generateId(string $prefix = ''): string {
        $id = base_convert(time(), 10, 36) . bin2hex(random_bytes(4));
        return $prefix ? "{$prefix}_{$id}" : $id;
    }
}

/**
 * Log un événement de sécurité
 */
if (!function_exists('logSecurityEvent')) {
    function logSecurityEvent(string $type, string $details, ?string $adminId = null, ?string $ip = null): void {
        try {
            Database::insert('security_events', [
                'admin_id' => $adminId,
                'event_type' => $type,
                'severity' => 'info',
                'ip_address' => $ip ?? ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown'),
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
                'details' => json_encode(['message' => $details]),
                'created_at' => date('Y-m-d H:i:s')
            ]);
        } catch (Exception $e) {
            error_log('Security log failed: ' . $e->getMessage());
        }
    }
}

/**
 * Log une activité
 */
if (!function_exists('logActivity')) {
    function logActivity(string $siteId, ?string $userId, string $type, ?string $description = null, ?string $details = null): void {
        try {
            Database::insert('activities', [
                'id' => generateId('act'),
                'site_id' => $siteId,
                'user_id' => $userId,
                'type' => $type,
                'description' => $description,
                'metadata' => $details ? json_encode(['details' => $details]) : null,
                'created_at' => date('Y-m-d H:i:s')
            ]);
        } catch (Exception $e) {
            error_log('Activity log failed: ' . $e->getMessage());
        }
    }
}

// ============== AUTH ==============

function getAuthAdmin(): ?array {
    $authHeader = '';
    foreach (getallheaders() as $key => $value) {
        if (strtolower($key) === 'authorization') {
            $authHeader = $value;
            break;
        }
    }
    
    $token = str_replace('Bearer ', '', $authHeader);
    if (!$token) return null;
    
    $session = Database::fetch(
        "SELECT s.*, a.* FROM sessions s 
         JOIN admins a ON s.admin_id = a.id 
         WHERE s.token = ? AND s.expires_at > NOW()",
        [$token]
    );
    
    if (!$session) return null;
    
    return [
        'id' => $session['admin_id'],
        'email' => $session['email'],
        'password' => $session['password'],
        'firstName' => $session['first_name'],
        'lastName' => $session['last_name'],
        'role' => $session['role'],
        'permissions' => json_decode($session['permissions'] ?? '[]', true),
        'createdAt' => $session['created_at'],
        'lastLoginAt' => $session['last_login_at'],
        'lastLoginIP' => $session['last_login_ip']
    ];
}

function requireAuth(?string $role = null): array {
    $admin = getAuthAdmin();
    if (!$admin) {
        error('Non autorisé', 401);
    }
    if ($role && $admin['role'] !== 'super_admin' && $admin['role'] !== $role) {
        error('Permissions insuffisantes', 403);
    }
    return $admin;
}

// ============== RATE LIMITING ==============

if (RATE_LIMITING_ENABLED && class_exists('RateLimiter')) {
    $clientIP = getClientIP();
    $requestUri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
    $authHeader = '';
    foreach (getallheaders() as $key => $value) {
        if (strtolower($key) === 'authorization') {
            $authHeader = $value;
            break;
        }
    }
    $token = str_replace('Bearer ', '', $authHeader);
    
    RateLimiter::enforce($clientIP, $requestUri, $token ?: null);
}

// ============== ROUTING ==============

$method = $_SERVER['REQUEST_METHOD'];

$input = json_decode(file_get_contents('php://input'), true) ?: [];
if ($method === 'POST') {
    $override = $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] ?? $input['_method'] ?? $_POST['_method'] ?? null;
    if ($override && in_array(strtoupper($override), ['PUT', 'DELETE', 'PATCH'])) {
        $method = strtoupper($override);
    }
}

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$scriptName = dirname($_SERVER['SCRIPT_NAME']);
if ($scriptName !== '/' && $scriptName !== '\\') {
    $uri = preg_replace('#^' . preg_quote($scriptName, '#') . '#', '', $uri);
}
$uri = preg_replace('#^/api\.php#', '', $uri);
$uri = preg_replace('#^/api(?=/|$)#', '', $uri);
$uri = '/' . trim($uri, '/');

if ($uri === '/' || $uri === '') {
    response(['status' => 'ok', 'message' => 'API Noteso MySQL', 'version' => '2.0']);
}

function matchRoute(string $pattern, string $uri): array|false {
    $pattern = preg_replace('#\{(\w+)\}#', '(?P<$1>[^/]+)', $pattern);
    if (preg_match('#^' . $pattern . '$#', $uri, $matches)) {
        return array_filter($matches, 'is_string', ARRAY_FILTER_USE_KEY);
    }
    return false;
}

// ============== AUTH ENDPOINTS ==============

if ($method === 'POST' && $uri === '/auth/login') {
    $input = getInput();
    $email = $input['email'] ?? '';
    $password = $input['password'] ?? '';
    
    if (!$email || !$password) {
        error('Email et mot de passe requis');
    }
    
    $admin = Database::fetch("SELECT * FROM admins WHERE email = ?", [$email]);
    
    if (!$admin || !password_verify($password, $admin['password'])) {
        logSecurityEvent('login_failed', 'Tentative de connexion échouée: ' . $email, null, getClientIP());
        error('Identifiants incorrects', 401);
    }
    
    // Créer session
    $token = bin2hex(random_bytes(32));
    $sessionId = generateId('sess');
    
    Database::insert('sessions', [
        'id' => $sessionId,
        'admin_id' => $admin['id'],
        'token' => $token,
        'ip' => getClientIP(),
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
        'created_at' => date('Y-m-d H:i:s'),
        'expires_at' => date('Y-m-d H:i:s', time() + SESSION_DURATION)
    ]);
    
    Database::update('admins', [
        'last_login_at' => date('Y-m-d H:i:s'),
        'last_login_ip' => getClientIP()
    ], ['id' => $admin['id']]);
    
    logSecurityEvent('login', 'Connexion réussie', $admin['id'], getClientIP());
    
    response([
        'token' => $token,
        'admin' => [
            'id' => $admin['id'],
            'email' => $admin['email'],
            'firstName' => $admin['first_name'],
            'lastName' => $admin['last_name'],
            'role' => $admin['role']
        ]
    ]);
}

if ($method === 'POST' && $uri === '/auth/logout') {
    $authHeader = '';
    foreach (getallheaders() as $key => $value) {
        if (strtolower($key) === 'authorization') {
            $authHeader = $value;
            break;
        }
    }
    $token = str_replace('Bearer ', '', $authHeader);
    
    if ($token) {
        Database::query("DELETE FROM sessions WHERE token = ?", [$token]);
    }
    
    response(['success' => true]);
}

if ($method === 'GET' && $uri === '/auth/me') {
    $admin = requireAuth();
    response([
        'id' => $admin['id'],
        'email' => $admin['email'],
        'firstName' => $admin['firstName'],
        'lastName' => $admin['lastName'],
        'role' => $admin['role'],
        'permissions' => $admin['permissions']
    ]);
}

// ============== SECURITY EVENTS ==============

if ($method === 'GET' && $uri === '/security/events') {
    $admin = requireAuth();
    $limit = (int)($_GET['limit'] ?? 50);
    $severity = $_GET['severity'] ?? null;
    
    $where = "admin_id = ?";
    $params = [$admin['id']];
    
    if ($severity) {
        $where .= " AND severity = ?";
        $params[] = $severity;
    }
    
    $events = Database::fetchAll(
        "SELECT * FROM security_events WHERE $where ORDER BY created_at DESC LIMIT ?",
        array_merge($params, [$limit])
    );
    
    $result = array_map(fn($e) => [
        'id' => $e['id'],
        'type' => $e['event_type'],
        'severity' => $e['severity'],
        'ip' => $e['ip_address'],
        'location' => $e['location'],
        'details' => json_decode($e['details'] ?? '{}', true),
        'createdAt' => $e['created_at']
    ], $events);
    
    response($result);
}

// ============== DASHBOARD ==============

if ($method === 'GET' && $uri === '/dashboard/overview') {
    $now = time();
    $today = date('Y-m-d');
    $yesterday = date('Y-m-d', strtotime('-1 day'));
    $thisMonth = date('Y-m-01');
    $lastMonthStart = date('Y-m-01', strtotime('-1 month'));
    $lastMonthEnd = date('Y-m-t', strtotime('-1 month'));
    
    // Stats globales
    $totalUsers = Database::count('users');
    $totalSites = Database::count('sites');
    $activeSites = Database::count('sites', ['status' => 'online']);
    
    // ========== STATS DU JOUR ==========
    $todayUsers = Database::fetchColumn(
        "SELECT COUNT(*) FROM users WHERE DATE(created_at) = ?",
        [$today]
    ) ?: 0;
    
    $todayPayments = Database::fetchColumn(
        "SELECT COUNT(*) FROM payments WHERE status = 'completed' AND DATE(created_at) = ?",
        [$today]
    ) ?: 0;
    
    $todayRevenue = Database::fetchColumn(
        "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status = 'completed' AND DATE(created_at) = ?",
        [$today]
    ) ?: 0;
    
    // Stats d'hier pour comparaison
    $yesterdayUsers = Database::fetchColumn(
        "SELECT COUNT(*) FROM users WHERE DATE(created_at) = ?",
        [$yesterday]
    ) ?: 0;
    
    $yesterdayPayments = Database::fetchColumn(
        "SELECT COUNT(*) FROM payments WHERE status = 'completed' AND DATE(created_at) = ?",
        [$yesterday]
    ) ?: 0;
    
    $yesterdayRevenue = Database::fetchColumn(
        "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status = 'completed' AND DATE(created_at) = ?",
        [$yesterday]
    ) ?: 0;
    
    // ========== STATS DU MOIS ==========
    $totalRevenue = Database::fetchColumn(
        "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status = 'completed'"
    ) ?: 0;
    
    $thisMonthRevenue = Database::fetchColumn(
        "SELECT COALESCE(SUM(amount), 0) FROM payments 
         WHERE status = 'completed' AND created_at >= ?",
        [$thisMonth]
    ) ?: 0;
    
    $lastMonthRevenue = Database::fetchColumn(
        "SELECT COALESCE(SUM(amount), 0) FROM payments 
         WHERE status = 'completed' AND created_at >= ? AND created_at <= ?",
        [$lastMonthStart, $lastMonthEnd . ' 23:59:59']
    ) ?: 0;
    
    $thisMonthPayments = Database::fetchColumn(
        "SELECT COUNT(*) FROM payments WHERE status = 'completed' AND created_at >= ?",
        [$thisMonth]
    );
    
    $lastMonthPayments = Database::fetchColumn(
        "SELECT COUNT(*) FROM payments 
         WHERE status = 'completed' AND created_at >= ? AND created_at <= ?",
        [$lastMonthStart, $lastMonthEnd . ' 23:59:59']
    );
    
    $thisMonthUsers = Database::fetchColumn(
        "SELECT COUNT(*) FROM users WHERE created_at >= ?",
        [$thisMonth]
    );
    
    $lastMonthUsers = Database::fetchColumn(
        "SELECT COUNT(*) FROM users WHERE created_at >= ? AND created_at <= ?",
        [$lastMonthStart, $lastMonthEnd . ' 23:59:59']
    );
    
    // MRR
    $mrr = Database::fetchColumn(
        "SELECT COALESCE(SUM(CASE WHEN interval_type = 'year' THEN amount/12 ELSE amount END), 0) 
         FROM subscriptions WHERE status = 'active'"
    ) ?: 0;
    
    $activeSubscriptions = Database::count('subscriptions', ['status' => 'active']);
    
    // Fonction de calcul des tendances
    $calcTrend = fn($current, $previous) => $previous > 0 ? round(($current - $previous) / $previous * 100, 1) : ($current > 0 ? 100 : 0);
    
    response([
        // Stats globales
        'totalUsers' => $totalUsers,
        'totalSites' => $totalSites,
        'activeSites' => $activeSites,
        'totalRevenue' => round($totalRevenue, 2),
        
        // Stats du JOUR (NOUVEAU)
        'todayUsers' => (int)$todayUsers,
        'todayPayments' => (int)$todayPayments,
        'todayRevenue' => round((float)$todayRevenue, 2),
        'todayUsersTrend' => $calcTrend($todayUsers, $yesterdayUsers),
        'todayPaymentsTrend' => $calcTrend($todayPayments, $yesterdayPayments),
        'todayRevenueTrend' => $calcTrend($todayRevenue, $yesterdayRevenue),
        
        // Stats du MOIS
        'monthlyUsers' => (int)$thisMonthUsers,
        'monthlyPayments' => (int)$thisMonthPayments,
        'monthlyRevenue' => round((float)$thisMonthRevenue, 2),
        'usersTrend' => $calcTrend($thisMonthUsers, $lastMonthUsers),
        'paymentsTrend' => $calcTrend($thisMonthPayments, $lastMonthPayments),
        'revenueTrend' => $calcTrend($thisMonthRevenue, $lastMonthRevenue),
        
        // MRR / ARR
        'mrr' => round($mrr, 2),
        'arr' => round($mrr * 12, 2),
        'activeSubscriptions' => $activeSubscriptions,
        'conversionRate' => $totalUsers > 0 ? round($activeSubscriptions / $totalUsers * 100, 1) : 0
    ]);
}

// ============== SITES ==============

if ($method === 'GET' && $uri === '/sites') {
    $sites = Database::fetchAll("SELECT * FROM sites ORDER BY created_at DESC");
    
    $result = [];
    foreach ($sites as $site) {
        $stats = Database::fetch(
            "SELECT 
                (SELECT COUNT(*) FROM users WHERE site_id = ?) as users,
                (SELECT COUNT(*) FROM payments WHERE site_id = ? AND status = 'completed') as payments,
                (SELECT COALESCE(SUM(amount), 0) FROM payments WHERE site_id = ? AND status = 'completed') as revenue",
            [$site['id'], $site['id'], $site['id']]
        );
        
        $uptime = Database::fetchColumn(
            "SELECT ROUND(AVG(CASE WHEN value > 0 THEN 100 ELSE 0 END), 1)
             FROM monitoring WHERE site_id = ? AND metric_type = 'uptime' 
             AND recorded_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)",
            [$site['id']]
        ) ?: 100;
        
        $avgResponseTime = Database::fetchColumn(
            "SELECT ROUND(AVG(value))
             FROM monitoring WHERE site_id = ? AND metric_type = 'response_time'
             AND recorded_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)",
            [$site['id']]
        ) ?: 0;
        
        $result[] = [
            'id' => $site['id'],
            'name' => $site['name'],
            'url' => $site['url'],
            'status' => $site['status'],
            'color' => $site['color'],
            'createdAt' => $site['created_at'],
            'apiKey' => $site['api_key'],
            'settings' => json_decode($site['settings'] ?? '{}', true),
            'stats' => [
                'users' => (int)$stats['users'],
                'payments' => (int)$stats['payments'],
                'revenue' => round((float)$stats['revenue'], 2),
                'uptime' => (float)$uptime,
                'avgResponseTime' => (int)$avgResponseTime
            ]
        ];
    }
    
    response($result);
}

if ($method === 'GET' && ($params = matchRoute('/sites/{id}', $uri))) {
    $site = Database::find('sites', $params['id']);
    if (!$site) error('Site non trouvé', 404);
    
    $stats = Database::fetch(
        "SELECT 
            (SELECT COUNT(*) FROM users WHERE site_id = ?) as users,
            (SELECT COUNT(*) FROM payments WHERE site_id = ? AND status = 'completed') as payments,
            (SELECT COALESCE(SUM(amount), 0) FROM payments WHERE site_id = ? AND status = 'completed') as revenue",
        [$site['id'], $site['id'], $site['id']]
    );
    
    response([
        'id' => $site['id'],
        'name' => $site['name'],
        'url' => $site['url'],
        'status' => $site['status'],
        'color' => $site['color'],
        'createdAt' => $site['created_at'],
        'apiKey' => $site['api_key'],
        'webhookSecret' => $site['webhook_secret'],
        'settings' => json_decode($site['settings'] ?? '{}', true),
        'stats' => [
            'users' => (int)$stats['users'],
            'payments' => (int)$stats['payments'],
            'revenue' => round((float)$stats['revenue'], 2)
        ]
    ]);
}

if ($method === 'POST' && $uri === '/sites') {
    $input = getInput();
    
    if (empty($input['name']) || empty($input['url'])) {
        error('Nom et URL requis');
    }
    
    $id = generateId('site');
    $apiKey = 'ek_' . bin2hex(random_bytes(16));
    $webhookSecret = 'whsec_' . bin2hex(random_bytes(16));
    
    Database::insert('sites', [
        'id' => $id,
        'name' => $input['name'],
        'url' => $input['url'],
        'status' => 'online',
        'color' => $input['color'] ?? '#3b82f6',
        'api_key' => $apiKey,
        'webhook_secret' => $webhookSecret,
        'settings' => json_encode($input['settings'] ?? []),
        'created_at' => date('Y-m-d H:i:s')
    ]);
    
    addNotification('success', 'Site ajouté', $input['name'] . ' a été ajouté avec succès');
    
    response(['id' => $id, 'apiKey' => $apiKey, 'webhookSecret' => $webhookSecret], 201);
}

if ($method === 'PUT' && ($params = matchRoute('/sites/{id}', $uri))) {
    $site = Database::find('sites', $params['id']);
    if (!$site) error('Site non trouvé', 404);
    
    $input = getInput();
    $updateData = [];
    
    if (isset($input['name'])) $updateData['name'] = $input['name'];
    if (isset($input['url'])) $updateData['url'] = $input['url'];
    if (isset($input['status'])) $updateData['status'] = $input['status'];
    if (isset($input['color'])) $updateData['color'] = $input['color'];
    if (isset($input['settings'])) $updateData['settings'] = json_encode($input['settings']);
    
    if (!empty($updateData)) {
        Database::update('sites', $updateData, ['id' => $params['id']]);
    }
    
    response(['success' => true]);
}

if ($method === 'DELETE' && ($params = matchRoute('/sites/{id}', $uri))) {
    $site = Database::find('sites', $params['id']);
    if (!$site) error('Site non trouvé', 404);
    
    Database::delete('sites', ['id' => $params['id']]);
    addNotification('info', 'Site supprimé', $site['name'] . ' a été supprimé');
    
    response(['success' => true]);
}

// ============== USERS ==============

if ($method === 'GET' && $uri === '/users') {
    $siteId = $_GET['siteId'] ?? null;
    $status = $_GET['status'] ?? null;
    $plan = $_GET['plan'] ?? null;
    $search = $_GET['search'] ?? null;
    $limit = (int)($_GET['limit'] ?? 50);
    $offset = (int)($_GET['offset'] ?? 0);
    
    $where = [];
    $params = [];
    
    if ($siteId) {
        $where[] = "u.site_id = ?";
        $params[] = $siteId;
    }
    if ($search) {
        $where[] = "(u.email LIKE ? OR u.name LIKE ?)";
        $params[] = "%$search%";
        $params[] = "%$search%";
    }
    
    $whereClause = !empty($where) ? 'WHERE ' . implode(' AND ', $where) : '';
    
    $total = Database::fetchColumn("SELECT COUNT(*) FROM users u $whereClause", $params);
    
    $users = Database::fetchAll(
        "SELECT u.*, s.name as site_name FROM users u 
         LEFT JOIN sites s ON u.site_id = s.id
         $whereClause ORDER BY u.created_at DESC LIMIT ? OFFSET ?",
        array_merge($params, [$limit, $offset])
    );
    
    $result = array_map(function($u) {
        $metadata = json_decode($u['metadata'] ?? '{}', true);
        return [
            'id' => $u['id'],
            'siteId' => $u['site_id'],
            'siteName' => $u['site_name'],
            'email' => $u['email'],
            'name' => $u['name'],
            'plan' => $metadata['plan'] ?? 'free',
            'status' => $metadata['status'] ?? 'active',
            'createdAt' => $u['created_at']
        ];
    }, $users);
    
    response(['users' => $result, 'total' => $total, 'limit' => $limit, 'offset' => $offset]);
}

if ($method === 'GET' && ($params = matchRoute('/users/{id}', $uri))) {
    $user = Database::fetch(
        "SELECT u.*, s.name as site_name FROM users u 
         LEFT JOIN sites s ON u.site_id = s.id WHERE u.id = ?",
        [$params['id']]
    );
    if (!$user) error('Utilisateur non trouvé', 404);
    
    $payments = Database::fetchAll(
        "SELECT * FROM payments WHERE user_id = ? ORDER BY created_at DESC",
        [$params['id']]
    );
    
    $subscription = Database::fetch(
        "SELECT * FROM subscriptions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
        [$params['id']]
    );
    
    response([
        'id' => $user['id'],
        'siteId' => $user['site_id'],
        'siteName' => $user['site_name'],
        'email' => $user['email'],
        'name' => $user['name'],
        'metadata' => json_decode($user['metadata'] ?? '{}', true),
        'createdAt' => $user['created_at'],
        'payments' => array_map(fn($p) => [
            'id' => $p['id'],
            'amount' => $p['amount'],
            'currency' => $p['currency'],
            'status' => $p['status'],
            'createdAt' => $p['created_at']
        ], $payments),
        'subscription' => $subscription ? [
            'id' => $subscription['id'],
            'plan' => $subscription['plan'],
            'status' => $subscription['status'],
            'amount' => $subscription['amount']
        ] : null
    ]);
}

if ($method === 'POST' && $uri === '/users') {
    $input = getInput();
    
    if (empty($input['siteId']) || empty($input['email'])) {
        error('siteId et email requis');
    }
    
    $id = generateId('user');
    
    Database::insert('users', [
        'id' => $id,
        'site_id' => $input['siteId'],
        'email' => $input['email'],
        'name' => trim(($input['firstName'] ?? '') . ' ' . ($input['lastName'] ?? '')),
        'external_id' => $input['externalId'] ?? null,
        'metadata' => json_encode([
            'source' => 'api',
            'plan' => $input['plan'] ?? 'free',
            'status' => 'active'
        ]),
        'created_at' => date('Y-m-d H:i:s')
    ]);
    
    logActivity($input['siteId'], $id, 'signup', 'Nouvelle inscription: ' . $input['email']);
    
    $user = Database::find('users', $id);
    
    response([
        'id' => $user['id'],
        'siteId' => $user['site_id'],
        'email' => $user['email'],
        'name' => $user['name'],
        'createdAt' => $user['created_at']
    ], 201);
}

if ($method === 'DELETE' && ($params = matchRoute('/users/{id}', $uri))) {
    $user = Database::find('users', $params['id']);
    if (!$user) error('Utilisateur non trouvé', 404);
    
    Database::delete('users', ['id' => $params['id']]);
    
    response(['success' => true]);
}

// ============== PAYMENTS ==============

if ($method === 'GET' && $uri === '/payments') {
    $siteId = $_GET['siteId'] ?? null;
    $userId = $_GET['userId'] ?? null;
    $status = $_GET['status'] ?? null;
    $limit = (int)($_GET['limit'] ?? 50);
    $offset = (int)($_GET['offset'] ?? 0);
    
    $where = [];
    $params = [];
    
    if ($siteId) {
        $where[] = "p.site_id = ?";
        $params[] = $siteId;
    }
    if ($userId) {
        $where[] = "p.user_id = ?";
        $params[] = $userId;
    }
    if ($status) {
        $where[] = "p.status = ?";
        $params[] = $status;
    }
    
    $whereClause = !empty($where) ? 'WHERE ' . implode(' AND ', $where) : '';
    
    $total = Database::fetchColumn("SELECT COUNT(*) FROM payments p $whereClause", $params);
    
    $totalAmountWhere = !empty($where) 
        ? 'WHERE ' . implode(' AND ', $where) . " AND p.status = 'completed'"
        : "WHERE p.status = 'completed'";
    $totalAmount = Database::fetchColumn(
        "SELECT COALESCE(SUM(amount), 0) FROM payments p $totalAmountWhere",
        $params
    ) ?: 0;
    
    $payments = Database::fetchAll(
        "SELECT p.*, s.name as site_name, u.email as user_email 
         FROM payments p
         LEFT JOIN sites s ON p.site_id = s.id
         LEFT JOIN users u ON p.user_id = u.id
         $whereClause ORDER BY p.created_at DESC LIMIT ? OFFSET ?",
        array_merge($params, [$limit, $offset])
    );
    
    $result = array_map(fn($p) => [
        'id' => $p['id'],
        'siteId' => $p['site_id'],
        'siteName' => $p['site_name'],
        'userId' => $p['user_id'],
        'userEmail' => $p['user_email'],
        'amount' => (float)$p['amount'],
        'currency' => $p['currency'],
        'status' => $p['status'],
        'paymentMethod' => $p['payment_method'],
        'createdAt' => $p['created_at'],
        'paidAt' => $p['paid_at']
    ], $payments);
    
    response([
        'payments' => $result,
        'total' => $total,
        'totalAmount' => round($totalAmount, 2),
        'limit' => $limit,
        'offset' => $offset
    ]);
}

if ($method === 'POST' && $uri === '/payments') {
    $input = getInput();
    
    if (empty($input['siteId']) || empty($input['amount'])) {
        error('siteId et amount requis');
    }
    
    $id = generateId('pay');
    
    Database::insert('payments', [
        'id' => $id,
        'site_id' => $input['siteId'],
        'user_id' => $input['userId'] ?? null,
        'subscription_id' => $input['subscriptionId'] ?? null,
        'amount' => (float)$input['amount'],
        'currency' => $input['currency'] ?? 'EUR',
        'status' => 'completed',
        'payment_method' => $input['method'] ?? 'card',
        'metadata' => isset($input['metadata']) ? json_encode($input['metadata']) : null,
        'paid_at' => date('Y-m-d H:i:s'),
        'created_at' => date('Y-m-d H:i:s')
    ]);
    
    logActivity($input['siteId'], $input['userId'] ?? null, 'payment', 'Nouveau paiement: +€' . number_format($input['amount'], 2));
    
    $payment = Database::find('payments', $id);
    
    response([
        'id' => $payment['id'],
        'siteId' => $payment['site_id'],
        'amount' => (float)$payment['amount'],
        'currency' => $payment['currency'],
        'status' => $payment['status'],
        'createdAt' => $payment['created_at']
    ], 201);
}

if ($method === 'POST' && ($params = matchRoute('/payments/{id}/refund', $uri))) {
    $payment = Database::find('payments', $params['id']);
    if (!$payment) error('Paiement non trouvé', 404);
    
    if ($payment['status'] !== 'completed') {
        error('Seuls les paiements complétés peuvent être remboursés');
    }
    
    Database::update('payments', [
        'status' => 'refunded'
    ], ['id' => $params['id']]);
    
    logActivity($payment['site_id'], $payment['user_id'], 'refund', 'Remboursement: -€' . number_format($payment['amount'], 2));
    
    $payment = Database::find('payments', $params['id']);
    
    response([
        'id' => $payment['id'],
        'status' => $payment['status'],
        'amount' => (float)$payment['amount']
    ]);
}

// ============== SUBSCRIPTIONS ==============

if ($method === 'GET' && $uri === '/subscriptions') {
    $siteId = $_GET['siteId'] ?? null;
    $status = $_GET['status'] ?? null;
    $limit = (int)($_GET['limit'] ?? 50);
    $offset = (int)($_GET['offset'] ?? 0);
    
    $where = [];
    $params = [];
    
    if ($siteId) {
        $where[] = "sub.site_id = ?";
        $params[] = $siteId;
    }
    if ($status) {
        $where[] = "sub.status = ?";
        $params[] = $status;
    }
    
    $whereClause = !empty($where) ? 'WHERE ' . implode(' AND ', $where) : '';
    
    $total = Database::fetchColumn("SELECT COUNT(*) FROM subscriptions sub $whereClause", $params);
    
    $subscriptions = Database::fetchAll(
        "SELECT sub.*, s.name as site_name, u.email as user_email, u.name as user_name
         FROM subscriptions sub
         LEFT JOIN sites s ON sub.site_id = s.id
         LEFT JOIN users u ON sub.user_id = u.id
         $whereClause ORDER BY sub.created_at DESC LIMIT ? OFFSET ?",
        array_merge($params, [$limit, $offset])
    );
    
    $result = array_map(fn($sub) => [
        'id' => $sub['id'],
        'siteId' => $sub['site_id'],
        'siteName' => $sub['site_name'],
        'userId' => $sub['user_id'],
        'user' => [
            'email' => $sub['user_email'],
            'name' => $sub['user_name']
        ],
        'plan' => $sub['plan'],
        'status' => $sub['status'],
        'amount' => (float)$sub['amount'],
        'currency' => $sub['currency'],
        'interval' => $sub['interval_type'],
        'createdAt' => $sub['created_at'],
        'cancelledAt' => $sub['cancelled_at']
    ], $subscriptions);
    
    response(['subscriptions' => $result, 'total' => $total, 'limit' => $limit, 'offset' => $offset]);
}

if ($method === 'POST' && ($params = matchRoute('/subscriptions/{id}/cancel', $uri))) {
    $subscription = Database::find('subscriptions', $params['id']);
    if (!$subscription) error('Abonnement non trouvé', 404);
    
    Database::update('subscriptions', [
        'status' => 'cancelled',
        'cancelled_at' => date('Y-m-d H:i:s')
    ], ['id' => $params['id']]);
    
    logActivity($subscription['site_id'], $subscription['user_id'], 'churn', 'Désabonnement: ' . $subscription['plan']);
    
    $subscription = Database::find('subscriptions', $params['id']);
    
    response([
        'id' => $subscription['id'],
        'status' => $subscription['status'],
        'cancelledAt' => $subscription['cancelled_at']
    ]);
}

// ============== ACTIVITIES ==============

if ($method === 'GET' && $uri === '/activities') {
    $siteId = $_GET['siteId'] ?? null;
    $type = $_GET['type'] ?? null;
    $limit = (int)($_GET['limit'] ?? 20);
    
    $where = [];
    $params = [];
    
    if ($siteId) {
        $where[] = "a.site_id = ?";
        $params[] = $siteId;
    }
    if ($type) {
        $where[] = "a.type = ?";
        $params[] = $type;
    }
    
    $whereClause = !empty($where) ? 'WHERE ' . implode(' AND ', $where) : '';
    
    $activities = Database::fetchAll(
        "SELECT a.*, s.name as site_name 
         FROM activities a
         LEFT JOIN sites s ON a.site_id = s.id
         $whereClause ORDER BY a.created_at DESC LIMIT ?",
        array_merge($params, [$limit])
    );
    
    $result = array_map(function($a) {
        $metadata = json_decode($a['metadata'] ?? '{}', true);
        return [
            'id' => $a['id'],
            'siteId' => $a['site_id'],
            'siteName' => $a['site_name'],
            'type' => $a['type'],
            'description' => $a['description'],
            'userId' => $a['user_id'],
            'metadata' => $metadata,
            'createdAt' => $a['created_at']
        ];
    }, $activities);
    
    response($result);
}

// ============== ANALYTICS ==============

if ($method === 'GET' && $uri === '/analytics/revenue') {
    $siteId = $_GET['siteId'] ?? null;
    $period = $_GET['period'] ?? '30d';
    
    $days = match($period) { '7d' => 7, '30d' => 30, '90d' => 90, '1y' => 365, default => 30 };
    
    $where = "status = 'completed' AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)";
    $params = [$days];
    
    if ($siteId) {
        $where .= " AND site_id = ?";
        $params[] = $siteId;
    }
    
    $data = Database::fetchAll(
        "SELECT DATE(created_at) as date, SUM(amount) as revenue 
         FROM payments WHERE $where 
         GROUP BY DATE(created_at) ORDER BY date",
        $params
    );
    
    $result = [];
    $dataMap = array_column($data, 'revenue', 'date');
    
    for ($i = $days - 1; $i >= 0; $i--) {
        $date = date('Y-m-d', strtotime("-$i days"));
        $result[] = [
            'date' => $date,
            'revenue' => round((float)($dataMap[$date] ?? 0), 2)
        ];
    }
    
    response($result);
}

if ($method === 'GET' && $uri === '/analytics/users') {
    $siteId = $_GET['siteId'] ?? null;
    $period = $_GET['period'] ?? '30d';
    
    $days = match($period) { '7d' => 7, '30d' => 30, '90d' => 90, '1y' => 365, default => 30 };
    
    $where = "created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)";
    $params = [$days];
    
    if ($siteId) {
        $where .= " AND site_id = ?";
        $params[] = $siteId;
    }
    
    $data = Database::fetchAll(
        "SELECT DATE(created_at) as date, COUNT(*) as signups 
         FROM users WHERE $where 
         GROUP BY DATE(created_at) ORDER BY date",
        $params
    );
    
    $result = [];
    $dataMap = array_column($data, 'signups', 'date');
    
    for ($i = $days - 1; $i >= 0; $i--) {
        $date = date('Y-m-d', strtotime("-$i days"));
        $result[] = [
            'date' => $date,
            'signups' => (int)($dataMap[$date] ?? 0)
        ];
    }
    
    response($result);
}

if ($method === 'GET' && $uri === '/analytics/breakdown') {
    $totalRevenue = Database::fetchColumn(
        "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status = 'completed'"
    ) ?: 0;
    
    $sites = Database::fetchAll(
        "SELECT s.id, s.name, s.color, COALESCE(SUM(p.amount), 0) as revenue
         FROM sites s
         LEFT JOIN payments p ON p.site_id = s.id AND p.status = 'completed'
         GROUP BY s.id ORDER BY revenue DESC"
    );
    
    $result = array_map(fn($s) => [
        'siteId' => $s['id'],
        'name' => $s['name'],
        'color' => $s['color'],
        'revenue' => round((float)$s['revenue'], 2),
        'percentage' => $totalRevenue > 0 ? round($s['revenue'] / $totalRevenue * 100) : 0
    ], $sites);
    
    response($result);
}

if ($method === 'GET' && $uri === '/analytics/comparison') {
    $period = $_GET['period'] ?? '30d';
    
    $days = match($period) { '7d' => 7, '30d' => 30, '90d' => 90, default => 30 };
    
    $currentRevenue = Database::fetchColumn(
        "SELECT COALESCE(SUM(amount), 0) FROM payments 
         WHERE status = 'completed' AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)",
        [$days]
    ) ?: 0;
    
    $currentPayments = Database::fetchColumn(
        "SELECT COUNT(*) FROM payments 
         WHERE status = 'completed' AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)",
        [$days]
    ) ?: 0;
    
    $currentUsers = Database::fetchColumn(
        "SELECT COUNT(*) FROM users WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)",
        [$days]
    ) ?: 0;
    
    $previousRevenue = Database::fetchColumn(
        "SELECT COALESCE(SUM(amount), 0) FROM payments 
         WHERE status = 'completed' 
         AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY) 
         AND created_at < DATE_SUB(NOW(), INTERVAL ? DAY)",
        [$days * 2, $days]
    ) ?: 0;
    
    $previousPayments = Database::fetchColumn(
        "SELECT COUNT(*) FROM payments 
         WHERE status = 'completed' 
         AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY) 
         AND created_at < DATE_SUB(NOW(), INTERVAL ? DAY)",
        [$days * 2, $days]
    ) ?: 0;
    
    $previousUsers = Database::fetchColumn(
        "SELECT COUNT(*) FROM users 
         WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY) 
         AND created_at < DATE_SUB(NOW(), INTERVAL ? DAY)",
        [$days * 2, $days]
    ) ?: 0;
    
    $calcTrend = fn($current, $previous) => $previous > 0 ? round(($current - $previous) / $previous * 100, 1) : 0;
    
    response([
        'current' => [
            'revenue' => round((float)$currentRevenue, 2),
            'payments' => (int)$currentPayments,
            'users' => (int)$currentUsers
        ],
        'previous' => [
            'revenue' => round((float)$previousRevenue, 2),
            'payments' => (int)$previousPayments,
            'users' => (int)$previousUsers
        ],
        'trends' => [
            'revenue' => $calcTrend($currentRevenue, $previousRevenue),
            'payments' => $calcTrend($currentPayments, $previousPayments),
            'users' => $calcTrend($currentUsers, $previousUsers)
        ]
    ]);
}

// ============== NOTIFICATIONS ==============

if ($method === 'GET' && $uri === '/notifications') {
    $admin = requireAuth();
    $unreadOnly = isset($_GET['unread']);
    $limit = (int)($_GET['limit'] ?? 20);
    
    $where = "(admin_id = ? OR admin_id IS NULL)";
    $params = [$admin['id']];
    
    if ($unreadOnly) {
        $where .= " AND is_read = 0";
    }
    
    $notifications = Database::fetchAll(
        "SELECT * FROM notifications WHERE $where ORDER BY created_at DESC LIMIT ?",
        array_merge($params, [$limit])
    );
    
    $result = array_map(fn($n) => [
        'id' => $n['id'],
        'type' => $n['type'],
        'title' => $n['title'],
        'message' => $n['message'],
        'isRead' => (bool)$n['is_read'],
        'createdAt' => $n['created_at']
    ], $notifications);
    
    response($result);
}

if ($method === 'PUT' && ($params = matchRoute('/notifications/{id}/read', $uri))) {
    $admin = requireAuth();
    
    Database::update('notifications', [
        'is_read' => 1,
        'read_at' => date('Y-m-d H:i:s')
    ], ['id' => $params['id']]);
    
    response(['success' => true]);
}

if ($method === 'PUT' && $uri === '/notifications/read-all') {
    $admin = requireAuth();
    
    Database::query(
        "UPDATE notifications SET is_read = 1, read_at = NOW() 
         WHERE (admin_id = ? OR admin_id IS NULL) AND is_read = 0",
        [$admin['id']]
    );
    
    response(['success' => true]);
}

// ============== REPORTS ==============

if ($method === 'GET' && $uri === '/reports') {
    $reports = Database::fetchAll("SELECT * FROM reports ORDER BY created_at DESC LIMIT 20");
    
    $result = array_map(fn($r) => [
        'id' => $r['id'],
        'type' => $r['type'],
        'siteId' => $r['site_id'],
        'period' => json_decode($r['period'], true),
        'data' => json_decode($r['data'], true),
        'createdAt' => $r['created_at']
    ], $reports);
    
    response($result);
}

if ($method === 'POST' && $uri === '/reports') {
    $input = getInput();
    $siteId = $input['siteId'] ?? null;
    $type = $input['type'] ?? 'monthly';
    
    $startOfMonth = date('Y-m-01');
    
    $siteFilter = $siteId ? "AND site_id = ?" : "";
    $params = $siteId ? [$startOfMonth, $siteId] : [$startOfMonth];
    
    $newUsers = Database::fetchColumn(
        "SELECT COUNT(*) FROM users WHERE created_at >= ? $siteFilter",
        $params
    );
    
    $payments = Database::fetchColumn(
        "SELECT COUNT(*) FROM payments WHERE status = 'completed' AND created_at >= ? $siteFilter",
        $params
    );
    
    $revenue = Database::fetchColumn(
        "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status = 'completed' AND created_at >= ? $siteFilter",
        $params
    ) ?: 0;
    
    $totalUsers = Database::fetchColumn(
        "SELECT COUNT(*) FROM users" . ($siteId ? " WHERE site_id = ?" : ""),
        $siteId ? [$siteId] : []
    );
    
    $activeSubs = Database::fetchColumn(
        "SELECT COUNT(*) FROM subscriptions WHERE status = 'active'" . ($siteId ? " AND site_id = ?" : ""),
        $siteId ? [$siteId] : []
    );
    
    $mrr = Database::fetchColumn(
        "SELECT COALESCE(SUM(CASE WHEN interval_type = 'year' THEN amount/12 ELSE amount END), 0)
         FROM subscriptions WHERE status = 'active'" . ($siteId ? " AND site_id = ?" : ""),
        $siteId ? [$siteId] : []
    ) ?: 0;
    
    $reportId = generateId('report');
    $reportData = [
        'totalUsers' => (int)$totalUsers,
        'newUsers' => (int)$newUsers,
        'totalPayments' => (int)$payments,
        'totalRevenue' => round((float)$revenue, 2),
        'mrr' => round((float)$mrr, 2),
        'arr' => round((float)$mrr * 12, 2),
        'activeSubscriptions' => (int)$activeSubs
    ];
    
    Database::insert('reports', [
        'id' => $reportId,
        'type' => $type,
        'site_id' => $siteId,
        'period' => json_encode(['start' => $startOfMonth, 'end' => date('Y-m-d')]),
        'data' => json_encode($reportData),
        'created_at' => date('Y-m-d H:i:s')
    ]);
    
    addNotification('success', 'Rapport généré', 'Le rapport a été créé.');
    
    response([
        'id' => $reportId,
        'type' => $type,
        'siteId' => $siteId ?: 'all',
        'period' => ['start' => $startOfMonth, 'end' => date('Y-m-d H:i:s')],
        'data' => $reportData,
        'createdAt' => date('Y-m-d H:i:s')
    ]);
}

if ($method === 'GET' && $uri === '/reports/generate') {
    $type = $_GET['type'] ?? 'daily';
    $format = $_GET['format'] ?? 'json';
    
    $days = match($type) { 'daily' => 1, 'weekly' => 7, 'monthly' => 30, default => 1 };
    $startDate = date('Y-m-d', strtotime("-{$days} days"));
    
    $revenue = Database::fetchColumn(
        "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status = 'completed' AND created_at >= ?",
        [$startDate]
    ) ?: 0;
    
    $payments = Database::fetchColumn(
        "SELECT COUNT(*) FROM payments WHERE status = 'completed' AND created_at >= ?",
        [$startDate]
    );
    
    $newUsers = Database::fetchColumn(
        "SELECT COUNT(*) FROM users WHERE created_at >= ?",
        [$startDate]
    );
    
    $report = [
        'type' => $type,
        'period' => ['start' => $startDate, 'end' => date('Y-m-d')],
        'generatedAt' => date('c'),
        'summary' => [
            'totalRevenue' => round((float)$revenue, 2),
            'totalPayments' => (int)$payments,
            'newUsers' => (int)$newUsers,
            'avgTransaction' => $payments > 0 ? round($revenue / $payments, 2) : 0
        ]
    ];
    
    response($report);
}

// ============== WEBHOOKS ==============

if ($method === 'POST' && ($params = matchRoute('/webhook/{siteId}', $uri))) {
    $site = Database::find('sites', $params['siteId']);
    if (!$site) {
        $site = Database::fetch("SELECT * FROM sites WHERE api_key = ?", [$params['siteId']]);
    }
    if (!$site) error('Site non trouvé', 404);
    
    $input = getInput();
    $event = $input['event'] ?? '';
    $data = $input['data'] ?? [];
    
    switch ($event) {
        case 'user.created':
            $id = generateId('user');
            Database::insert('users', [
                'id' => $id,
                'site_id' => $site['id'],
                'email' => $data['email'],
                'name' => trim(($data['firstName'] ?? '') . ' ' . ($data['lastName'] ?? '')),
                'external_id' => $data['userId'] ?? $data['externalId'] ?? null,
                'metadata' => json_encode([
                    'plan' => $data['plan'] ?? 'free',
                    'source' => 'webhook',
                    'status' => 'active'
                ]),
                'created_at' => date('Y-m-d H:i:s')
            ]);
            logActivity($site['id'], $id, 'signup', 'Nouvelle inscription: ' . $data['email']);
            addNotification('success', 'Nouvel utilisateur', $data['email'] . ' sur ' . $site['name']);
            response(['success' => true, 'userId' => $id]);
            break;
            
        case 'payment.completed':
            $id = generateId('pay');
            Database::insert('payments', [
                'id' => $id,
                'site_id' => $site['id'],
                'user_id' => $data['userId'] ?? null,
                'amount' => (float)($data['amount'] ?? 0),
                'currency' => $data['currency'] ?? 'EUR',
                'status' => 'completed',
                'payment_method' => $data['method'] ?? 'card',
                'external_id' => $data['paymentId'] ?? $data['externalId'] ?? null,
                'metadata' => json_encode($data['metadata'] ?? []),
                'paid_at' => date('Y-m-d H:i:s'),
                'created_at' => date('Y-m-d H:i:s')
            ]);
            logActivity($site['id'], $data['userId'] ?? null, 'payment', 'Paiement: +€' . number_format($data['amount'] ?? 0, 2));
            addNotification('success', 'Nouveau paiement', number_format($data['amount'] ?? 0, 2) . '€ sur ' . $site['name']);
            response(['success' => true, 'paymentId' => $id]);
            break;
            
        case 'subscription.created':
            $id = generateId('sub');
            Database::insert('subscriptions', [
                'id' => $id,
                'site_id' => $site['id'],
                'user_id' => $data['userId'] ?? null,
                'external_id' => $data['subscriptionId'] ?? $data['externalId'] ?? null,
                'plan' => $data['plan'] ?? 'default',
                'amount' => (float)($data['amount'] ?? 0),
                'currency' => $data['currency'] ?? 'EUR',
                'interval_type' => $data['interval'] ?? 'month',
                'status' => 'active',
                'started_at' => date('Y-m-d H:i:s'),
                'created_at' => date('Y-m-d H:i:s')
            ]);
            logActivity($site['id'], $data['userId'] ?? null, 'subscription', 'Nouvel abonnement: ' . ($data['plan'] ?? 'N/A'));
            addNotification('success', 'Nouvel abonnement', 'Plan ' . ($data['plan'] ?? 'N/A') . ' sur ' . $site['name']);
            response(['success' => true, 'subscriptionId' => $id]);
            break;
            
        case 'subscription.cancelled':
            $externalId = $data['subscriptionId'] ?? $data['externalId'] ?? null;
            if ($externalId) {
                Database::query(
                    "UPDATE subscriptions SET status = 'cancelled', cancelled_at = NOW() 
                     WHERE site_id = ? AND external_id = ?",
                    [$site['id'], $externalId]
                );
            }
            logActivity($site['id'], $data['userId'] ?? null, 'churn', 'Abonnement annulé');
            addNotification('warning', 'Abonnement annulé', 'Sur ' . $site['name']);
            response(['success' => true]);
            break;
            
        default:
            logActivity($site['id'], null, $event ?: 'unknown', 'Événement webhook: ' . $event);
            response(['success' => true, 'message' => 'Événement reçu']);
    }
}

// ============== API KEYS ==============

if ($method === 'GET' && $uri === '/api-keys') {
    $admin = requireAuth();
    
    $keys = Database::fetchAll(
        "SELECT * FROM api_keys WHERE admin_id = ? ORDER BY created_at DESC",
        [$admin['id']]
    );
    
    response(array_map(fn($k) => [
        'id' => $k['id'],
        'name' => $k['name'],
        'keyPrefix' => $k['key_prefix'],
        'permissions' => json_decode($k['permissions'] ?? '[]', true),
        'rateLimit' => (int)$k['rate_limit'],
        'lastUsedAt' => $k['last_used_at'],
        'usageCount' => (int)$k['usage_count'],
        'isActive' => (bool)$k['is_active'],
        'createdAt' => $k['created_at']
    ], $keys));
}

if ($method === 'POST' && $uri === '/api-keys') {
    $admin = requireAuth();
    $input = getInput();
    
    $name = $input['name'] ?? '';
    if (!$name) {
        error('Nom requis', 400);
    }
    
    $keyRaw = 'pk_' . bin2hex(random_bytes(24));
    $keyPrefix = substr($keyRaw, 0, 10);
    $keyHash = hash('sha256', $keyRaw);
    
    $id = generateId('apikey');
    Database::insert('api_keys', [
        'id' => $id,
        'admin_id' => $admin['id'],
        'name' => $name,
        'key_hash' => $keyHash,
        'key_prefix' => $keyPrefix,
        'permissions' => json_encode($input['permissions'] ?? ['read']),
        'rate_limit' => $input['rateLimit'] ?? 1000,
        'is_active' => 1
    ]);
    
    response([
        'id' => $id,
        'name' => $name,
        'key' => $keyRaw,
        'keyPrefix' => $keyPrefix,
        'message' => 'Conservez cette clé précieusement, elle ne sera plus affichée.'
    ], 201);
}

if ($method === 'DELETE' && ($params = matchRoute('/api-keys/{id}', $uri))) {
    $admin = requireAuth();
    
    Database::query(
        "DELETE FROM api_keys WHERE id = ? AND admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    response(['success' => true]);
}

// ============== SETTINGS ==============

if ($method === 'GET' && $uri === '/settings') {
    $admin = getAuthAdmin();
    
    if ($admin) {
        $settings = Database::find('settings', $admin['id'], 'admin_id');
        if ($settings) {
            response([
                'theme' => $settings['theme'],
                'language' => $settings['language'],
                'currency' => $settings['currency'],
                'timezone' => $settings['timezone'],
                'notifications' => [
                    'email' => (bool)$settings['notifications_email'],
                    'push' => (bool)$settings['notifications_push']
                ],
                'integrations' => json_decode($settings['integrations'] ?? '{}', true)
            ]);
        }
    }
    
    response([
        'theme' => 'dark',
        'language' => 'fr',
        'currency' => 'EUR',
        'timezone' => 'Europe/Paris',
        'notifications' => ['email' => true, 'push' => true],
        'integrations' => ['stripe' => ['enabled' => false], 'paypal' => ['enabled' => false]]
    ]);
}

if ($method === 'PUT' && $uri === '/settings') {
    $admin = requireAuth();
    $input = getInput();
    
    $data = [
        'admin_id' => $admin['id'],
        'theme' => $input['theme'] ?? 'dark',
        'language' => $input['language'] ?? 'fr',
        'currency' => $input['currency'] ?? 'EUR',
        'timezone' => $input['timezone'] ?? 'Europe/Paris',
        'notifications_email' => ($input['notifications']['email'] ?? true) ? 1 : 0,
        'notifications_push' => ($input['notifications']['push'] ?? true) ? 1 : 0,
        'integrations' => json_encode($input['integrations'] ?? [])
    ];
    
    Database::query(
        "INSERT INTO settings (admin_id, theme, language, currency, timezone, notifications_email, notifications_push, integrations)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            theme = VALUES(theme),
            language = VALUES(language),
            currency = VALUES(currency),
            timezone = VALUES(timezone),
            notifications_email = VALUES(notifications_email),
            notifications_push = VALUES(notifications_push),
            integrations = VALUES(integrations),
            updated_at = NOW()",
        array_values($data)
    );
    
    response(['success' => true]);
}

// ============== EXPORTS ==============

if ($method === 'GET' && $uri === '/export/users') {
    $siteId = $_GET['siteId'] ?? null;
    $format = $_GET['format'] ?? 'json';
    
    $where = $siteId ? "WHERE site_id = ?" : "";
    $params = $siteId ? [$siteId] : [];
    
    $users = Database::fetchAll(
        "SELECT u.*, s.name as site_name FROM users u 
         LEFT JOIN sites s ON u.site_id = s.id 
         $where ORDER BY u.created_at DESC",
        $params
    );
    
    if ($format === 'csv') {
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="users_' . date('Y-m-d') . '.csv"');
        
        echo "ID,Site,Email,Nom,Créé le\n";
        foreach ($users as $u) {
            echo '"' . $u['id'] . '","' . ($u['site_name'] ?? '') . '","' . $u['email'] . '","' . ($u['name'] ?? '') . '","' . $u['created_at'] . '"' . "\n";
        }
        exit;
    }
    
    response($users);
}

if ($method === 'GET' && $uri === '/export/payments') {
    $siteId = $_GET['siteId'] ?? null;
    $format = $_GET['format'] ?? 'json';
    
    $where = $siteId ? "WHERE p.site_id = ?" : "";
    $params = $siteId ? [$siteId] : [];
    
    $payments = Database::fetchAll(
        "SELECT p.*, s.name as site_name, u.email as user_email FROM payments p 
         LEFT JOIN sites s ON p.site_id = s.id 
         LEFT JOIN users u ON p.user_id = u.id
         $where ORDER BY p.created_at DESC",
        $params
    );
    
    if ($format === 'csv') {
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="payments_' . date('Y-m-d') . '.csv"');
        
        echo "ID,Site,Client,Montant,Devise,Statut,Méthode,Créé le\n";
        foreach ($payments as $p) {
            echo '"' . $p['id'] . '","' . ($p['site_name'] ?? '') . '","' . ($p['user_email'] ?? '') . '",' . $p['amount'] . ',"' . $p['currency'] . '","' . $p['status'] . '","' . ($p['payment_method'] ?? '') . '","' . $p['created_at'] . '"' . "\n";
        }
        exit;
    }
    
    response($payments);
}

// ============== MONITORING ==============

if ($method === 'GET' && $uri === '/monitoring') {
    $sites = Database::fetchAll("SELECT * FROM sites ORDER BY created_at DESC");
    
    $result = [];
    foreach ($sites as $site) {
        $lastCheck = Database::fetch(
            "SELECT * FROM monitoring WHERE site_id = ? AND metric_type = 'uptime' ORDER BY recorded_at DESC LIMIT 1",
            [$site['id']]
        );
        
        $stats = Database::fetch(
            "SELECT 
                ROUND(AVG(CASE WHEN metric_type = 'uptime' AND value > 0 THEN 100 ELSE 0 END), 1) as uptime,
                ROUND(AVG(CASE WHEN metric_type = 'response_time' THEN value ELSE NULL END)) as avg_response,
                COUNT(CASE WHEN metric_type = 'uptime' AND value = 0 THEN 1 END) as incidents
             FROM monitoring WHERE site_id = ? AND recorded_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)",
            [$site['id']]
        );
        
        $result[] = [
            'siteId' => $site['id'],
            'siteName' => $site['name'],
            'url' => $site['url'],
            'status' => $site['status'],
            'uptime' => round((float)($stats['uptime'] ?? 100), 1),
            'avgResponseTime' => (int)($stats['avg_response'] ?? 0),
            'lastCheck' => $lastCheck['recorded_at'] ?? null,
            'lastStatus' => $lastCheck ? ($lastCheck['value'] > 0 ? 'up' : 'down') : null,
            'incidents' => (int)($stats['incidents'] ?? 0)
        ];
    }
    
    response($result);
}

/**
 * NOTESO - Endpoints Sécurité & Monitoring
 * ==========================================
 * 
 * Ajouter ce code à api.php avant la ligne "error('Endpoint non trouvé', 404);"
 */

// ============== AUDIT LOGS ==============

// GET /security/audit - Liste des logs d'audit
if ($method === 'GET' && $uri === '/security/audit') {
    $admin = requireAuth();
    
    $page = max(1, intval($_GET['page'] ?? 1));
    $limit = min(100, max(10, intval($_GET['limit'] ?? 50)));
    $offset = ($page - 1) * $limit;
    
    // Filtres
    $where = ['1=1'];
    $params = [];
    
    if (!empty($_GET['action'])) {
        $where[] = 'action = ?';
        $params[] = $_GET['action'];
    }
    
    if (!empty($_GET['entity_type'])) {
        $where[] = 'entity_type = ?';
        $params[] = $_GET['entity_type'];
    }
    
    if (!empty($_GET['admin_id'])) {
        $where[] = 'admin_id = ?';
        $params[] = $_GET['admin_id'];
    }
    
    if (!empty($_GET['ip'])) {
        $where[] = 'ip_address LIKE ?';
        $params[] = '%' . $_GET['ip'] . '%';
    }
    
    if (!empty($_GET['from'])) {
        $where[] = 'created_at >= ?';
        $params[] = $_GET['from'];
    }
    
    if (!empty($_GET['to'])) {
        $where[] = 'created_at <= ?';
        $params[] = $_GET['to'];
    }
    
    $whereClause = implode(' AND ', $where);
    
    $total = Database::fetchColumn(
        "SELECT COUNT(*) FROM audit_logs WHERE $whereClause",
        $params
    );
    
    $logs = Database::fetchAll(
        "SELECT al.*, a.email as admin_email, a.first_name, a.last_name
         FROM audit_logs al
         LEFT JOIN admins a ON al.admin_id = a.id
         WHERE $whereClause
         ORDER BY al.created_at DESC
         LIMIT $limit OFFSET $offset",
        $params
    );
    
    response([
        'logs' => $logs,
        'pagination' => [
            'page' => $page,
            'limit' => $limit,
            'total' => $total,
            'pages' => ceil($total / $limit)
        ]
    ]);
}

// GET /security/audit/stats - Statistiques des logs d'audit
if ($method === 'GET' && $uri === '/security/audit/stats') {
    $admin = requireAuth();
    
    $period = $_GET['period'] ?? '24h';
    $interval = match($period) {
        '1h' => 'INTERVAL 1 HOUR',
        '24h' => 'INTERVAL 24 HOUR',
        '7d' => 'INTERVAL 7 DAY',
        '30d' => 'INTERVAL 30 DAY',
        default => 'INTERVAL 24 HOUR'
    };
    
    // Actions par type
    $byAction = Database::fetchAll(
        "SELECT action, COUNT(*) as count 
         FROM audit_logs 
         WHERE created_at > DATE_SUB(NOW(), $interval)
         GROUP BY action 
         ORDER BY count DESC 
         LIMIT 10"
    );
    
    // Par entité
    $byEntity = Database::fetchAll(
        "SELECT entity_type, COUNT(*) as count 
         FROM audit_logs 
         WHERE created_at > DATE_SUB(NOW(), $interval)
         GROUP BY entity_type 
         ORDER BY count DESC"
    );
    
    // Par admin
    $byAdmin = Database::fetchAll(
        "SELECT al.admin_id, a.email, a.first_name, a.last_name, COUNT(*) as count 
         FROM audit_logs al
         LEFT JOIN admins a ON al.admin_id = a.id
         WHERE al.created_at > DATE_SUB(NOW(), $interval)
         GROUP BY al.admin_id 
         ORDER BY count DESC 
         LIMIT 10"
    );
    
    // Timeline (par heure ou par jour selon la période)
    $groupBy = in_array($period, ['1h', '24h']) ? '%Y-%m-%d %H:00' : '%Y-%m-%d';
    $timeline = Database::fetchAll(
        "SELECT DATE_FORMAT(created_at, '$groupBy') as period, COUNT(*) as count 
         FROM audit_logs 
         WHERE created_at > DATE_SUB(NOW(), $interval)
         GROUP BY period 
         ORDER BY period ASC"
    );
    
    response([
        'period' => $period,
        'byAction' => $byAction,
        'byEntity' => $byEntity,
        'byAdmin' => $byAdmin,
        'timeline' => $timeline,
        'total' => Database::fetchColumn(
            "SELECT COUNT(*) FROM audit_logs WHERE created_at > DATE_SUB(NOW(), $interval)"
        )
    ]);
}

// ============== ALERTES ==============

// GET /security/alerts - Liste des alertes
if ($method === 'GET' && $uri === '/security/alerts') {
    $admin = requireAuth();
    
    $status = $_GET['status'] ?? 'active'; // active, resolved, all
    $severity = $_GET['severity'] ?? null;
    $limit = min(100, intval($_GET['limit'] ?? 50));
    
    $where = ['1=1'];
    $params = [];
    
    if ($status === 'active') {
        $where[] = 'is_resolved = 0';
    } elseif ($status === 'resolved') {
        $where[] = 'is_resolved = 1';
    }
    
    if ($severity) {
        $where[] = 'severity = ?';
        $params[] = $severity;
    }
    
    $whereClause = implode(' AND ', $where);
    
    $alerts = Database::fetchAll(
        "SELECT a.*, adm.email as resolved_by_email
         FROM alerts a
         LEFT JOIN admins adm ON a.resolved_by = adm.id
         WHERE $whereClause
         ORDER BY 
            CASE a.severity WHEN 'critical' THEN 1 WHEN 'warning' THEN 2 ELSE 3 END,
            a.created_at DESC
         LIMIT $limit",
        $params
    );
    
    $counts = Database::fetch(
        "SELECT 
            SUM(CASE WHEN is_resolved = 0 THEN 1 ELSE 0 END) as active,
            SUM(CASE WHEN is_resolved = 0 AND severity = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN is_resolved = 0 AND severity = 'warning' THEN 1 ELSE 0 END) as warning,
            SUM(CASE WHEN is_resolved = 1 THEN 1 ELSE 0 END) as resolved
         FROM alerts"
    );
    
    response([
        'alerts' => $alerts,
        'counts' => $counts
    ]);
}

// POST /security/alerts/:id/resolve - Résoudre une alerte
if ($method === 'POST' && preg_match('#^/security/alerts/([^/]+)/resolve$#', $uri, $m)) {
    $admin = requireAuth();
    $alertId = $m[1];
    
    $alert = Database::find('alerts', $alertId);
    if (!$alert) {
        error('Alerte non trouvée', 404);
    }
    
    Database::update('alerts', [
        'is_resolved' => 1,
        'resolved_at' => date('Y-m-d H:i:s'),
        'resolved_by' => $admin['id']
    ], ['id' => $alertId]);
    
    auditLog($admin['id'], 'resolve', 'alert', $alertId);
    
    response(['success' => true, 'message' => 'Alerte résolue']);
}

// POST /security/alerts/:id/reopen - Réouvrir une alerte
if ($method === 'POST' && preg_match('#^/security/alerts/([^/]+)/reopen$#', $uri, $m)) {
    $admin = requireAuth();
    $alertId = $m[1];
    
    Database::update('alerts', [
        'is_resolved' => 0,
        'resolved_at' => null,
        'resolved_by' => null
    ], ['id' => $alertId]);
    
    auditLog($admin['id'], 'reopen', 'alert', $alertId);
    
    response(['success' => true]);
}

// DELETE /security/alerts/:id - Supprimer une alerte
if ($method === 'DELETE' && preg_match('#^/security/alerts/([^/]+)$#', $uri, $m)) {
    $admin = requireAuth();
    $alertId = $m[1];
    
    Database::delete('alerts', ['id' => $alertId]);
    auditLog($admin['id'], 'delete', 'alert', $alertId);
    
    response(['success' => true]);
}

// ============== RÈGLES D'ALERTES ==============

// GET /security/alert-rules - Liste des règles
if ($method === 'GET' && $uri === '/security/alert-rules') {
    $admin = requireAuth();
    
    $rules = Database::fetchAll(
        "SELECT * FROM alert_rules ORDER BY is_enabled DESC, severity DESC, name ASC"
    );
    
    response(['rules' => $rules]);
}

// POST /security/alert-rules - Créer une règle
if ($method === 'POST' && $uri === '/security/alert-rules') {
    $admin = requireAuth();
    $input = getInput();
    
    $required = ['name', 'metric', 'condition_operator', 'condition_value'];
    foreach ($required as $field) {
        if (empty($input[$field])) {
            error("Le champ '$field' est requis", 400);
        }
    }
    
    $id = generateId('rule');
    
    Database::insert('alert_rules', [
        'id' => $id,
        'name' => $input['name'],
        'description' => $input['description'] ?? null,
        'type' => $input['type'] ?? 'threshold',
        'metric' => $input['metric'],
        'condition_operator' => $input['condition_operator'],
        'condition_value' => $input['condition_value'],
        'time_window_minutes' => $input['time_window_minutes'] ?? 5,
        'severity' => $input['severity'] ?? 'warning',
        'is_enabled' => $input['is_enabled'] ?? 1,
        'notify_email' => $input['notify_email'] ?? 1,
        'notify_webhook' => $input['notify_webhook'] ?? 0,
        'webhook_url' => $input['webhook_url'] ?? null,
        'cooldown_minutes' => $input['cooldown_minutes'] ?? 15
    ]);
    
    auditLog($admin['id'], 'create', 'alert_rule', $id, null, $input);
    
    response(['success' => true, 'id' => $id]);
}

// PUT /security/alert-rules/:id - Modifier une règle
if ($method === 'PUT' && preg_match('#^/security/alert-rules/([^/]+)$#', $uri, $m)) {
    $admin = requireAuth();
    $ruleId = $m[1];
    $input = getInput();
    
    $rule = Database::find('alert_rules', $ruleId);
    if (!$rule) {
        error('Règle non trouvée', 404);
    }
    
    $updates = [];
    $allowed = ['name', 'description', 'type', 'metric', 'condition_operator', 'condition_value', 
                'time_window_minutes', 'severity', 'is_enabled', 'notify_email', 'notify_webhook', 
                'webhook_url', 'cooldown_minutes'];
    
    foreach ($allowed as $field) {
        if (isset($input[$field])) {
            $updates[$field] = $input[$field];
        }
    }
    
    if (!empty($updates)) {
        Database::update('alert_rules', $updates, ['id' => $ruleId]);
        auditLog($admin['id'], 'update', 'alert_rule', $ruleId, $rule, $updates);
    }
    
    response(['success' => true]);
}

// DELETE /security/alert-rules/:id - Supprimer une règle
if ($method === 'DELETE' && preg_match('#^/security/alert-rules/([^/]+)$#', $uri, $m)) {
    $admin = requireAuth();
    $ruleId = $m[1];
    
    Database::delete('alert_rules', ['id' => $ruleId]);
    auditLog($admin['id'], 'delete', 'alert_rule', $ruleId);
    
    response(['success' => true]);
}

// ============== IP WHITELIST/BLACKLIST ==============

// GET /security/ip-rules - Liste des règles IP
if ($method === 'GET' && $uri === '/security/ip-rules') {
    $admin = requireAuth();
    
    $type = $_GET['type'] ?? null; // whitelist, blacklist
    
    $where = '(expires_at IS NULL OR expires_at > NOW())';
    $params = [];
    
    if ($type) {
        $where .= ' AND type = ?';
        $params[] = $type;
    }
    
    $rules = Database::fetchAll(
        "SELECT ipr.*, a.email as created_by_email
         FROM ip_rules ipr
         LEFT JOIN admins a ON ipr.created_by = a.id
         WHERE $where
         ORDER BY type, created_at DESC",
        $params
    );
    
    response(['rules' => $rules]);
}

// POST /security/ip-rules - Ajouter une règle IP
if ($method === 'POST' && $uri === '/security/ip-rules') {
    $admin = requireAuth();
    $input = getInput();
    
    if (empty($input['ip_address']) || empty($input['type'])) {
        error('IP et type requis', 400);
    }
    
    // Valider le format IP ou CIDR
    $ip = $input['ip_address'];
    if (!filter_var($ip, FILTER_VALIDATE_IP) && !preg_match('#^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$#', $ip)) {
        error('Format IP invalide', 400);
    }
    
    if (!in_array($input['type'], ['whitelist', 'blacklist'])) {
        error('Type invalide (whitelist ou blacklist)', 400);
    }
    
    $id = generateId('iprule');
    
    Database::insert('ip_rules', [
        'id' => $id,
        'ip_address' => $ip,
        'type' => $input['type'],
        'description' => $input['description'] ?? null,
        'expires_at' => $input['expires_at'] ?? null,
        'created_by' => $admin['id']
    ]);
    
    auditLog($admin['id'], 'create', 'ip_rule', $id, null, $input);
    logSecurityEvent('ip_rule_created', "Règle IP créée: {$input['type']} - $ip", $admin['id']);
    
    response(['success' => true, 'id' => $id]);
}

// DELETE /security/ip-rules/:id - Supprimer une règle IP
if ($method === 'DELETE' && preg_match('#^/security/ip-rules/([^/]+)$#', $uri, $m)) {
    $admin = requireAuth();
    $ruleId = $m[1];
    
    $rule = Database::find('ip_rules', $ruleId);
    if ($rule) {
        Database::delete('ip_rules', ['id' => $ruleId]);
        auditLog($admin['id'], 'delete', 'ip_rule', $ruleId, $rule);
        logSecurityEvent('ip_rule_deleted', "Règle IP supprimée: {$rule['ip_address']}", $admin['id']);
    }
    
    response(['success' => true]);
}

// GET /security/ip-check/:ip - Vérifier si une IP est autorisée
if ($method === 'GET' && preg_match('#^/security/ip-check/([^/]+)$#', $uri, $m)) {
    $admin = requireAuth();
    $ip = $m[1];
    
    $status = checkIPAccess($ip);
    
    response([
        'ip' => $ip,
        'allowed' => $status['allowed'],
        'reason' => $status['reason'],
        'matchedRule' => $status['rule'] ?? null
    ]);
}

// ============== BACKUPS ==============

// GET /security/backups - Liste des backups
if ($method === 'GET' && $uri === '/security/backups') {
    $admin = requireAuth();
    
    $backups = Database::fetchAll(
        "SELECT b.*, a.email as created_by_email
         FROM backups b
         LEFT JOIN admins a ON b.created_by = a.id
         ORDER BY b.created_at DESC
         LIMIT 50"
    );
    
    response(['backups' => $backups]);
}

// POST /security/backups - Créer un backup
if ($method === 'POST' && $uri === '/security/backups') {
    $admin = requireAuth();
    $input = getInput();
    
    $id = generateId('backup');
    $filename = 'noteso_backup_' . date('Y-m-d_His') . '.sql';
    $backupDir = '/srv/web/noteso/backups';
    
    // Créer le dossier si nécessaire
    if (!is_dir($backupDir)) {
        mkdir($backupDir, 0755, true);
    }
    
    $filePath = $backupDir . '/' . $filename;
    
    // Tables à sauvegarder
    $tables = $input['tables'] ?? ['admins', 'sites', 'users', 'payments', 'subscriptions', 
                                     'activities', 'notifications', 'settings', 'api_keys'];
    
    // Créer l'entrée backup
    Database::insert('backups', [
        'id' => $id,
        'filename' => $filename,
        'file_path' => $filePath,
        'file_size' => 0,
        'type' => 'manual',
        'status' => 'running',
        'tables_included' => json_encode($tables),
        'started_at' => date('Y-m-d H:i:s'),
        'created_by' => $admin['id']
    ]);
    
    // Exécuter le backup en arrière-plan
    // En production, utiliser un job queue
    try {
        $config = require dirname(__DIR__) . '/config/config.php';
        $dbHost = $config['database']['host'];
        $dbName = $config['database']['name'];
        $dbUser = $config['database']['user'];
        $dbPass = $config['database']['password'];
        
        $tablesStr = implode(' ', $tables);
        $cmd = sprintf(
            'mysqldump -h %s -u %s -p%s %s %s > %s 2>&1',
            escapeshellarg($dbHost),
            escapeshellarg($dbUser),
            escapeshellarg($dbPass),
            escapeshellarg($dbName),
            $tablesStr,
            escapeshellarg($filePath)
        );
        
        exec($cmd, $output, $returnCode);
        
        if ($returnCode === 0 && file_exists($filePath)) {
            $fileSize = filesize($filePath);
            Database::update('backups', [
                'status' => 'completed',
                'file_size' => $fileSize,
                'completed_at' => date('Y-m-d H:i:s')
            ], ['id' => $id]);
            
            auditLog($admin['id'], 'create', 'backup', $id);
            logSecurityEvent('backup_created', "Backup créé: $filename ($fileSize bytes)", $admin['id']);
            
            response([
                'success' => true, 
                'id' => $id, 
                'filename' => $filename,
                'size' => $fileSize
            ]);
        } else {
            Database::update('backups', [
                'status' => 'failed',
                'error_message' => implode("\n", $output)
            ], ['id' => $id]);
            
            error('Échec du backup: ' . implode(', ', $output), 500);
        }
    } catch (Exception $e) {
        Database::update('backups', [
            'status' => 'failed',
            'error_message' => $e->getMessage()
        ], ['id' => $id]);
        
        error('Erreur backup: ' . $e->getMessage(), 500);
    }
}

// GET /security/backups/:id/download - Télécharger un backup
if ($method === 'GET' && preg_match('#^/security/backups/([^/]+)/download$#', $uri, $m)) {
    $admin = requireAuth();
    $backupId = $m[1];
    
    $backup = Database::find('backups', $backupId);
    if (!$backup || $backup['status'] !== 'completed') {
        error('Backup non disponible', 404);
    }
    
    if (!file_exists($backup['file_path'])) {
        error('Fichier non trouvé', 404);
    }
    
    auditLog($admin['id'], 'download', 'backup', $backupId);
    
    header('Content-Type: application/sql');
    header('Content-Disposition: attachment; filename="' . $backup['filename'] . '"');
    header('Content-Length: ' . $backup['file_size']);
    readfile($backup['file_path']);
    exit;
}

// DELETE /security/backups/:id - Supprimer un backup
if ($method === 'DELETE' && preg_match('#^/security/backups/([^/]+)$#', $uri, $m)) {
    $admin = requireAuth();
    $backupId = $m[1];
    
    $backup = Database::find('backups', $backupId);
    if ($backup) {
        // Supprimer le fichier
        if (file_exists($backup['file_path'])) {
            unlink($backup['file_path']);
        }
        
        Database::delete('backups', ['id' => $backupId]);
        auditLog($admin['id'], 'delete', 'backup', $backupId);
    }
    
    response(['success' => true]);
}

// ============== SECURITY EVENTS ==============

// GET /security/events - Liste des événements de sécurité
if ($method === 'GET' && $uri === '/security/events') {
    $admin = requireAuth();
    
    $limit = min(100, intval($_GET['limit'] ?? 50));
    $type = $_GET['type'] ?? null;
    $severity = $_GET['severity'] ?? null;
    
    $where = ['1=1'];
    $params = [];
    
    if ($type) {
        $where[] = 'event_type = ?';
        $params[] = $type;
    }
    
    if ($severity) {
        $where[] = 'severity = ?';
        $params[] = $severity;
    }
    
    $whereClause = implode(' AND ', $where);
    
    $events = Database::fetchAll(
        "SELECT se.*, a.email as admin_email, a.first_name, a.last_name
         FROM security_events se
         LEFT JOIN admins a ON se.admin_id = a.id
         WHERE $whereClause
         ORDER BY se.created_at DESC
         LIMIT $limit",
        $params
    );
    
    response(['events' => $events]);
}

// GET /security/events/stats - Statistiques des événements
if ($method === 'GET' && $uri === '/security/events/stats') {
    $admin = requireAuth();
    
    // Événements des dernières 24h par type
    $byType = Database::fetchAll(
        "SELECT event_type, COUNT(*) as count 
         FROM security_events 
         WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
         GROUP BY event_type 
         ORDER BY count DESC"
    );
    
    // Par sévérité
    $bySeverity = Database::fetchAll(
        "SELECT severity, COUNT(*) as count 
         FROM security_events 
         WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
         GROUP BY severity"
    );
    
    // Timeline horaire
    $timeline = Database::fetchAll(
        "SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:00') as hour, COUNT(*) as count 
         FROM security_events 
         WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
         GROUP BY hour 
         ORDER BY hour ASC"
    );
    
    // Top IPs
    $topIPs = Database::fetchAll(
        "SELECT ip_address, COUNT(*) as count 
         FROM security_events 
         WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
         GROUP BY ip_address 
         ORDER BY count DESC 
         LIMIT 10"
    );
    
    response([
        'byType' => $byType,
        'bySeverity' => $bySeverity,
        'timeline' => $timeline,
        'topIPs' => $topIPs,
        'total24h' => Database::fetchColumn(
            "SELECT COUNT(*) FROM security_events WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        )
    ]);
}

// ============== MÉTRIQUES ==============

// POST /security/metrics - Enregistrer une métrique
if ($method === 'POST' && $uri === '/security/metrics') {
    // Pas besoin d'auth pour les métriques internes
    $input = getInput();
    
    if (empty($input['name']) || !isset($input['value'])) {
        error('name et value requis', 400);
    }
    
    Database::insert('metrics', [
        'metric_name' => $input['name'],
        'metric_value' => $input['value'],
        'tags' => isset($input['tags']) ? json_encode($input['tags']) : null
    ]);
    
    response(['success' => true]);
}

// GET /security/metrics - Récupérer les métriques
if ($method === 'GET' && $uri === '/security/metrics') {
    $admin = requireAuth();
    
    $metric = $_GET['metric'] ?? null;
    $period = $_GET['period'] ?? '24h';
    
    $interval = match($period) {
        '1h' => 'INTERVAL 1 HOUR',
        '6h' => 'INTERVAL 6 HOUR',
        '24h' => 'INTERVAL 24 HOUR',
        '7d' => 'INTERVAL 7 DAY',
        '30d' => 'INTERVAL 30 DAY',
        default => 'INTERVAL 24 HOUR'
    };
    
    if ($metric) {
        $data = Database::fetchAll(
            "SELECT metric_value as value, recorded_at as time
             FROM metrics 
             WHERE metric_name = ? AND recorded_at > DATE_SUB(NOW(), $interval)
             ORDER BY recorded_at ASC",
            [$metric]
        );
    } else {
        // Liste des métriques disponibles
        $data = Database::fetchAll(
            "SELECT metric_name, 
                    AVG(metric_value) as avg_value,
                    MIN(metric_value) as min_value,
                    MAX(metric_value) as max_value,
                    COUNT(*) as sample_count
             FROM metrics 
             WHERE recorded_at > DATE_SUB(NOW(), $interval)
             GROUP BY metric_name"
        );
    }
    
    response(['metrics' => $data, 'period' => $period]);
}

// ============== DASHBOARD SÉCURITÉ ==============

// GET /security/dashboard - Vue d'ensemble sécurité
if ($method === 'GET' && $uri === '/security/dashboard') {
    $admin = requireAuth();
    
    // Alertes actives
    $activeAlerts = Database::fetchAll(
        "SELECT * FROM alerts WHERE is_resolved = 0 
         ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'warning' THEN 2 ELSE 3 END, created_at DESC
         LIMIT 5"
    );
    
    // Événements récents
    $recentEvents = Database::fetchAll(
        "SELECT se.*, a.email as admin_email
         FROM security_events se
         LEFT JOIN admins a ON se.admin_id = a.id
         ORDER BY se.created_at DESC
         LIMIT 10"
    );
    
    // Stats 24h
    $stats24h = [
        'loginAttempts' => Database::fetchColumn(
            "SELECT COUNT(*) FROM security_events WHERE event_type LIKE 'login%' AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        ),
        'loginFailures' => Database::fetchColumn(
            "SELECT COUNT(*) FROM security_events WHERE event_type = 'login_failed' AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        ),
        'apiRequests' => Database::fetchColumn(
            "SELECT COUNT(*) FROM audit_logs WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        ) ?: 0,
        'uniqueIPs' => Database::fetchColumn(
            "SELECT COUNT(DISTINCT ip_address) FROM security_events WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        ),
        'newAlerts' => Database::fetchColumn(
            "SELECT COUNT(*) FROM alerts WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        ) ?: 0
    ];
    
    // IPs suspectes
    $suspiciousIPs = Database::fetchAll(
        "SELECT ip_address, COUNT(*) as attempts
         FROM security_events 
         WHERE event_type IN ('login_failed', '2fa_validation_failed', 'suspicious_activity')
         AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
         GROUP BY ip_address 
         HAVING attempts >= 3
         ORDER BY attempts DESC
         LIMIT 5"
    );
    
    // Derniers backups
    $lastBackup = Database::fetch(
        "SELECT * FROM backups WHERE status = 'completed' ORDER BY created_at DESC LIMIT 1"
    );
    
    // Règles IP actives
    $ipRulesCount = [
        'whitelist' => Database::fetchColumn("SELECT COUNT(*) FROM ip_rules WHERE type = 'whitelist' AND (expires_at IS NULL OR expires_at > NOW())") ?: 0,
        'blacklist' => Database::fetchColumn("SELECT COUNT(*) FROM ip_rules WHERE type = 'blacklist' AND (expires_at IS NULL OR expires_at > NOW())") ?: 0
    ];
    
    response([
        'alerts' => [
            'active' => $activeAlerts,
            'criticalCount' => Database::fetchColumn("SELECT COUNT(*) FROM alerts WHERE is_resolved = 0 AND severity = 'critical'") ?: 0,
            'warningCount' => Database::fetchColumn("SELECT COUNT(*) FROM alerts WHERE is_resolved = 0 AND severity = 'warning'") ?: 0
        ],
        'events' => $recentEvents,
        'stats24h' => $stats24h,
        'suspiciousIPs' => $suspiciousIPs,
        'lastBackup' => $lastBackup,
        'ipRules' => $ipRulesCount,
        'timestamp' => date('Y-m-d H:i:s')
    ]);
}

// ============== FONCTIONS HELPERS ==============

/**
 * Log une action dans l'audit
 */
if (!function_exists('auditLog')) {
    function auditLog(?string $adminId, string $action, string $entityType, ?string $entityId = null, $oldValues = null, $newValues = null): void {
        try {
            Database::insert('audit_logs', [
                'id' => generateId('audit'),
                'admin_id' => $adminId,
                'action' => $action,
                'entity_type' => $entityType,
                'entity_id' => $entityId,
                'old_values' => $oldValues ? json_encode($oldValues) : null,
                'new_values' => $newValues ? json_encode($newValues) : null,
                'ip_address' => getClientIP(),
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
                'request_method' => $_SERVER['REQUEST_METHOD'] ?? null,
                'request_uri' => $_SERVER['REQUEST_URI'] ?? null
            ]);
        } catch (Exception $e) {
            error_log('Audit log failed: ' . $e->getMessage());
        }
    }
}

/**
 * Vérifie si une IP est autorisée
 */
if (!function_exists('checkIPAccess')) {
    function checkIPAccess(string $ip): array {
        // Vérifier la blacklist d'abord
        $blacklisted = Database::fetch(
            "SELECT * FROM ip_rules 
             WHERE type = 'blacklist' 
             AND (expires_at IS NULL OR expires_at > NOW())
             AND (ip_address = ? OR ? LIKE CONCAT(REPLACE(ip_address, '*', '%')))",
            [$ip, $ip]
        );
        
        if ($blacklisted) {
            return [
                'allowed' => false,
                'reason' => 'IP blacklistée',
                'rule' => $blacklisted
            ];
        }
        
        // Vérifier si whitelist est activée
        $whitelistCount = Database::fetchColumn(
            "SELECT COUNT(*) FROM ip_rules WHERE type = 'whitelist' AND (expires_at IS NULL OR expires_at > NOW())"
        );
        
        if ($whitelistCount > 0) {
            // Si whitelist existe, l'IP doit y être
            $whitelisted = Database::fetch(
                "SELECT * FROM ip_rules 
                 WHERE type = 'whitelist' 
                 AND (expires_at IS NULL OR expires_at > NOW())
                 AND (ip_address = ? OR ? LIKE CONCAT(REPLACE(ip_address, '*', '%')))",
                [$ip, $ip]
            );
            
            if (!$whitelisted) {
                return [
                    'allowed' => false,
                    'reason' => 'IP non whitelistée',
                    'rule' => null
                ];
            }
            
            return [
                'allowed' => true,
                'reason' => 'IP whitelistée',
                'rule' => $whitelisted
            ];
        }
        
        return [
            'allowed' => true,
            'reason' => 'Aucune restriction',
            'rule' => null
        ];
    }
}


// ============== 404 ==============

error('Endpoint non trouvé: ' . $method . ' ' . $uri, 404);
