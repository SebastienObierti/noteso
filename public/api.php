<?php
/**
 * NOTESO - API Backend MySQL 8
 * Dashboard Multi-Sites complet en PHP pur + PDO
 * v1.1 - Sécurité renforcée (2FA, Rate Limiting, Webhooks sécurisés)
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

ob_end_clean();

// Headers
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key, X-HTTP-Method-Override, X-Noteso-Signature, X-Noteso-Timestamp');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// ============== HELPERS ==============

function hashPassword(string $password): string {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);
}

function verifyPassword(string $password, string $hash): bool {
    return password_verify($password, $hash);
}

function generateToken(): string {
    return bin2hex(random_bytes(32));
}

function isStrongPassword(string $password): bool {
    if (strlen($password) < MIN_PASSWORD_LENGTH) return false;
    if (REQUIRE_UPPERCASE && !preg_match('/[A-Z]/', $password)) return false;
    if (REQUIRE_LOWERCASE && !preg_match('/[a-z]/', $password)) return false;
    if (REQUIRE_NUMBER && !preg_match('/[0-9]/', $password)) return false;
    if (REQUIRE_SPECIAL && !preg_match('/[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]/', $password)) return false;
    return true;
}

function getPasswordRequirements(): string {
    $requirements = [MIN_PASSWORD_LENGTH . ' caractères minimum'];
    if (REQUIRE_UPPERCASE) $requirements[] = 'une majuscule';
    if (REQUIRE_LOWERCASE) $requirements[] = 'une minuscule';
    if (REQUIRE_NUMBER) $requirements[] = 'un chiffre';
    if (REQUIRE_SPECIAL) $requirements[] = 'un caractère spécial';
    return implode(', ', $requirements);
}

function getClientIP(): string {
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($ips[0]);
    }
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function isIPBlocked(string $ip): bool {
    $cutoff = date('Y-m-d H:i:s', time() - LOCKOUT_DURATION);
    $count = Database::fetchColumn(
        "SELECT COUNT(*) FROM login_attempts 
         WHERE ip = ? AND success = 0 AND attempted_at > ?",
        [$ip, $cutoff]
    );
    return $count >= MAX_LOGIN_ATTEMPTS;
}

function recordLoginAttempt(string $ip, string $email, bool $success): void {
    Database::insert('login_attempts', [
        'email' => $email,
        'ip' => $ip,
        'success' => $success ? 1 : 0,
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
        'attempted_at' => date('Y-m-d H:i:s')
    ]);
    
    // Nettoyage des anciennes tentatives (> 24h)
    Database::query("DELETE FROM login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)");
}

function getRemainingLockoutTime(string $ip): int {
    $lastAttempt = Database::fetchColumn(
        "SELECT UNIX_TIMESTAMP(attempted_at) FROM login_attempts 
         WHERE ip = ? AND success = 0 ORDER BY attempted_at DESC LIMIT 1",
        [$ip]
    );
    if (!$lastAttempt) return 0;
    $remaining = LOCKOUT_DURATION - (time() - $lastAttempt);
    return max(0, $remaining);
}

function cleanExpiredSessions(): void {
    Database::query("DELETE FROM sessions WHERE expires_at < NOW()");
}

function getInput(): array {
    return json_decode(file_get_contents('php://input'), true) ?: [];
}

function response(mixed $data, int $code = 200): never {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function error(string $message, int $code = 400): never {
    response(['error' => $message], $code);
}

function getAuthAdmin(): ?array {
    $headers = getallheaders();
    $token = str_replace('Bearer ', '', $headers['Authorization'] ?? '');
    
    if (!$token) return null;
    
    $session = Database::fetch(
        "SELECT s.*, a.* FROM sessions s 
         JOIN admins a ON s.admin_id = a.id 
         WHERE s.token = ? AND s.expires_at > NOW()",
        [$token]
    );
    
    if (!$session) return null;
    
    // Reformater pour compatibilité
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

// Appliquer le rate limiting (si activé et classe disponible)
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
$uri = preg_replace('#^/api(?=/|$)#', '', $uri); // Ne matche que /api/ ou /api en fin, pas /api-keys
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

// ============== AUTH ROUTES ==============

if ($method === 'POST' && $uri === '/auth/login') {
    $input = getInput();
    $email = strtolower(trim($input['email'] ?? ''));
    $password = $input['password'] ?? '';
    $ip = getClientIP();
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
    
    if (isIPBlocked($ip)) {
        $remaining = getRemainingLockoutTime($ip);
        $minutes = ceil($remaining / 60);
        logSecurityEvent('login_blocked', "IP bloquée: $email", null, $ip);
        error("Trop de tentatives. Réessayez dans $minutes minute(s).", 429);
    }
    
    if (!$email || !$password) {
        error('Email et mot de passe requis');
    }
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        recordLoginAttempt($ip, $email, false);
        error('Format email invalide');
    }
    
    $admin = Database::fetch("SELECT * FROM admins WHERE LOWER(email) = ?", [$email]);
    
    if (!$admin || !verifyPassword($password, $admin['password'])) {
        recordLoginAttempt($ip, $email, false);
        logSecurityEvent('login_failed', "Échec connexion: $email", null, $ip);
        error('Identifiants incorrects', 401);
    }
    
    // Succès de l'authentification par mot de passe
    recordLoginAttempt($ip, $email, true);
    
    // Mettre à jour last login
    Database::update('admins', [
        'last_login_at' => date('Y-m-d H:i:s'),
        'last_login_ip' => $ip
    ], ['id' => $admin['id']]);
    
    cleanExpiredSessions();
    
    // Créer session
    $token = generateToken();
    $sessionId = generateId('sess');
    $deviceName = parseDeviceName($userAgent);
    $deviceType = parseDeviceType($userAgent);
    
    Database::insert('sessions', [
        'id' => $sessionId,
        'admin_id' => $admin['id'],
        'token' => $token,
        'ip' => $ip,
        'user_agent' => $userAgent,
        'device_name' => $deviceName,
        'device_type' => $deviceType,
        'last_activity_at' => date('Y-m-d H:i:s'),
        'is_current' => $admin['two_factor_enabled'] ? 0 : 1, // Si 2FA, pas encore validé
        'created_at' => date('Y-m-d H:i:s'),
        'expires_at' => date('Y-m-d H:i:s', time() + SESSION_DURATION)
    ]);
    
    // Vérifier si 2FA est activé
    if ($admin['two_factor_enabled']) {
        logSecurityEvent('login_2fa_required', "Connexion nécessite 2FA: $email", $admin['id'], $ip);
        
        response([
            'requires2FA' => true,
            'tempToken' => $token,
            'message' => 'Veuillez entrer votre code d\'authentification'
        ]);
    }
    
    logSecurityEvent('login_success', "Connexion réussie: $email", $admin['id'], $ip);
    
    response([
        'token' => $token,
        'expiresIn' => SESSION_DURATION,
        'requires2FA' => false,
        'admin' => [
            'id' => $admin['id'],
            'email' => $admin['email'],
            'firstName' => $admin['first_name'],
            'lastName' => $admin['last_name'],
            'role' => $admin['role'],
            'permissions' => json_decode($admin['permissions'] ?? '[]', true)
        ]
    ]);
}

if ($method === 'POST' && $uri === '/auth/logout') {
    $headers = getallheaders();
    $token = str_replace('Bearer ', '', $headers['Authorization'] ?? '');
    
    Database::delete('sessions', ['token' => $token]);
    logSecurityEvent('logout', 'Déconnexion');
    
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

if ($method === 'PUT' && $uri === '/auth/password') {
    $admin = requireAuth();
    $input = getInput();
    
    $currentPassword = $input['currentPassword'] ?? '';
    $newPassword = $input['newPassword'] ?? '';
    $confirmPassword = $input['confirmPassword'] ?? '';
    
    if (!$currentPassword || !$newPassword || !$confirmPassword) {
        error('Tous les champs sont requis');
    }
    
    if ($newPassword !== $confirmPassword) {
        error('Les mots de passe ne correspondent pas');
    }
    
    if (!isStrongPassword($newPassword)) {
        error('Le mot de passe doit contenir: ' . getPasswordRequirements());
    }
    
    $dbAdmin = Database::find('admins', $admin['id']);
    if (!verifyPassword($currentPassword, $dbAdmin['password'])) {
        logSecurityEvent('password_change_failed', 'Mot de passe actuel incorrect', $admin['id']);
        error('Mot de passe actuel incorrect');
    }
    
    Database::update('admins', [
        'password' => hashPassword($newPassword),
        'password_changed_at' => date('Y-m-d H:i:s')
    ], ['id' => $admin['id']]);
    
    // Invalider autres sessions
    $currentToken = str_replace('Bearer ', '', getallheaders()['Authorization'] ?? '');
    Database::query(
        "DELETE FROM sessions WHERE admin_id = ? AND token != ?",
        [$admin['id'], $currentToken]
    );
    
    logSecurityEvent('password_changed', 'Mot de passe modifié', $admin['id']);
    
    response(['success' => true, 'message' => 'Mot de passe modifié avec succès']);
}

if ($method === 'GET' && $uri === '/auth/sessions') {
    $admin = requireAuth();
    $currentToken = str_replace('Bearer ', '', getallheaders()['Authorization'] ?? '');
    
    $sessions = Database::fetchAll(
        "SELECT id, ip, user_agent, created_at, expires_at, token 
         FROM sessions WHERE admin_id = ? AND expires_at > NOW()",
        [$admin['id']]
    );
    
    $result = array_map(fn($s) => [
        'id' => $s['id'],
        'ip' => $s['ip'],
        'userAgent' => $s['user_agent'],
        'createdAt' => $s['created_at'],
        'expiresAt' => $s['expires_at'],
        'current' => $s['token'] === $currentToken
    ], $sessions);
    
    response($result);
}

if ($method === 'DELETE' && $uri === '/auth/sessions') {
    $admin = requireAuth();
    $input = getInput();
    $sessionId = $input['sessionId'] ?? null;
    $currentToken = str_replace('Bearer ', '', getallheaders()['Authorization'] ?? '');
    
    if ($sessionId) {
        Database::query(
            "DELETE FROM sessions WHERE id = ? AND admin_id = ? AND token != ?",
            [$sessionId, $admin['id'], $currentToken]
        );
    } else {
        Database::query(
            "DELETE FROM sessions WHERE admin_id = ? AND token != ?",
            [$admin['id'], $currentToken]
        );
    }
    
    logSecurityEvent('sessions_revoked', $sessionId ? 'Session révoquée' : 'Toutes les autres sessions révoquées', $admin['id']);
    
    response(['success' => true]);
}

if ($method === 'GET' && $uri === '/auth/password-requirements') {
    response([
        'minLength' => MIN_PASSWORD_LENGTH,
        'requireUppercase' => REQUIRE_UPPERCASE,
        'requireLowercase' => REQUIRE_LOWERCASE,
        'requireNumber' => REQUIRE_NUMBER,
        'requireSpecial' => REQUIRE_SPECIAL,
        'description' => getPasswordRequirements()
    ]);
}

// ============== MOT DE PASSE OUBLIÉ ==============

if ($method === 'POST' && $uri === '/auth/forgot-password') {
    $input = getInput();
    $email = strtolower(trim($input['email'] ?? ''));
    
    // Toujours répondre pareil pour la sécurité
    if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        response(['success' => true, 'message' => 'Si un compte existe avec cette adresse, un email sera envoyé.']);
    }
    
    $admin = Database::fetch("SELECT * FROM admins WHERE LOWER(email) = ?", [$email]);
    
    if ($admin) {
        $resetToken = bin2hex(random_bytes(32));
        $expiresAt = date('Y-m-d H:i:s', time() + 3600);
        
        // Supprimer anciens tokens et créer nouveau
        Database::query("DELETE FROM password_resets WHERE admin_id = ?", [$admin['id']]);
        Database::query(
            "INSERT INTO password_resets (id, admin_id, email, token, expires_at, created_at) VALUES (?, ?, ?, ?, ?, NOW())",
            [generateId('rst'), $admin['id'], $email, $resetToken, $expiresAt]
        );
        
        // Construire le lien
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $resetLink = "{$protocol}://{$host}/?reset_token={$resetToken}";
        
        // Email HTML
        $htmlBody = "
        <!DOCTYPE html>
        <html><head><meta charset='UTF-8'></head>
        <body style='font-family:Inter,Arial,sans-serif;background:#f8fafc;padding:40px;'>
            <div style='max-width:500px;margin:0 auto;background:white;border-radius:16px;padding:40px;box-shadow:0 4px 20px rgba(0,0,0,0.1);'>
                <div style='text-align:center;margin-bottom:30px;'>
                    <div style='width:60px;height:60px;background:linear-gradient(135deg,#3b82f6,#8b5cf6);border-radius:12px;display:inline-flex;align-items:center;justify-content:center;color:white;font-weight:bold;font-size:24px;'>N</div>
                </div>
                <h1 style='text-align:center;color:#0f172a;margin-bottom:16px;'>Réinitialisation du mot de passe</h1>
                <p style='color:#64748b;text-align:center;margin-bottom:30px;'>Vous avez demandé la réinitialisation de votre mot de passe Noteso.</p>
                <div style='text-align:center;margin-bottom:30px;'>
                    <a href='{$resetLink}' style='display:inline-block;background:linear-gradient(135deg,#3b82f6,#8b5cf6);color:white;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:600;'>Réinitialiser mon mot de passe</a>
                </div>
                <p style='color:#94a3b8;font-size:13px;text-align:center;'>Ce lien expire dans 1 heure.</p>
            </div>
        </body></html>";
        
        // Envoyer email (fonction à implémenter selon votre config SMTP)
        @mail($email, '[Noteso] Réinitialisation de mot de passe', $htmlBody, "Content-Type: text/html; charset=UTF-8\r\nFrom: Noteso <noreply@noteso.fr>");
        
        logSecurityEvent('password_reset_requested', "Demande réinitialisation: $email", null);
        error_log("[NOTESO] Reset link for {$email}: {$resetLink}");
    }
    
    response(['success' => true, 'message' => 'Si un compte existe avec cette adresse, un email sera envoyé.']);
}

if ($method === 'POST' && $uri === '/auth/reset-password') {
    $input = getInput();
    $token = trim($input['token'] ?? '');
    $newPassword = $input['password'] ?? '';
    $confirmPassword = $input['confirmPassword'] ?? '';
    
    if (!$token) error('Token de réinitialisation manquant', 400);
    if (!$newPassword || !$confirmPassword) error('Le mot de passe est requis', 400);
    if ($newPassword !== $confirmPassword) error('Les mots de passe ne correspondent pas', 400);
    if (!isStrongPassword($newPassword)) error('Le mot de passe doit contenir: ' . getPasswordRequirements(), 400);
    
    // Vérifier token
    $resetData = Database::fetch(
        "SELECT * FROM password_resets WHERE token = ? AND used = 0 AND expires_at > NOW()",
        [$token]
    );
    
    if (!$resetData) {
        logSecurityEvent('password_reset_invalid_token', 'Token invalide ou expiré');
        error('Lien de réinitialisation invalide ou expiré.', 400);
    }
    
    // Mettre à jour le mot de passe
    Database::update('admins', [
        'password' => hashPassword($newPassword),
        'password_changed_at' => date('Y-m-d H:i:s')
    ], ['id' => $resetData['admin_id']]);
    
    // Marquer token utilisé
    Database::query("UPDATE password_resets SET used = 1, used_at = NOW() WHERE id = ?", [$resetData['id']]);
    
    // Invalider toutes les sessions
    Database::delete('sessions', ['admin_id' => $resetData['admin_id']]);
    
    logSecurityEvent('password_reset_success', "Mot de passe réinitialisé: {$resetData['email']}", $resetData['admin_id']);
    
    response(['success' => true, 'message' => 'Mot de passe réinitialisé avec succès.']);
}

// ============== 2FA (Authentification à deux facteurs) ==============

// GET /auth/2fa/status - Vérifier si 2FA est activé
if ($method === 'GET' && $uri === '/auth/2fa/status') {
    $admin = requireAuth();
    
    $adminData = Database::find('admins', $admin['id']);
    
    response([
        'enabled' => (bool)($adminData['two_factor_enabled'] ?? false),
        'verifiedAt' => $adminData['two_factor_verified_at'] ?? null
    ]);
}

// POST /auth/2fa/setup - Initialiser le 2FA
if ($method === 'POST' && $uri === '/auth/2fa/setup') {
    $admin = requireAuth();
    
    if (!class_exists('TOTP')) {
        error('2FA non disponible sur ce serveur', 503);
    }
    
    // Générer un nouveau secret
    $secret = TOTP::generateSecret();
    
    // Générer les backup codes
    $backupCodes = TOTP::generateBackupCodes(8);
    
    // Sauvegarder temporairement (non activé tant que pas vérifié)
    Database::update('admins', [
        'two_factor_secret' => $secret,
        'backup_codes' => json_encode($backupCodes)
    ], ['id' => $admin['id']]);
    
    // Générer l'URL du QR code
    $qrCodeUrl = TOTP::getQRCodeImageUrl($secret, $admin['email'], 'Noteso');
    $otpauthUrl = TOTP::getQRCodeUrl($secret, $admin['email'], 'Noteso');
    
    response([
        'secret' => $secret,
        'qrCode' => $qrCodeUrl,
        'otpauth' => $otpauthUrl,
        'backupCodes' => $backupCodes
    ]);
}

// GET /auth/2fa/debug - Route de debug temporaire (À SUPPRIMER EN PROD)
if ($method === 'GET' && $uri === '/auth/2fa/debug') {
    $admin = requireAuth();
    
    if (!class_exists('TOTP')) {
        error('2FA non disponible', 503);
    }
    
    $adminData = Database::find('admins', $admin['id']);
    $secret = $adminData['two_factor_secret'] ?? '';
    
    if (!$secret) {
        error('Pas de secret 2FA configuré', 400);
    }
    
    // Générer le code actuel
    $currentCode = TOTP::generateCode($secret);
    $serverTime = time();
    $timeSlice = (int)floor($serverTime / 30);
    
    response([
        'secret' => $secret,
        'currentCode' => $currentCode,
        'serverTime' => $serverTime,
        'serverTimeFormatted' => date('Y-m-d H:i:s', $serverTime),
        'timeSlice' => $timeSlice,
        'nextCodeIn' => 30 - ($serverTime % 30)
    ]);
}

// POST /auth/2fa/verify - Vérifier et activer le 2FA
if ($method === 'POST' && $uri === '/auth/2fa/verify') {
    $admin = requireAuth();
    $input = getInput();
    $code = $input['code'] ?? '';
    
    if (!class_exists('TOTP')) {
        error('2FA non disponible sur ce serveur', 503);
    }
    
    $adminData = Database::find('admins', $admin['id']);
    $secret = $adminData['two_factor_secret'] ?? '';
    
    if (!$secret) {
        error('Veuillez d\'abord initialiser le 2FA', 400);
    }
    
    // Vérifier le code
    if (!TOTP::verify($secret, $code)) {
        logSecurityEvent('2fa_verification_failed', 'Tentative de vérification 2FA échouée', $admin['id']);
        error('Code invalide', 400);
    }
    
    // Activer le 2FA
    Database::update('admins', [
        'two_factor_enabled' => 1,
        'two_factor_verified_at' => date('Y-m-d H:i:s')
    ], ['id' => $admin['id']]);
    
    logSecurityEvent('2fa_enabled', 'Authentification à deux facteurs activée', $admin['id']);
    addNotification('success', 'Sécurité', 'L\'authentification à deux facteurs est maintenant activée');
    
    response(['success' => true, 'message' => '2FA activé avec succès']);
}

// POST /auth/2fa/validate - Valider un code 2FA (lors de la connexion)
if ($method === 'POST' && $uri === '/auth/2fa/validate') {
    $input = getInput();
    $tempToken = $input['tempToken'] ?? '';
    $code = $input['code'] ?? '';
    
    if (!$tempToken || !$code) {
        error('Token et code requis', 400);
    }
    
    // Récupérer la session temporaire
    $tempSession = Database::fetch(
        "SELECT * FROM sessions WHERE token = ? AND expires_at > NOW()",
        [$tempToken]
    );
    
    if (!$tempSession) {
        error('Session expirée, veuillez vous reconnecter', 401);
    }
    
    $adminData = Database::find('admins', $tempSession['admin_id']);
    $secret = $adminData['two_factor_secret'] ?? '';
    
    // Vérifier le code TOTP
    $valid = false;
    if (class_exists('TOTP') && TOTP::verify($secret, $code)) {
        $valid = true;
    }
    
    // Si pas valide, vérifier les backup codes
    if (!$valid) {
        $backupCodes = json_decode($adminData['backup_codes'] ?? '[]', true);
        $usedIndex = TOTP::verifyBackupCode($code, $backupCodes);
        
        if ($usedIndex !== null) {
            $valid = true;
            // Invalider le backup code utilisé
            $backupCodes[$usedIndex] = null;
            Database::update('admins', [
                'backup_codes' => json_encode($backupCodes)
            ], ['id' => $adminData['id']]);
            
            logSecurityEvent('2fa_backup_code_used', 'Code de secours utilisé', $adminData['id']);
        }
    }
    
    if (!$valid) {
        logSecurityEvent('2fa_validation_failed', 'Tentative de validation 2FA échouée', $adminData['id']);
        error('Code invalide', 401);
    }
    
    // Marquer la session comme complètement authentifiée
    Database::update('sessions', [
        'is_current' => 1
    ], ['token' => $tempToken]);
    
    logSecurityEvent('2fa_validation_success', 'Validation 2FA réussie', $adminData['id']);
    
    response([
        'success' => true,
        'token' => $tempToken,
        'admin' => [
            'id' => $adminData['id'],
            'email' => $adminData['email'],
            'firstName' => $adminData['first_name'],
            'lastName' => $adminData['last_name'],
            'role' => $adminData['role']
        ]
    ]);
}

// POST /auth/2fa/disable - Désactiver le 2FA
if ($method === 'POST' && $uri === '/auth/2fa/disable') {
    $admin = requireAuth();
    $input = getInput();
    $password = $input['password'] ?? '';
    
    if (!$password) {
        error('Mot de passe requis pour désactiver le 2FA', 400);
    }
    
    $adminData = Database::find('admins', $admin['id']);
    
    if (!verifyPassword($password, $adminData['password'])) {
        logSecurityEvent('2fa_disable_failed', 'Tentative de désactivation 2FA avec mauvais mot de passe', $admin['id']);
        error('Mot de passe incorrect', 401);
    }
    
    Database::update('admins', [
        'two_factor_enabled' => 0,
        'two_factor_secret' => null,
        'two_factor_verified_at' => null,
        'backup_codes' => null
    ], ['id' => $admin['id']]);
    
    logSecurityEvent('2fa_disabled', 'Authentification à deux facteurs désactivée', $admin['id']);
    addNotification('warning', 'Sécurité', 'L\'authentification à deux facteurs a été désactivée');
    
    response(['success' => true, 'message' => '2FA désactivé']);
}

// GET /auth/2fa/backup-codes - Régénérer les codes de secours
if ($method === 'GET' && $uri === '/auth/2fa/backup-codes') {
    $admin = requireAuth();
    
    $adminData = Database::find('admins', $admin['id']);
    
    if (!$adminData['two_factor_enabled']) {
        error('Le 2FA n\'est pas activé', 400);
    }
    
    // Générer de nouveaux codes
    $backupCodes = TOTP::generateBackupCodes(8);
    
    Database::update('admins', [
        'backup_codes' => json_encode($backupCodes)
    ], ['id' => $admin['id']]);
    
    logSecurityEvent('2fa_backup_codes_regenerated', 'Codes de secours régénérés', $admin['id']);
    
    response(['backupCodes' => $backupCodes]);
}

// ============== SESSIONS ==============

// GET /auth/sessions - Liste des sessions actives
if ($method === 'GET' && $uri === '/auth/sessions') {
    $admin = requireAuth();
    $currentToken = str_replace('Bearer ', '', getallheaders()['Authorization'] ?? '');
    
    $sessions = Database::fetchAll(
        "SELECT * FROM sessions WHERE admin_id = ? AND expires_at > NOW() ORDER BY created_at DESC",
        [$admin['id']]
    );
    
    $result = array_map(function($s) use ($currentToken) {
        return [
            'id' => $s['id'],
            'deviceName' => $s['device_name'] ?? self::parseDeviceName($s['user_agent']),
            'deviceType' => $s['device_type'] ?? 'unknown',
            'ip' => $s['ip'],
            'location' => $s['location'],
            'lastActivity' => $s['last_activity_at'] ?? $s['created_at'],
            'createdAt' => $s['created_at'],
            'isCurrent' => $s['token'] === $currentToken
        ];
    }, $sessions);
    
    response($result);
}

// DELETE /auth/sessions/{id} - Révoquer une session
if ($method === 'DELETE' && ($params = matchRoute('/auth/sessions/{id}', $uri))) {
    $admin = requireAuth();
    
    $session = Database::fetch(
        "SELECT * FROM sessions WHERE id = ? AND admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    if (!$session) {
        error('Session non trouvée', 404);
    }
    
    Database::delete('sessions', ['id' => $params['id']]);
    
    logSecurityEvent('session_revoked', 'Session révoquée', $admin['id']);
    
    response(['success' => true]);
}

// DELETE /auth/sessions - Révoquer toutes les autres sessions
if ($method === 'DELETE' && $uri === '/auth/sessions') {
    $admin = requireAuth();
    $currentToken = str_replace('Bearer ', '', getallheaders()['Authorization'] ?? '');
    
    Database::query(
        "DELETE FROM sessions WHERE admin_id = ? AND token != ?",
        [$admin['id'], $currentToken]
    );
    
    logSecurityEvent('all_sessions_revoked', 'Toutes les autres sessions révoquées', $admin['id']);
    
    response(['success' => true, 'message' => 'Toutes les autres sessions ont été révoquées']);
}

// Helper pour parser le user agent
function parseDeviceName(?string $userAgent): string {
    if (!$userAgent) return 'Appareil inconnu';
    
    if (strpos($userAgent, 'iPhone') !== false) return 'iPhone';
    if (strpos($userAgent, 'iPad') !== false) return 'iPad';
    if (strpos($userAgent, 'Android') !== false) return 'Android';
    if (strpos($userAgent, 'Windows') !== false) return 'Windows';
    if (strpos($userAgent, 'Mac') !== false) return 'Mac';
    if (strpos($userAgent, 'Linux') !== false) return 'Linux';
    
    return 'Navigateur Web';
}

function parseDeviceType(?string $userAgent): string {
    if (!$userAgent) return 'unknown';
    
    if (preg_match('/Mobile|iPhone|Android.*Mobile/i', $userAgent)) return 'mobile';
    if (preg_match('/iPad|Tablet|Android(?!.*Mobile)/i', $userAgent)) return 'tablet';
    
    return 'desktop';
}

// ============== SECURITY EVENTS (Logs de sécurité) ==============

// GET /security/events - Liste des événements de sécurité
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

// GET /security/login-history - Historique des connexions
if ($method === 'GET' && $uri === '/security/login-history') {
    $admin = requireAuth();
    $limit = (int)($_GET['limit'] ?? 20);
    
    $events = Database::fetchAll(
        "SELECT * FROM security_events 
         WHERE admin_id = ? AND event_type IN ('login', 'login_failed', '2fa_validation_success')
         ORDER BY created_at DESC LIMIT ?",
        [$admin['id'], $limit]
    );
    
    $result = array_map(fn($e) => [
        'type' => $e['event_type'],
        'success' => $e['event_type'] !== 'login_failed',
        'ip' => $e['ip_address'],
        'location' => $e['location'],
        'userAgent' => $e['user_agent'],
        'createdAt' => $e['created_at']
    ], $events);
    
    response($result);
}

// ============== DASHBOARD ==============

if ($method === 'GET' && $uri === '/dashboard/overview') {
    $now = time();
    $thisMonth = date('Y-m-01');
    $lastMonthStart = date('Y-m-01', strtotime('-1 month'));
    $lastMonthEnd = date('Y-m-t', strtotime('-1 month'));
    
    // Stats globales
    $totalUsers = Database::count('users');
    $totalSites = Database::count('sites');
    $activeSites = Database::count('sites', ['status' => 'online']);
    
    // Revenus
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
    
    // Paiements
    $thisMonthPayments = Database::fetchColumn(
        "SELECT COUNT(*) FROM payments WHERE status = 'completed' AND created_at >= ?",
        [$thisMonth]
    );
    
    $lastMonthPayments = Database::fetchColumn(
        "SELECT COUNT(*) FROM payments 
         WHERE status = 'completed' AND created_at >= ? AND created_at <= ?",
        [$lastMonthStart, $lastMonthEnd . ' 23:59:59']
    );
    
    // Users
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
    
    $calcTrend = fn($current, $previous) => $previous > 0 ? round(($current - $previous) / $previous * 100, 1) : 0;
    
    response([
        'totalUsers' => $totalUsers,
        'usersTrend' => $calcTrend($thisMonthUsers, $lastMonthUsers),
        'monthlyPayments' => $thisMonthPayments,
        'paymentsTrend' => $calcTrend($thisMonthPayments, $lastMonthPayments),
        'totalRevenue' => round($totalRevenue, 2),
        'revenueTrend' => $calcTrend($thisMonthRevenue, $lastMonthRevenue),
        'activeSites' => $activeSites,
        'totalSites' => $totalSites,
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
        
        // Uptime depuis monitoring
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
    $apiKey = 'ek_' . generateId();
    $webhookSecret = bin2hex(random_bytes(16)); // 32 caractères hex
    
    Database::insert('sites', [
        'id' => $id,
        'name' => $input['name'],
        'url' => $input['url'],
        'status' => 'online',
        'color' => $input['color'] ?? '#3b82f6',
        'api_key' => $apiKey,
        'webhook_secret' => $webhookSecret,
        'settings' => json_encode(['currency' => 'EUR', 'timezone' => 'Europe/Paris']),
        'created_at' => date('Y-m-d H:i:s')
    ]);
    
    $site = Database::find('sites', $id);
    
    logActivity($id, null, 'site_created', 'Nouveau site créé: ' . $input['name']);
    addNotification('success', 'Site créé', $input['name'] . ' a été ajouté.');
    
    response([
        'id' => $site['id'],
        'name' => $site['name'],
        'url' => $site['url'],
        'status' => $site['status'],
        'color' => $site['color'],
        'createdAt' => $site['created_at'],
        'apiKey' => $site['api_key'],
        'webhookSecret' => $site['webhook_secret'],
        'settings' => json_decode($site['settings'], true)
    ], 201);
}

if ($method === 'PUT' && ($params = matchRoute('/sites/{id}', $uri))) {
    $input = getInput();
    $site = Database::find('sites', $params['id']);
    if (!$site) error('Site non trouvé', 404);
    
    $updateData = [];
    if (isset($input['name'])) $updateData['name'] = $input['name'];
    if (isset($input['url'])) $updateData['url'] = $input['url'];
    if (isset($input['status'])) $updateData['status'] = $input['status'];
    if (isset($input['color'])) $updateData['color'] = $input['color'];
    if (isset($input['settings'])) $updateData['settings'] = json_encode($input['settings']);
    
    if (!empty($updateData)) {
        Database::update('sites', $updateData, ['id' => $params['id']]);
    }
    
    $site = Database::find('sites', $params['id']);
    logActivity($params['id'], null, 'site_updated', 'Site modifié: ' . $site['name']);
    
    response([
        'id' => $site['id'],
        'name' => $site['name'],
        'url' => $site['url'],
        'status' => $site['status'],
        'color' => $site['color'],
        'createdAt' => $site['created_at'],
        'apiKey' => $site['api_key'],
        'settings' => json_decode($site['settings'], true)
    ]);
}

if ($method === 'DELETE' && ($params = matchRoute('/sites/{id}', $uri))) {
    $site = Database::find('sites', $params['id']);
    if (!$site) error('Site non trouvé', 404);
    
    // Cascade delete via FK, mais on log avant
    logActivity($params['id'], null, 'site_deleted', 'Site supprimé: ' . $site['name']);
    
    Database::delete('sites', ['id' => $params['id']]);
    
    response(['success' => true, 'site' => [
        'id' => $site['id'],
        'name' => $site['name']
    ]]);
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
        $where[] = "site_id = ?";
        $params[] = $siteId;
    }
    if ($status) {
        $where[] = "JSON_EXTRACT(metadata, '$.status') = ?";
        $params[] = $status;
    }
    if ($search) {
        $where[] = "(email LIKE ? OR name LIKE ?)";
        $params[] = "%$search%";
        $params[] = "%$search%";
    }
    
    $whereClause = !empty($where) ? 'WHERE ' . implode(' AND ', $where) : '';
    
    $total = Database::fetchColumn("SELECT COUNT(*) FROM users $whereClause", $params);
    
    $users = Database::fetchAll(
        "SELECT u.*, s.name as site_name FROM users u 
         LEFT JOIN sites s ON u.site_id = s.id
         $whereClause ORDER BY u.created_at DESC LIMIT ? OFFSET ?",
        array_merge($params, [$limit, $offset])
    );
    
    $result = array_map(fn($u) => [
        'id' => $u['id'],
        'siteId' => $u['site_id'],
        'siteName' => $u['site_name'],
        'email' => $u['email'],
        'name' => $u['name'],
        'externalId' => $u['external_id'],
        'metadata' => json_decode($u['metadata'] ?? '{}', true),
        'createdAt' => $u['created_at'],
        'updatedAt' => $u['updated_at']
    ], $users);
    
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
    
    // Correction: gérer le cas où whereClause est vide
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
            'siteName' => $a['site_name'] ?? 'Système',
            'type' => $a['type'],
            'message' => $a['description'],
            'details' => $metadata['details'] ?? null,
            'createdAt' => $a['created_at']
        ];
    }, $activities);
    
    response($result);
}

// ============== NOTIFICATIONS ==============

if ($method === 'GET' && $uri === '/notifications') {
    $notifications = Database::fetchAll(
        "SELECT * FROM notifications ORDER BY created_at DESC LIMIT 50"
    );
    
    $result = array_map(fn($n) => [
        'id' => $n['id'],
        'type' => $n['type'],
        'title' => $n['title'],
        'message' => $n['message'],
        'read' => (bool)$n['is_read'],
        'createdAt' => $n['created_at']
    ], $notifications);
    
    response($result);
}

if ($method === 'PUT' && ($params = matchRoute('/notifications/{id}/read', $uri))) {
    Database::update('notifications', [
        'is_read' => 1,
        'read_at' => date('Y-m-d H:i:s')
    ], ['id' => $params['id']]);
    
    response(['success' => true]);
}

if ($method === 'PUT' && $uri === '/notifications/read-all') {
    Database::query("UPDATE notifications SET is_read = 1, read_at = NOW() WHERE is_read = 0");
    response(['success' => true]);
}

// GET /notifications/settings - Paramètres de notifications
if ($method === 'GET' && $uri === '/notifications/settings') {
    $admin = getAuthAdmin();
    
    // Récupérer les paramètres depuis notification_settings ou créer défaut
    $settings = null;
    if ($admin) {
        $settings = Database::fetch(
            "SELECT * FROM notification_settings WHERE admin_id = ?",
            [$admin['id']]
        );
    }
    
    if ($settings) {
        response([
            'email' => [
                'enabled' => (bool)$settings['email_enabled'],
                'address' => $settings['email_address']
            ],
            'slack' => [
                'enabled' => (bool)$settings['slack_enabled'],
                'webhookUrl' => $settings['slack_webhook_url']
            ],
            'discord' => [
                'enabled' => (bool)$settings['discord_enabled'],
                'webhookUrl' => $settings['discord_webhook_url']
            ],
            'reports' => [
                'daily' => (bool)$settings['report_daily'],
                'weekly' => (bool)$settings['report_weekly'],
                'monthly' => (bool)$settings['report_monthly']
            ]
        ]);
    }
    
    // Paramètres par défaut
    response([
        'email' => ['enabled' => false, 'address' => ''],
        'slack' => ['enabled' => false, 'webhookUrl' => ''],
        'discord' => ['enabled' => false, 'webhookUrl' => ''],
        'reports' => ['daily' => false, 'weekly' => true, 'monthly' => true]
    ]);
}

// PUT /notifications/settings - Mettre à jour les paramètres
if ($method === 'PUT' && $uri === '/notifications/settings') {
    $admin = requireAuth();
    $input = getInput();
    
    // Construire les données à mettre à jour
    $data = ['admin_id' => $admin['id']];
    
    if (isset($input['email'])) {
        if (isset($input['email']['enabled'])) $data['email_enabled'] = $input['email']['enabled'] ? 1 : 0;
        if (isset($input['email']['address'])) $data['email_address'] = $input['email']['address'];
    }
    if (isset($input['slack'])) {
        if (isset($input['slack']['enabled'])) $data['slack_enabled'] = $input['slack']['enabled'] ? 1 : 0;
        if (isset($input['slack']['webhookUrl'])) $data['slack_webhook_url'] = $input['slack']['webhookUrl'];
    }
    if (isset($input['discord'])) {
        if (isset($input['discord']['enabled'])) $data['discord_enabled'] = $input['discord']['enabled'] ? 1 : 0;
        if (isset($input['discord']['webhookUrl'])) $data['discord_webhook_url'] = $input['discord']['webhookUrl'];
    }
    if (isset($input['reports'])) {
        if (isset($input['reports']['daily'])) $data['report_daily'] = $input['reports']['daily'] ? 1 : 0;
        if (isset($input['reports']['weekly'])) $data['report_weekly'] = $input['reports']['weekly'] ? 1 : 0;
        if (isset($input['reports']['monthly'])) $data['report_monthly'] = $input['reports']['monthly'] ? 1 : 0;
    }
    
    // Upsert
    $existing = Database::fetch("SELECT id FROM notification_settings WHERE admin_id = ?", [$admin['id']]);
    
    if ($existing) {
        unset($data['admin_id']);
        Database::update('notification_settings', $data, ['admin_id' => $admin['id']]);
    } else {
        $data['id'] = generateId('notif_settings');
        Database::insert('notification_settings', $data);
    }
    
    response(['success' => true]);
}

// POST /notifications/test - Tester une notification
if ($method === 'POST' && $uri === '/notifications/test') {
    $admin = requireAuth();
    $input = getInput();
    $channel = $input['channel'] ?? 'email';
    
    $settings = Database::fetch(
        "SELECT * FROM notification_settings WHERE admin_id = ?",
        [$admin['id']]
    );
    
    if (!$settings) {
        error('Aucun paramètre de notification configuré', 400);
    }
    
    $success = false;
    $message = '';
    
    switch ($channel) {
        case 'slack':
            $webhookUrl = $settings['slack_webhook_url'] ?? '';
            if (!$webhookUrl) {
                error('URL Slack non configurée', 400);
            }
            // Envoyer notification test Slack
            $payload = json_encode([
                'text' => '🔔 Test Noteso - Notification configurée avec succès!',
                'username' => 'Noteso',
                'icon_emoji' => ':bell:'
            ]);
            $ch = curl_init($webhookUrl);
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $payload,
                CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 10
            ]);
            $result = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            $success = $httpCode >= 200 && $httpCode < 300;
            $message = $success ? 'Notification Slack envoyée' : 'Erreur Slack: ' . $result;
            break;
            
        case 'discord':
            $webhookUrl = $settings['discord_webhook_url'] ?? '';
            if (!$webhookUrl) {
                error('URL Discord non configurée', 400);
            }
            // Envoyer notification test Discord
            $payload = json_encode([
                'content' => '🔔 **Test Noteso** - Notification configurée avec succès!',
                'username' => 'Noteso'
            ]);
            $ch = curl_init($webhookUrl);
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $payload,
                CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 10
            ]);
            $result = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            $success = $httpCode >= 200 && $httpCode < 300;
            $message = $success ? 'Notification Discord envoyée' : 'Erreur Discord';
            break;
            
        case 'email':
        default:
            $email = $settings['email_address'] ?? $admin['email'];
            if (!$email) {
                error('Email non configuré', 400);
            }
            // Envoyer email test
            $subject = '[Noteso] Test de notification';
            $body = '<html><body style="font-family:Arial,sans-serif;"><h2>🔔 Test Noteso</h2><p>Vos notifications email sont correctement configurées!</p></body></html>';
            $headers = "Content-Type: text/html; charset=UTF-8\r\nFrom: Noteso <noreply@noteso.fr>";
            $success = @mail($email, $subject, $body, $headers);
            $message = $success ? 'Email de test envoyé à ' . $email : 'Erreur envoi email';
            break;
    }
    
    if (!$success) {
        error($message, 500);
    }
    
    response(['success' => true, 'message' => $message]);
}

// ============== DASHBOARD WIDGETS ==============

// GET /dashboard/widgets - Liste des widgets de l'utilisateur
if ($method === 'GET' && $uri === '/dashboard/widgets') {
    $admin = requireAuth();
    
    $widgets = Database::fetchAll(
        "SELECT * FROM dashboard_widgets WHERE admin_id = ? AND is_visible = 1 ORDER BY position ASC",
        [$admin['id']]
    );
    
    // Si pas de widgets, créer les widgets par défaut
    if (empty($widgets)) {
        $defaultWidgets = [
            ['type' => 'stats_overview', 'title' => 'Vue d\'ensemble', 'width' => 'full', 'position' => 0],
            ['type' => 'revenue_chart', 'title' => 'Revenus', 'width' => 'large', 'position' => 1],
            ['type' => 'recent_payments', 'title' => 'Paiements récents', 'width' => 'medium', 'position' => 2],
            ['type' => 'sites_status', 'title' => 'Statut des sites', 'width' => 'medium', 'position' => 3],
            ['type' => 'activity_feed', 'title' => 'Activité récente', 'width' => 'medium', 'position' => 4],
        ];
        
        foreach ($defaultWidgets as $w) {
            $id = generateId('widget');
            Database::insert('dashboard_widgets', [
                'id' => $id,
                'admin_id' => $admin['id'],
                'widget_type' => $w['type'],
                'title' => $w['title'],
                'width' => $w['width'],
                'position' => $w['position'],
                'config' => json_encode([]),
                'is_visible' => 1
            ]);
        }
        
        $widgets = Database::fetchAll(
            "SELECT * FROM dashboard_widgets WHERE admin_id = ? ORDER BY position ASC",
            [$admin['id']]
        );
    }
    
    $result = array_map(fn($w) => [
        'id' => $w['id'],
        'type' => $w['widget_type'],
        'title' => $w['title'],
        'width' => $w['width'],
        'position' => (int)$w['position'],
        'config' => json_decode($w['config'] ?? '{}', true),
        'visible' => (bool)$w['is_visible']
    ], $widgets);
    
    response($result);
}

// POST /dashboard/widgets - Ajouter un widget
if ($method === 'POST' && $uri === '/dashboard/widgets') {
    $admin = requireAuth();
    $input = getInput();
    
    $type = $input['type'] ?? '';
    $title = $input['title'] ?? '';
    $width = $input['width'] ?? 'medium';
    
    if (!$type) {
        error('Type de widget requis', 400);
    }
    
    // Récupérer la dernière position
    $lastPosition = Database::fetchColumn(
        "SELECT MAX(position) FROM dashboard_widgets WHERE admin_id = ?",
        [$admin['id']]
    ) ?? -1;
    
    $id = generateId('widget');
    Database::insert('dashboard_widgets', [
        'id' => $id,
        'admin_id' => $admin['id'],
        'widget_type' => $type,
        'title' => $title ?: ucfirst(str_replace('_', ' ', $type)),
        'width' => $width,
        'position' => $lastPosition + 1,
        'config' => json_encode($input['config'] ?? []),
        'is_visible' => 1
    ]);
    
    response(['id' => $id, 'success' => true], 201);
}

// PUT /dashboard/widgets/reorder - Réorganiser les widgets
if ($method === 'PUT' && $uri === '/dashboard/widgets/reorder') {
    $admin = requireAuth();
    $input = getInput();
    
    $order = $input['order'] ?? [];
    
    foreach ($order as $position => $widgetId) {
        Database::query(
            "UPDATE dashboard_widgets SET position = ? WHERE id = ? AND admin_id = ?",
            [$position, $widgetId, $admin['id']]
        );
    }
    
    response(['success' => true]);
}

// PUT /dashboard/widgets/{id} - Modifier un widget
if ($method === 'PUT' && ($params = matchRoute('/dashboard/widgets/{id}', $uri))) {
    $admin = requireAuth();
    $input = getInput();
    
    $widget = Database::fetch(
        "SELECT * FROM dashboard_widgets WHERE id = ? AND admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    if (!$widget) {
        error('Widget non trouvé', 404);
    }
    
    $updateData = [];
    if (isset($input['title'])) $updateData['title'] = $input['title'];
    if (isset($input['width'])) $updateData['width'] = $input['width'];
    if (isset($input['config'])) $updateData['config'] = json_encode($input['config']);
    if (isset($input['visible'])) $updateData['is_visible'] = $input['visible'] ? 1 : 0;
    
    if (!empty($updateData)) {
        Database::update('dashboard_widgets', $updateData, ['id' => $params['id']]);
    }
    
    response(['success' => true]);
}

// DELETE /dashboard/widgets/{id} - Supprimer un widget
if ($method === 'DELETE' && ($params = matchRoute('/dashboard/widgets/{id}', $uri))) {
    $admin = requireAuth();
    
    Database::query(
        "DELETE FROM dashboard_widgets WHERE id = ? AND admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    response(['success' => true]);
}

// GET /dashboard/widgets/available - Types de widgets disponibles
if ($method === 'GET' && $uri === '/dashboard/widgets/available') {
    response([
        ['type' => 'stats_overview', 'name' => 'Vue d\'ensemble', 'description' => 'Statistiques principales', 'icon' => '📊'],
        ['type' => 'revenue_chart', 'name' => 'Graphique revenus', 'description' => 'Évolution des revenus', 'icon' => '📈'],
        ['type' => 'users_chart', 'name' => 'Graphique utilisateurs', 'description' => 'Évolution des inscriptions', 'icon' => '👥'],
        ['type' => 'recent_payments', 'name' => 'Paiements récents', 'description' => 'Derniers paiements reçus', 'icon' => '💳'],
        ['type' => 'recent_users', 'name' => 'Nouveaux utilisateurs', 'description' => 'Dernières inscriptions', 'icon' => '🆕'],
        ['type' => 'sites_status', 'name' => 'Statut des sites', 'description' => 'État de vos sites', 'icon' => '🌐'],
        ['type' => 'activity_feed', 'name' => 'Fil d\'activité', 'description' => 'Activité récente', 'icon' => '📋'],
        ['type' => 'mrr_widget', 'name' => 'MRR/ARR', 'description' => 'Revenus récurrents', 'icon' => '💰'],
        ['type' => 'conversion_funnel', 'name' => 'Entonnoir', 'description' => 'Taux de conversion', 'icon' => '🔄'],
        ['type' => 'top_customers', 'name' => 'Top clients', 'description' => 'Meilleurs clients', 'icon' => '⭐'],
        ['type' => 'alerts_summary', 'name' => 'Alertes', 'description' => 'Résumé des alertes', 'icon' => '🔔'],
        ['type' => 'quick_actions', 'name' => 'Actions rapides', 'description' => 'Raccourcis', 'icon' => '⚡'],
    ]);
}

// ============== ALERTES INTELLIGENTES ==============

// GET /alerts - Liste des alertes
if ($method === 'GET' && $uri === '/alerts') {
    $admin = requireAuth();
    
    $alerts = Database::fetchAll(
        "SELECT a.*, s.name as site_name 
         FROM alerts a 
         LEFT JOIN sites s ON a.site_id = s.id 
         WHERE a.admin_id = ? 
         ORDER BY a.created_at DESC",
        [$admin['id']]
    );
    
    $result = array_map(fn($a) => [
        'id' => $a['id'],
        'name' => $a['name'],
        'description' => $a['description'],
        'metric' => $a['metric'],
        'condition' => $a['condition'],
        'threshold' => (float)$a['threshold'],
        'timeWindow' => $a['time_window'],
        'siteId' => $a['site_id'],
        'siteName' => $a['site_name'],
        'notifyEmail' => (bool)$a['notify_email'],
        'notifySlack' => (bool)$a['notify_slack'],
        'notifyDiscord' => (bool)$a['notify_discord'],
        'isActive' => (bool)$a['is_active'],
        'lastTriggeredAt' => $a['last_triggered_at'],
        'triggerCount' => (int)$a['trigger_count'],
        'createdAt' => $a['created_at']
    ], $alerts);
    
    response($result);
}

// POST /alerts - Créer une alerte
if ($method === 'POST' && $uri === '/alerts') {
    $admin = requireAuth();
    $input = getInput();
    
    $required = ['name', 'metric', 'condition', 'threshold'];
    foreach ($required as $field) {
        if (empty($input[$field]) && $input[$field] !== 0) {
            error("Champ requis: $field", 400);
        }
    }
    
    $validMetrics = ['revenue', 'payments', 'users', 'churn', 'mrr', 'conversion'];
    if (!in_array($input['metric'], $validMetrics)) {
        error('Métrique invalide', 400);
    }
    
    $validConditions = ['above', 'below', 'equals', 'change_percent'];
    if (!in_array($input['condition'], $validConditions)) {
        error('Condition invalide', 400);
    }
    
    $id = generateId('alert');
    Database::insert('alerts', [
        'id' => $id,
        'admin_id' => $admin['id'],
        'name' => $input['name'],
        'description' => $input['description'] ?? null,
        'metric' => $input['metric'],
        'condition' => $input['condition'],
        'threshold' => (float)$input['threshold'],
        'time_window' => $input['timeWindow'] ?? 'daily',
        'site_id' => $input['siteId'] ?? null,
        'notify_email' => $input['notifyEmail'] ?? true ? 1 : 0,
        'notify_slack' => $input['notifySlack'] ?? false ? 1 : 0,
        'notify_discord' => $input['notifyDiscord'] ?? false ? 1 : 0,
        'is_active' => 1
    ]);
    
    addNotification('success', 'Alerte créée', $input['name'] . ' est maintenant active');
    
    response(['id' => $id, 'success' => true], 201);
}

// GET /alerts/{id} - Détail d'une alerte
if ($method === 'GET' && ($params = matchRoute('/alerts/{id}', $uri))) {
    $admin = requireAuth();
    
    $alert = Database::fetch(
        "SELECT a.*, s.name as site_name 
         FROM alerts a 
         LEFT JOIN sites s ON a.site_id = s.id 
         WHERE a.id = ? AND a.admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    if (!$alert) {
        error('Alerte non trouvée', 404);
    }
    
    // Récupérer l'historique
    $history = Database::fetchAll(
        "SELECT * FROM alert_history WHERE alert_id = ? ORDER BY created_at DESC LIMIT 20",
        [$params['id']]
    );
    
    response([
        'id' => $alert['id'],
        'name' => $alert['name'],
        'description' => $alert['description'],
        'metric' => $alert['metric'],
        'condition' => $alert['condition'],
        'threshold' => (float)$alert['threshold'],
        'timeWindow' => $alert['time_window'],
        'siteId' => $alert['site_id'],
        'siteName' => $alert['site_name'],
        'notifyEmail' => (bool)$alert['notify_email'],
        'notifySlack' => (bool)$alert['notify_slack'],
        'notifyDiscord' => (bool)$alert['notify_discord'],
        'isActive' => (bool)$alert['is_active'],
        'lastTriggeredAt' => $alert['last_triggered_at'],
        'triggerCount' => (int)$alert['trigger_count'],
        'history' => array_map(fn($h) => [
            'triggeredValue' => (float)$h['triggered_value'],
            'thresholdValue' => (float)$h['threshold_value'],
            'message' => $h['message'],
            'createdAt' => $h['created_at']
        ], $history)
    ]);
}

// PUT /alerts/{id} - Modifier une alerte
if ($method === 'PUT' && ($params = matchRoute('/alerts/{id}', $uri))) {
    $admin = requireAuth();
    $input = getInput();
    
    $alert = Database::fetch(
        "SELECT * FROM alerts WHERE id = ? AND admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    if (!$alert) {
        error('Alerte non trouvée', 404);
    }
    
    $updateData = [];
    if (isset($input['name'])) $updateData['name'] = $input['name'];
    if (isset($input['description'])) $updateData['description'] = $input['description'];
    if (isset($input['metric'])) $updateData['metric'] = $input['metric'];
    if (isset($input['condition'])) $updateData['condition'] = $input['condition'];
    if (isset($input['threshold'])) $updateData['threshold'] = (float)$input['threshold'];
    if (isset($input['timeWindow'])) $updateData['time_window'] = $input['timeWindow'];
    if (isset($input['siteId'])) $updateData['site_id'] = $input['siteId'];
    if (isset($input['notifyEmail'])) $updateData['notify_email'] = $input['notifyEmail'] ? 1 : 0;
    if (isset($input['notifySlack'])) $updateData['notify_slack'] = $input['notifySlack'] ? 1 : 0;
    if (isset($input['notifyDiscord'])) $updateData['notify_discord'] = $input['notifyDiscord'] ? 1 : 0;
    if (isset($input['isActive'])) $updateData['is_active'] = $input['isActive'] ? 1 : 0;
    
    if (!empty($updateData)) {
        Database::update('alerts', $updateData, ['id' => $params['id']]);
    }
    
    response(['success' => true]);
}

// DELETE /alerts/{id} - Supprimer une alerte
if ($method === 'DELETE' && ($params = matchRoute('/alerts/{id}', $uri))) {
    $admin = requireAuth();
    
    Database::query(
        "DELETE FROM alerts WHERE id = ? AND admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    response(['success' => true]);
}

// POST /alerts/{id}/test - Tester une alerte
if ($method === 'POST' && ($params = matchRoute('/alerts/{id}/test', $uri))) {
    $admin = requireAuth();
    
    $alert = Database::fetch(
        "SELECT * FROM alerts WHERE id = ? AND admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    if (!$alert) {
        error('Alerte non trouvée', 404);
    }
    
    // Simuler un déclenchement
    $testValue = (float)$alert['threshold'] + ($alert['condition'] === 'above' ? 10 : -10);
    
    Database::insert('alert_history', [
        'alert_id' => $alert['id'],
        'triggered_value' => $testValue,
        'threshold_value' => $alert['threshold'],
        'message' => '[TEST] Alerte déclenchée manuellement',
        'notified' => 1
    ]);
    
    addNotification('warning', 'Test alerte', $alert['name'] . ' - Test déclenché');
    
    response(['success' => true, 'testValue' => $testValue]);
}

// POST /alerts/check - Vérifier toutes les alertes (appelé par cron)
if ($method === 'POST' && $uri === '/alerts/check') {
    // Récupérer toutes les alertes actives
    $alerts = Database::fetchAll("SELECT * FROM alerts WHERE is_active = 1");
    
    $triggered = 0;
    
    foreach ($alerts as $alert) {
        $currentValue = getMetricValue($alert['metric'], $alert['site_id'], $alert['time_window']);
        $shouldTrigger = false;
        
        switch ($alert['condition']) {
            case 'above':
                $shouldTrigger = $currentValue > (float)$alert['threshold'];
                break;
            case 'below':
                $shouldTrigger = $currentValue < (float)$alert['threshold'];
                break;
            case 'equals':
                $shouldTrigger = abs($currentValue - (float)$alert['threshold']) < 0.01;
                break;
            case 'change_percent':
                $previousValue = getMetricValue($alert['metric'], $alert['site_id'], $alert['time_window'], true);
                if ($previousValue > 0) {
                    $changePercent = (($currentValue - $previousValue) / $previousValue) * 100;
                    $shouldTrigger = abs($changePercent) >= (float)$alert['threshold'];
                }
                break;
        }
        
        if ($shouldTrigger) {
            // Enregistrer dans l'historique
            Database::insert('alert_history', [
                'alert_id' => $alert['id'],
                'triggered_value' => $currentValue,
                'threshold_value' => $alert['threshold'],
                'message' => sprintf('%s: %.2f (seuil: %.2f)', $alert['metric'], $currentValue, $alert['threshold']),
                'notified' => 0
            ]);
            
            // Mettre à jour l'alerte
            Database::update('alerts', [
                'last_triggered_at' => date('Y-m-d H:i:s'),
                'trigger_count' => $alert['trigger_count'] + 1
            ], ['id' => $alert['id']]);
            
            // Créer notification
            addNotification('warning', 'Alerte: ' . $alert['name'], 
                sprintf('Valeur actuelle: %.2f (seuil: %.2f)', $currentValue, $alert['threshold']),
                $alert['admin_id']
            );
            
            $triggered++;
        }
    }
    
    response(['checked' => count($alerts), 'triggered' => $triggered]);
}

// Helper pour récupérer la valeur d'une métrique
function getMetricValue(string $metric, ?string $siteId, string $timeWindow, bool $previous = false): float {
    $interval = match($timeWindow) {
        'hourly' => '1 HOUR',
        'daily' => '1 DAY',
        'weekly' => '7 DAY',
        'monthly' => '30 DAY',
        default => '1 DAY'
    };
    
    $offset = $previous ? $interval : '0 SECOND';
    $siteCondition = $siteId ? "AND site_id = '$siteId'" : '';
    
    switch ($metric) {
        case 'revenue':
            return (float)Database::fetchColumn(
                "SELECT COALESCE(SUM(amount), 0) FROM payments 
                 WHERE status = 'completed' $siteCondition 
                 AND created_at >= DATE_SUB(DATE_SUB(NOW(), INTERVAL $offset), INTERVAL $interval)
                 AND created_at < DATE_SUB(NOW(), INTERVAL $offset)"
            );
        case 'payments':
            return (float)Database::fetchColumn(
                "SELECT COUNT(*) FROM payments 
                 WHERE status = 'completed' $siteCondition 
                 AND created_at >= DATE_SUB(DATE_SUB(NOW(), INTERVAL $offset), INTERVAL $interval)
                 AND created_at < DATE_SUB(NOW(), INTERVAL $offset)"
            );
        case 'users':
            return (float)Database::fetchColumn(
                "SELECT COUNT(*) FROM users 
                 WHERE 1=1 $siteCondition 
                 AND created_at >= DATE_SUB(DATE_SUB(NOW(), INTERVAL $offset), INTERVAL $interval)
                 AND created_at < DATE_SUB(NOW(), INTERVAL $offset)"
            );
        case 'churn':
            return (float)Database::fetchColumn(
                "SELECT COUNT(*) FROM subscriptions 
                 WHERE status = 'cancelled' $siteCondition 
                 AND cancelled_at >= DATE_SUB(DATE_SUB(NOW(), INTERVAL $offset), INTERVAL $interval)
                 AND cancelled_at < DATE_SUB(NOW(), INTERVAL $offset)"
            );
        case 'mrr':
            return (float)Database::fetchColumn(
                "SELECT COALESCE(SUM(amount), 0) FROM subscriptions 
                 WHERE status = 'active' $siteCondition AND interval_type = 'month'"
            );
        case 'conversion':
            $users = (float)Database::fetchColumn("SELECT COUNT(*) FROM users WHERE 1=1 $siteCondition");
            $paying = (float)Database::fetchColumn("SELECT COUNT(DISTINCT user_id) FROM payments WHERE status = 'completed' $siteCondition");
            return $users > 0 ? ($paying / $users) * 100 : 0;
        default:
            return 0;
    }
}

// ============== GESTION D'ÉQUIPE (MULTI-USERS) ==============

// GET /team - Liste des membres de l'équipe
if ($method === 'GET' && $uri === '/team') {
    $admin = requireAuth();
    
    // Seuls super_admin et admin peuvent voir l'équipe
    if (!in_array($admin['role'], ['super_admin', 'admin'])) {
        error('Accès non autorisé', 403);
    }
    
    $members = Database::fetchAll(
        "SELECT id, email, first_name, last_name, role, is_active, last_login_at, last_seen_at, created_at 
         FROM admins ORDER BY created_at ASC"
    );
    
    $result = array_map(fn($m) => [
        'id' => $m['id'],
        'email' => $m['email'],
        'firstName' => $m['first_name'],
        'lastName' => $m['last_name'],
        'role' => $m['role'],
        'isActive' => (bool)$m['is_active'],
        'lastLoginAt' => $m['last_login_at'],
        'lastSeenAt' => $m['last_seen_at'],
        'createdAt' => $m['created_at']
    ], $members);
    
    response($result);
}

// POST /team/invite - Inviter un membre
if ($method === 'POST' && $uri === '/team/invite') {
    $admin = requireAuth();
    $input = getInput();
    
    // Seul super_admin peut inviter
    if ($admin['role'] !== 'super_admin') {
        error('Seul un super admin peut inviter des membres', 403);
    }
    
    $email = strtolower(trim($input['email'] ?? ''));
    $role = $input['role'] ?? 'viewer';
    
    if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        error('Email invalide', 400);
    }
    
    // Vérifier si déjà membre
    $existing = Database::fetch("SELECT id FROM admins WHERE LOWER(email) = ?", [$email]);
    if ($existing) {
        error('Cet email est déjà utilisé', 400);
    }
    
    // Vérifier si invitation en cours
    $existingInvite = Database::fetch(
        "SELECT id FROM team_invitations WHERE email = ? AND expires_at > NOW() AND accepted_at IS NULL",
        [$email]
    );
    if ($existingInvite) {
        error('Une invitation est déjà en cours pour cet email', 400);
    }
    
    $validRoles = ['admin', 'manager', 'viewer'];
    if (!in_array($role, $validRoles)) {
        error('Rôle invalide', 400);
    }
    
    $id = generateId('invite');
    $token = bin2hex(random_bytes(32));
    
    Database::insert('team_invitations', [
        'id' => $id,
        'email' => $email,
        'role' => $role,
        'permissions' => json_encode($input['permissions'] ?? []),
        'invited_by' => $admin['id'],
        'token' => $token,
        'expires_at' => date('Y-m-d H:i:s', time() + 7 * 24 * 3600) // 7 jours
    ]);
    
    // TODO: Envoyer email d'invitation
    $inviteUrl = ($CONFIG['app']['url'] ?? 'https://noteso.fr') . '/invite/' . $token;
    
    addNotification('info', 'Invitation envoyée', "Invitation envoyée à $email");
    
    response([
        'success' => true,
        'inviteUrl' => $inviteUrl,
        'expiresIn' => '7 jours'
    ], 201);
}

// GET /team/invitations - Liste des invitations en attente
if ($method === 'GET' && $uri === '/team/invitations') {
    $admin = requireAuth();
    
    if ($admin['role'] !== 'super_admin') {
        error('Accès non autorisé', 403);
    }
    
    $invitations = Database::fetchAll(
        "SELECT i.*, a.email as invited_by_email 
         FROM team_invitations i 
         JOIN admins a ON i.invited_by = a.id 
         WHERE i.accepted_at IS NULL AND i.expires_at > NOW()
         ORDER BY i.created_at DESC"
    );
    
    $result = array_map(fn($i) => [
        'id' => $i['id'],
        'email' => $i['email'],
        'role' => $i['role'],
        'invitedBy' => $i['invited_by_email'],
        'expiresAt' => $i['expires_at'],
        'createdAt' => $i['created_at']
    ], $invitations);
    
    response($result);
}

// DELETE /team/invitations/{id} - Annuler une invitation
if ($method === 'DELETE' && ($params = matchRoute('/team/invitations/{id}', $uri))) {
    $admin = requireAuth();
    
    if ($admin['role'] !== 'super_admin') {
        error('Accès non autorisé', 403);
    }
    
    Database::delete('team_invitations', ['id' => $params['id']]);
    
    response(['success' => true]);
}

// POST /team/join/{token} - Accepter une invitation
if ($method === 'POST' && ($params = matchRoute('/team/join/{token}', $uri))) {
    $input = getInput();
    
    $invitation = Database::fetch(
        "SELECT * FROM team_invitations WHERE token = ? AND expires_at > NOW() AND accepted_at IS NULL",
        [$params['token']]
    );
    
    if (!$invitation) {
        error('Invitation invalide ou expirée', 400);
    }
    
    $password = $input['password'] ?? '';
    $firstName = $input['firstName'] ?? '';
    $lastName = $input['lastName'] ?? '';
    
    if (strlen($password) < 8) {
        error('Le mot de passe doit contenir au moins 8 caractères', 400);
    }
    
    // Créer le compte
    $adminId = generateId('admin');
    Database::insert('admins', [
        'id' => $adminId,
        'email' => $invitation['email'],
        'password' => hashPassword($password),
        'first_name' => $firstName,
        'last_name' => $lastName,
        'role' => $invitation['role'],
        'permissions' => $invitation['permissions'],
        'invited_by' => $invitation['invited_by'],
        'is_active' => 1
    ]);
    
    // Marquer invitation comme acceptée
    Database::update('team_invitations', [
        'accepted_at' => date('Y-m-d H:i:s')
    ], ['id' => $invitation['id']]);
    
    // Créer session
    $token = generateToken();
    Database::insert('sessions', [
        'id' => generateId('sess'),
        'admin_id' => $adminId,
        'token' => $token,
        'ip' => getClientIP(),
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
        'expires_at' => date('Y-m-d H:i:s', time() + SESSION_DURATION)
    ]);
    
    addNotification('success', 'Nouveau membre', "$firstName $lastName a rejoint l'équipe", $invitation['invited_by']);
    
    response([
        'success' => true,
        'token' => $token,
        'admin' => [
            'id' => $adminId,
            'email' => $invitation['email'],
            'firstName' => $firstName,
            'lastName' => $lastName,
            'role' => $invitation['role']
        ]
    ]);
}

// PUT /team/{id} - Modifier un membre
if ($method === 'PUT' && ($params = matchRoute('/team/{id}', $uri))) {
    $admin = requireAuth();
    $input = getInput();
    
    if ($admin['role'] !== 'super_admin') {
        error('Seul un super admin peut modifier les membres', 403);
    }
    
    // Empêcher de modifier son propre rôle
    if ($params['id'] === $admin['id'] && isset($input['role'])) {
        error('Vous ne pouvez pas modifier votre propre rôle', 400);
    }
    
    $member = Database::find('admins', $params['id']);
    if (!$member) {
        error('Membre non trouvé', 404);
    }
    
    $updateData = [];
    if (isset($input['role'])) {
        $validRoles = ['admin', 'manager', 'viewer'];
        if (!in_array($input['role'], $validRoles)) {
            error('Rôle invalide', 400);
        }
        $updateData['role'] = $input['role'];
    }
    if (isset($input['isActive'])) $updateData['is_active'] = $input['isActive'] ? 1 : 0;
    if (isset($input['permissions'])) $updateData['permissions'] = json_encode($input['permissions']);
    
    if (!empty($updateData)) {
        Database::update('admins', $updateData, ['id' => $params['id']]);
    }
    
    response(['success' => true]);
}

// DELETE /team/{id} - Supprimer un membre
if ($method === 'DELETE' && ($params = matchRoute('/team/{id}', $uri))) {
    $admin = requireAuth();
    
    if ($admin['role'] !== 'super_admin') {
        error('Seul un super admin peut supprimer des membres', 403);
    }
    
    if ($params['id'] === $admin['id']) {
        error('Vous ne pouvez pas vous supprimer vous-même', 400);
    }
    
    $member = Database::find('admins', $params['id']);
    if (!$member) {
        error('Membre non trouvé', 404);
    }
    
    if ($member['role'] === 'super_admin') {
        error('Impossible de supprimer un super admin', 400);
    }
    
    // Supprimer les sessions
    Database::delete('sessions', ['admin_id' => $params['id']]);
    
    // Supprimer le membre
    Database::delete('admins', ['id' => $params['id']]);
    
    addNotification('info', 'Membre supprimé', $member['first_name'] . ' ' . $member['last_name'] . ' a été retiré de l\'équipe');
    
    response(['success' => true]);
}

// GET /team/permissions/{adminId} - Permissions par site d'un membre
if ($method === 'GET' && ($params = matchRoute('/team/permissions/{adminId}', $uri))) {
    $admin = requireAuth();
    
    if (!in_array($admin['role'], ['super_admin', 'admin'])) {
        error('Accès non autorisé', 403);
    }
    
    $permissions = Database::fetchAll(
        "SELECT asp.*, s.name as site_name 
         FROM admin_site_permissions asp 
         JOIN sites s ON asp.site_id = s.id 
         WHERE asp.admin_id = ?",
        [$params['adminId']]
    );
    
    $result = array_map(fn($p) => [
        'siteId' => $p['site_id'],
        'siteName' => $p['site_name'],
        'canView' => (bool)$p['can_view'],
        'canEdit' => (bool)$p['can_edit'],
        'canDelete' => (bool)$p['can_delete'],
        'canExport' => (bool)$p['can_export']
    ], $permissions);
    
    response($result);
}

// PUT /team/permissions/{adminId} - Modifier les permissions par site
if ($method === 'PUT' && ($params = matchRoute('/team/permissions/{adminId}', $uri))) {
    $admin = requireAuth();
    $input = getInput();
    
    if ($admin['role'] !== 'super_admin') {
        error('Seul un super admin peut modifier les permissions', 403);
    }
    
    $permissions = $input['permissions'] ?? [];
    
    foreach ($permissions as $perm) {
        $siteId = $perm['siteId'] ?? null;
        if (!$siteId) continue;
        
        // Upsert
        $existing = Database::fetch(
            "SELECT id FROM admin_site_permissions WHERE admin_id = ? AND site_id = ?",
            [$params['adminId'], $siteId]
        );
        
        $data = [
            'admin_id' => $params['adminId'],
            'site_id' => $siteId,
            'can_view' => $perm['canView'] ?? true ? 1 : 0,
            'can_edit' => $perm['canEdit'] ?? false ? 1 : 0,
            'can_delete' => $perm['canDelete'] ?? false ? 1 : 0,
            'can_export' => $perm['canExport'] ?? false ? 1 : 0
        ];
        
        if ($existing) {
            Database::update('admin_site_permissions', $data, ['id' => $existing['id']]);
        } else {
            Database::insert('admin_site_permissions', $data);
        }
    }
    
    response(['success' => true]);
}

// ============== WEBHOOKS ==============

// GET /webhooks/outgoing - Liste des webhooks
if ($method === 'GET' && $uri === '/webhooks/outgoing') {
    $webhooks = Database::fetchAll("SELECT * FROM webhooks_outgoing WHERE is_active = 1 ORDER BY created_at DESC");
    
    $result = array_map(fn($w) => [
        'id' => $w['id'],
        'name' => $w['name'] ?? 'Webhook',
        'url' => $w['url'],
        'events' => json_decode($w['events'] ?? '[]', true),
        'isActive' => (bool)$w['is_active'],
        'successCount' => (int)($w['success_count'] ?? 0),
        'failureCount' => (int)($w['failure_count'] ?? 0),
        'lastTriggeredAt' => $w['last_triggered_at'],
        'createdAt' => $w['created_at']
    ], $webhooks);
    
    response($result);
}

// POST /webhooks/outgoing - Créer un webhook
if ($method === 'POST' && $uri === '/webhooks/outgoing') {
    requireAuth();
    $input = getInput();
    
    if (empty($input['url'])) {
        error('URL requise', 400);
    }
    
    $id = generateId('webhook');
    $secret = bin2hex(random_bytes(16));
    
    Database::insert('webhooks_outgoing', [
        'id' => $id,
        'name' => $input['name'] ?? 'Webhook',
        'url' => $input['url'],
        'events' => json_encode($input['events'] ?? ['payment.completed']),
        'secret' => $secret,
        'is_active' => 1
    ]);
    
    response([
        'id' => $id,
        'name' => $input['name'] ?? 'Webhook',
        'url' => $input['url'],
        'events' => $input['events'] ?? ['payment.completed'],
        'secret' => $secret,
        'isActive' => true
    ], 201);
}

// DELETE /webhooks/outgoing/{id} - Supprimer un webhook
if ($method === 'DELETE' && ($params = matchRoute('/webhooks/outgoing/{id}', $uri))) {
    requireAuth();
    
    $webhook = Database::find('webhooks_outgoing', $params['id']);
    if (!$webhook) {
        error('Webhook non trouvé', 404);
    }
    
    Database::delete('webhooks_outgoing', ['id' => $params['id']]);
    response(['success' => true]);
}

// POST /webhooks/outgoing/{id}/test - Tester un webhook
if ($method === 'POST' && ($params = matchRoute('/webhooks/outgoing/{id}/test', $uri))) {
    requireAuth();
    
    $webhook = Database::find('webhooks_outgoing', $params['id']);
    if (!$webhook) {
        error('Webhook non trouvé', 404);
    }
    
    // Préparer payload de test
    $payload = json_encode([
        'event' => 'test',
        'timestamp' => date('c'),
        'data' => [
            'message' => 'Test webhook from Noteso',
            'webhookId' => $webhook['id']
        ]
    ]);
    
    // Signature HMAC
    $signature = hash_hmac('sha256', $payload, $webhook['secret'] ?? '');
    
    // Envoyer
    $ch = curl_init($webhook['url']);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'X-Noteso-Signature: ' . $signature,
            'X-Noteso-Event: test'
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10
    ]);
    
    $result = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    // Mettre à jour stats
    $success = $httpCode >= 200 && $httpCode < 300;
    Database::query(
        "UPDATE webhooks_outgoing SET 
            last_triggered_at = NOW(), 
            last_status = ?,
            success_count = success_count + ?,
            failure_count = failure_count + ?
         WHERE id = ?",
        [$httpCode, $success ? 1 : 0, $success ? 0 : 1, $params['id']]
    );
    
    if (!$success) {
        error("Webhook a retourné le code HTTP $httpCode", 500);
    }
    
    response(['success' => true, 'httpCode' => $httpCode]);
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
    
    // Remplir les jours manquants
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

if ($method === 'GET' && $uri === '/analytics/mrr') {
    $mrr = Database::fetchColumn(
        "SELECT COALESCE(SUM(CASE WHEN interval_type = 'year' THEN amount/12 ELSE amount END), 0)
         FROM subscriptions WHERE status = 'active'"
    ) ?: 0;
    
    $activeSubscriptions = Database::count('subscriptions', ['status' => 'active']);
    
    response([
        'mrr' => round($mrr, 2),
        'arr' => round($mrr * 12, 2),
        'activeSubscriptions' => $activeSubscriptions
    ]);
}

// GET /analytics/charts - Données graphiques pour les charts
if ($method === 'GET' && $uri === '/analytics/charts') {
    $period = $_GET['period'] ?? '30d';
    $siteId = $_GET['siteId'] ?? null;
    
    $days = match($period) { '7d' => 7, '30d' => 30, '90d' => 90, '365d' => 365, default => 30 };
    
    $where = "status = 'completed' AND created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)";
    $params = [$days];
    
    if ($siteId) {
        $where .= " AND site_id = ?";
        $params[] = $siteId;
    }
    
    $data = Database::fetchAll(
        "SELECT DATE(created_at) as date, SUM(amount) as revenue, COUNT(*) as count 
         FROM payments WHERE $where 
         GROUP BY DATE(created_at) ORDER BY date",
        $params
    );
    
    // Remplir les jours manquants
    $result = [];
    $dataMap = [];
    foreach ($data as $row) {
        $dataMap[$row['date']] = ['revenue' => (float)$row['revenue'], 'count' => (int)$row['count']];
    }
    
    for ($i = $days - 1; $i >= 0; $i--) {
        $date = date('Y-m-d', strtotime("-$i days"));
        $result[] = [
            'date' => $date,
            'revenue' => $dataMap[$date]['revenue'] ?? 0,
            'count' => $dataMap[$date]['count'] ?? 0
        ];
    }
    
    $total = array_sum(array_column($result, 'revenue'));
    $count = array_sum(array_column($result, 'count'));
    
    response([
        'daily' => $result,
        'total' => round($total, 2),
        'count' => $count,
        'average' => $days > 0 ? round($total / $days, 2) : 0
    ]);
}

// GET /analytics/comparison - Comparaison période précédente
if ($method === 'GET' && $uri === '/analytics/comparison') {
    $period = $_GET['period'] ?? '30d';
    
    $days = match($period) { '7d' => 7, '30d' => 30, '90d' => 90, default => 30 };
    
    // Période actuelle
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
    
    // Période précédente
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
    
    // Calcul des tendances
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

// ============== WIDGETS ==============

if ($method === 'GET' && $uri === '/widgets') {
    $widgets = Database::fetchAll("SELECT * FROM widgets ORDER BY position_y, position_x");
    
    $result = array_map(fn($w) => [
        'id' => $w['id'],
        'type' => $w['type'],
        'title' => $w['title'],
        'position' => [
            'x' => (int)$w['position_x'],
            'y' => (int)$w['position_y'],
            'w' => (int)$w['width'],
            'h' => (int)$w['height']
        ],
        'visible' => (bool)$w['is_visible'],
        'config' => json_decode($w['config'] ?? '{}', true)
    ], $widgets);
    
    response($result);
}

if ($method === 'PUT' && $uri === '/widgets') {
    $widgets = getInput();
    
    foreach ($widgets as $w) {
        Database::query(
            "INSERT INTO widgets (id, type, title, position_x, position_y, width, height, is_visible, config)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE 
                position_x = VALUES(position_x),
                position_y = VALUES(position_y),
                width = VALUES(width),
                height = VALUES(height),
                is_visible = VALUES(is_visible),
                config = VALUES(config)",
            [
                $w['id'],
                $w['type'],
                $w['title'],
                $w['position']['x'] ?? 0,
                $w['position']['y'] ?? 0,
                $w['position']['w'] ?? 1,
                $w['position']['h'] ?? 1,
                $w['visible'] ?? true ? 1 : 0,
                isset($w['config']) ? json_encode($w['config']) : null
            ]
        );
    }
    
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
    
    // Paramètres par défaut
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

// ============== SECURITY LOGS ==============

if ($method === 'GET' && $uri === '/security/logs') {
    requireAuth('super_admin');
    
    $limit = (int)($_GET['limit'] ?? 100);
    $type = $_GET['type'] ?? null;
    
    $where = "";
    $params = [];
    
    if ($type) {
        $where = "WHERE type = ?";
        $params[] = $type;
    }
    
    $logs = Database::fetchAll(
        "SELECT * FROM security_logs $where ORDER BY timestamp DESC LIMIT ?",
        array_merge($params, [$limit])
    );
    
    $result = array_map(fn($l) => [
        'id' => $l['id'],
        'type' => $l['type'],
        'details' => $l['details'],
        'ip' => $l['ip'],
        'userAgent' => $l['user_agent'],
        'timestamp' => $l['timestamp']
    ], $logs);
    
    response($result);
}

// ============== ADMINS ==============

if ($method === 'GET' && $uri === '/admins') {
    requireAuth('super_admin');
    
    $admins = Database::fetchAll("SELECT * FROM admins ORDER BY created_at");
    
    $result = array_map(fn($a) => [
        'id' => $a['id'],
        'email' => $a['email'],
        'firstName' => $a['first_name'],
        'lastName' => $a['last_name'],
        'role' => $a['role'],
        'createdAt' => $a['created_at'],
        'lastLoginAt' => $a['last_login_at']
    ], $admins);
    
    response($result);
}

if ($method === 'POST' && $uri === '/admins') {
    $currentAdmin = requireAuth('super_admin');
    $input = getInput();
    
    $email = strtolower(trim($input['email'] ?? ''));
    $password = $input['password'] ?? '';
    $firstName = trim($input['firstName'] ?? '');
    $lastName = trim($input['lastName'] ?? '');
    $role = $input['role'] ?? 'viewer';
    
    if (!$email || !$password || !$firstName || !$lastName) {
        error('Tous les champs sont requis');
    }
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        error('Format email invalide');
    }
    
    if (!isStrongPassword($password)) {
        error('Le mot de passe doit contenir: ' . getPasswordRequirements());
    }
    
    if (!in_array($role, ['super_admin', 'admin', 'viewer'])) {
        error('Rôle invalide');
    }
    
    if (Database::exists('admins', ['email' => $email])) {
        error('Cet email est déjà utilisé');
    }
    
    $id = generateId('admin');
    $permissions = match($role) {
        'super_admin' => ['all'],
        'admin' => ['read', 'write'],
        default => ['read']
    };
    
    Database::insert('admins', [
        'id' => $id,
        'email' => $email,
        'password' => hashPassword($password),
        'first_name' => $firstName,
        'last_name' => $lastName,
        'role' => $role,
        'permissions' => json_encode($permissions),
        'created_at' => date('Y-m-d H:i:s')
    ]);
    
    logSecurityEvent('admin_created', "Nouvel admin créé: $email par " . $currentAdmin['email'], $currentAdmin['id']);
    
    response([
        'id' => $id,
        'email' => $email,
        'firstName' => $firstName,
        'lastName' => $lastName,
        'role' => $role
    ], 201);
}

if ($method === 'DELETE' && ($params = matchRoute('/admins/{id}', $uri))) {
    $admin = requireAuth('super_admin');
    
    if ($params['id'] === $admin['id']) {
        error('Vous ne pouvez pas vous supprimer vous-même');
    }
    
    Database::delete('admins', ['id' => $params['id']]);
    
    response(['success' => true]);
}

// ============== WEBHOOK ENTRANT ==============

if ($method === 'POST' && ($params = matchRoute('/webhook/{siteId}', $uri))) {
    $site = Database::find('sites', $params['siteId']);
    if (!$site) error('Site non trouvé', 404);
    
    $headers = getallheaders();
    $apiKey = '';
    $signature = '';
    $timestamp = '';
    
    foreach ($headers as $key => $value) {
        $lowerKey = strtolower($key);
        if ($lowerKey === 'x-api-key') $apiKey = $value;
        if ($lowerKey === 'x-noteso-signature') $signature = $value;
        if ($lowerKey === 'x-noteso-timestamp') $timestamp = $value;
    }
    
    $payload = file_get_contents('php://input');
    $useSignature = !empty($signature);
    
    // Validation: soit signature HMAC, soit API key (rétrocompatibilité)
    if ($useSignature) {
        // Nouvelle méthode: signature HMAC
        $secret = $site['webhook_secret'] ?? $site['api_key'];
        
        if (class_exists('WebhookValidator')) {
            $validation = WebhookValidator::verify($payload, $secret, $signature, $timestamp);
            if (!$validation['valid']) {
                logSecurityEvent('webhook_invalid_signature', 'Signature webhook invalide: ' . $validation['error'], null, getClientIP());
                error('Signature invalide: ' . $validation['error'], 401);
            }
        }
    } else {
        // Ancienne méthode: API key
        if (empty($apiKey)) {
            error('Clé API ou signature manquante', 401);
        }
        if ($apiKey !== $site['api_key']) {
            logSecurityEvent('webhook_invalid_api_key', 'Clé API webhook invalide', null, getClientIP());
            error('Clé API invalide', 401);
        }
    }
    
    $input = json_decode($payload, true) ?: [];
    $event = $input['event'] ?? '';
    $data = $input['data'] ?? [];
    
    // Option: utiliser la file d'attente pour traitement asynchrone
    $useQueue = $_GET['async'] ?? false;
    
    if ($useQueue && class_exists('WebhookValidator')) {
        $queueId = WebhookValidator::queue($site['id'], $event, $data, $signature);
        response(['success' => true, 'queued' => true, 'queueId' => $queueId]);
    }
    
    // Traitement synchrone
    switch ($event) {
        case 'user.created':
        case 'user.signup':
            $id = generateId('user');
            Database::insert('users', [
                'id' => $id,
                'site_id' => $site['id'],
                'email' => $data['email'] ?? null,
                'name' => trim(($data['firstName'] ?? '') . ' ' . ($data['lastName'] ?? '')),
                'external_id' => $data['externalId'] ?? $data['userId'] ?? null,
                'metadata' => json_encode(['source' => 'webhook', 'status' => 'active']),
                'created_at' => date('Y-m-d H:i:s')
            ]);
            
            logActivity($site['id'], $id, 'signup', 'Nouvelle inscription: ' . ($data['email'] ?? 'N/A'));
            addNotification('info', 'Nouvel utilisateur', ($data['email'] ?? 'Utilisateur') . ' sur ' . $site['name']);
            
            response(['success' => true, 'userId' => $id]);
            break;
            
        case 'payment.completed':
        case 'payment.success':
            $id = generateId('pay');
            $amount = (float)($data['amount'] ?? 0);
            
            Database::insert('payments', [
                'id' => $id,
                'site_id' => $site['id'],
                'user_id' => $data['userId'] ?? null,
                'amount' => $amount,
                'currency' => $data['currency'] ?? 'EUR',
                'status' => 'completed',
                'payment_method' => $data['method'] ?? $data['paymentMethod'] ?? 'card',
                'external_id' => $data['externalId'] ?? $data['paymentId'] ?? null,
                'paid_at' => date('Y-m-d H:i:s'),
                'created_at' => date('Y-m-d H:i:s')
            ]);
            
            $amountStr = number_format($amount, 2) . ' ' . ($data['currency'] ?? 'EUR');
            logActivity($site['id'], $data['userId'] ?? null, 'payment', "Paiement: +{$amountStr}", $amountStr);
            addNotification('success', 'Paiement reçu', $amountStr . ' sur ' . $site['name']);
            
            response(['success' => true, 'paymentId' => $id]);
            break;
            
        case 'payment.failed':
            $id = generateId('pay');
            Database::insert('payments', [
                'id' => $id,
                'site_id' => $site['id'],
                'user_id' => $data['userId'] ?? null,
                'amount' => (float)($data['amount'] ?? 0),
                'currency' => $data['currency'] ?? 'EUR',
                'status' => 'failed',
                'payment_method' => $data['method'] ?? 'card',
                'metadata' => json_encode(['error' => $data['error'] ?? null]),
                'created_at' => date('Y-m-d H:i:s')
            ]);
            
            logActivity($site['id'], $data['userId'] ?? null, 'payment_failed', 'Paiement échoué');
            addNotification('error', 'Paiement échoué', ($data['error'] ?? 'Erreur') . ' sur ' . $site['name']);
            
            response(['success' => true, 'paymentId' => $id, 'status' => 'failed']);
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
            
        case 'test':
        case 'ping':
            response(['success' => true, 'message' => 'Webhook reçu', 'timestamp' => date('c')]);
            break;
            
        default:
            // Événement inconnu mais on log quand même
            logActivity($site['id'], null, 'webhook', "Événement reçu: {$event}");
            response(['success' => true, 'message' => 'Événement reçu: ' . $event]);
    }
}

// ============== MONITORING ==============

if ($method === 'GET' && $uri === '/monitoring') {
    $hours = (int)($_GET['hours'] ?? 24);
    
    $sites = Database::fetchAll("SELECT * FROM sites");
    
    $result = [];
    foreach ($sites as $site) {
        $stats = Database::fetch(
            "SELECT 
                AVG(CASE WHEN metric_type = 'uptime' THEN value END) as uptime,
                AVG(CASE WHEN metric_type = 'response_time' THEN value END) as avg_response,
                COUNT(CASE WHEN metric_type = 'uptime' AND value = 0 THEN 1 END) as incidents
             FROM monitoring 
             WHERE site_id = ? AND recorded_at > DATE_SUB(NOW(), INTERVAL ? HOUR)",
            [$site['id'], $hours]
        );
        
        $lastCheck = Database::fetch(
            "SELECT recorded_at, value FROM monitoring 
             WHERE site_id = ? AND metric_type = 'uptime' 
             ORDER BY recorded_at DESC LIMIT 1",
            [$site['id']]
        );
        
        $result[] = [
            'siteId' => $site['id'],
            'siteName' => $site['name'],
            'status' => $site['status'],
            'uptime' => round((float)($stats['uptime'] ?? 100), 2),
            'avgResponseTime' => round((float)($stats['avg_response'] ?? 0)),
            'lastCheck' => $lastCheck['recorded_at'] ?? null,
            'lastStatus' => $lastCheck ? ($lastCheck['value'] > 0 ? 'up' : 'down') : null,
            'incidents' => (int)($stats['incidents'] ?? 0)
        ];
    }
    
    response($result);
}

// ============== INTÉGRATIONS (Stripe, PayPal) ==============

// GET /integrations - Liste des intégrations
if ($method === 'GET' && $uri === '/integrations') {
    $admin = requireAuth();
    
    $integrations = Database::fetchAll(
        "SELECT * FROM integrations WHERE admin_id = ? ORDER BY created_at DESC",
        [$admin['id']]
    );
    
    $result = array_map(fn($i) => [
        'id' => $i['id'],
        'provider' => $i['provider'],
        'name' => $i['name'],
        'isActive' => (bool)$i['is_active'],
        'lastSyncAt' => $i['last_sync_at'],
        'syncStatus' => $i['sync_status'],
        'syncError' => $i['sync_error'],
        'settings' => json_decode($i['settings'] ?? '{}', true),
        'createdAt' => $i['created_at']
    ], $integrations);
    
    response($result);
}

// GET /integrations/available - Intégrations disponibles
if ($method === 'GET' && $uri === '/integrations/available') {
    response([
        [
            'provider' => 'stripe',
            'name' => 'Stripe',
            'icon' => '💳',
            'description' => 'Importez automatiquement vos paiements Stripe',
            'requiredFields' => ['api_key'],
            'features' => ['payments', 'subscriptions', 'customers', 'refunds']
        ],
        [
            'provider' => 'paypal',
            'name' => 'PayPal',
            'icon' => '🅿️',
            'description' => 'Synchronisez vos transactions PayPal',
            'requiredFields' => ['client_id', 'client_secret'],
            'features' => ['payments', 'refunds']
        ],
        [
            'provider' => 'gocardless',
            'name' => 'GoCardless',
            'icon' => '🏦',
            'description' => 'Prélèvements SEPA automatiques',
            'requiredFields' => ['access_token'],
            'features' => ['payments', 'mandates']
        ],
        [
            'provider' => 'google_analytics',
            'name' => 'Google Analytics',
            'icon' => '📊',
            'description' => 'Suivez le trafic de vos sites',
            'requiredFields' => ['property_id', 'credentials_json'],
            'features' => ['pageviews', 'sessions', 'conversions']
        ]
    ]);
}

// POST /integrations - Ajouter une intégration
if ($method === 'POST' && $uri === '/integrations') {
    $admin = requireAuth();
    $input = getInput();
    
    $provider = $input['provider'] ?? '';
    $credentials = $input['credentials'] ?? [];
    
    if (!$provider) {
        error('Provider requis', 400);
    }
    
    // Vérifier si déjà configuré
    $existing = Database::fetch(
        "SELECT id FROM integrations WHERE admin_id = ? AND provider = ?",
        [$admin['id'], $provider]
    );
    
    if ($existing) {
        error('Cette intégration est déjà configurée', 400);
    }
    
    // Chiffrer les credentials (simple base64 pour l'exemple - utiliser AES en prod)
    $encryptedCredentials = base64_encode(json_encode($credentials));
    
    $id = generateId('integ');
    Database::insert('integrations', [
        'id' => $id,
        'admin_id' => $admin['id'],
        'provider' => $provider,
        'name' => $input['name'] ?? ucfirst($provider),
        'credentials' => $encryptedCredentials,
        'settings' => json_encode($input['settings'] ?? []),
        'is_active' => 1,
        'sync_status' => 'idle'
    ]);
    
    addNotification('success', 'Intégration ajoutée', ucfirst($provider) . ' est maintenant configuré');
    
    response(['id' => $id, 'success' => true], 201);
}

// PUT /integrations/{id} - Modifier une intégration
if ($method === 'PUT' && ($params = matchRoute('/integrations/{id}', $uri))) {
    $admin = requireAuth();
    $input = getInput();
    
    $integration = Database::fetch(
        "SELECT * FROM integrations WHERE id = ? AND admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    if (!$integration) {
        error('Intégration non trouvée', 404);
    }
    
    $updateData = [];
    if (isset($input['name'])) $updateData['name'] = $input['name'];
    if (isset($input['isActive'])) $updateData['is_active'] = $input['isActive'] ? 1 : 0;
    if (isset($input['settings'])) $updateData['settings'] = json_encode($input['settings']);
    if (isset($input['credentials'])) {
        $updateData['credentials'] = base64_encode(json_encode($input['credentials']));
    }
    
    if (!empty($updateData)) {
        Database::update('integrations', $updateData, ['id' => $params['id']]);
    }
    
    response(['success' => true]);
}

// DELETE /integrations/{id} - Supprimer une intégration
if ($method === 'DELETE' && ($params = matchRoute('/integrations/{id}', $uri))) {
    $admin = requireAuth();
    
    Database::query(
        "DELETE FROM integrations WHERE id = ? AND admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    response(['success' => true]);
}

// POST /integrations/{id}/sync - Synchroniser une intégration
if ($method === 'POST' && ($params = matchRoute('/integrations/{id}/sync', $uri))) {
    $admin = requireAuth();
    
    $integration = Database::fetch(
        "SELECT * FROM integrations WHERE id = ? AND admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    if (!$integration) {
        error('Intégration non trouvée', 404);
    }
    
    if (!$integration['is_active']) {
        error('Intégration désactivée', 400);
    }
    
    // Marquer comme en cours de sync
    Database::update('integrations', ['sync_status' => 'syncing'], ['id' => $params['id']]);
    
    $startTime = microtime(true);
    $result = ['processed' => 0, 'created' => 0, 'updated' => 0, 'errors' => []];
    
    try {
        $credentials = json_decode(base64_decode($integration['credentials']), true);
        
        switch ($integration['provider']) {
            case 'stripe':
                $result = syncStripePayments($credentials, $admin['id']);
                break;
            case 'paypal':
                $result = syncPayPalPayments($credentials, $admin['id']);
                break;
            case 'google_analytics':
                $result = syncGoogleAnalytics($credentials, $admin['id']);
                break;
            default:
                throw new Exception('Provider non supporté: ' . $integration['provider']);
        }
        
        $duration = (int)((microtime(true) - $startTime) * 1000);
        
        // Log de sync
        Database::insert('sync_logs', [
            'integration_id' => $params['id'],
            'action' => 'sync_payments',
            'status' => 'success',
            'records_processed' => $result['processed'],
            'records_created' => $result['created'],
            'records_updated' => $result['updated'],
            'duration_ms' => $duration
        ]);
        
        Database::update('integrations', [
            'last_sync_at' => date('Y-m-d H:i:s'),
            'sync_status' => 'success',
            'sync_error' => null
        ], ['id' => $params['id']]);
        
        response([
            'success' => true,
            'processed' => $result['processed'],
            'created' => $result['created'],
            'updated' => $result['updated'],
            'duration' => $duration
        ]);
        
    } catch (Exception $e) {
        Database::update('integrations', [
            'sync_status' => 'error',
            'sync_error' => $e->getMessage()
        ], ['id' => $params['id']]);
        
        Database::insert('sync_logs', [
            'integration_id' => $params['id'],
            'action' => 'sync_payments',
            'status' => 'error',
            'error_message' => $e->getMessage()
        ]);
        
        error('Erreur de synchronisation: ' . $e->getMessage(), 500);
    }
}

// GET /integrations/{id}/logs - Logs de synchronisation
if ($method === 'GET' && ($params = matchRoute('/integrations/{id}/logs', $uri))) {
    $admin = requireAuth();
    
    $integration = Database::fetch(
        "SELECT * FROM integrations WHERE id = ? AND admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    if (!$integration) {
        error('Intégration non trouvée', 404);
    }
    
    $logs = Database::fetchAll(
        "SELECT * FROM sync_logs WHERE integration_id = ? ORDER BY created_at DESC LIMIT 50",
        [$params['id']]
    );
    
    $result = array_map(fn($l) => [
        'id' => $l['id'],
        'action' => $l['action'],
        'status' => $l['status'],
        'processed' => (int)$l['records_processed'],
        'created' => (int)$l['records_created'],
        'updated' => (int)$l['records_updated'],
        'error' => $l['error_message'],
        'duration' => (int)$l['duration_ms'],
        'createdAt' => $l['created_at']
    ], $logs);
    
    response($result);
}

// Fonction helper pour sync Stripe
function syncStripePayments(array $credentials, string $adminId): array {
    $apiKey = $credentials['api_key'] ?? '';
    if (!$apiKey) {
        throw new Exception('Clé API Stripe manquante');
    }
    
    // Récupérer le premier site pour associer les paiements
    $site = Database::fetch("SELECT id FROM sites LIMIT 1");
    $siteId = $site['id'] ?? null;
    
    // Appel API Stripe
    $ch = curl_init('https://api.stripe.com/v1/charges?limit=100');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $apiKey],
        CURLOPT_TIMEOUT => 30
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) {
        throw new Exception('Erreur API Stripe: ' . $httpCode);
    }
    
    $data = json_decode($response, true);
    $charges = $data['data'] ?? [];
    
    $result = ['processed' => 0, 'created' => 0, 'updated' => 0];
    
    foreach ($charges as $charge) {
        $result['processed']++;
        
        // Vérifier si déjà importé
        $existing = Database::fetch(
            "SELECT id FROM payments WHERE external_id = ? AND provider = 'stripe'",
            [$charge['id']]
        );
        
        if ($existing) {
            $result['updated']++;
            continue;
        }
        
        // Créer le paiement
        $id = generateId('pay');
        Database::insert('payments', [
            'id' => $id,
            'site_id' => $siteId,
            'external_id' => $charge['id'],
            'amount' => $charge['amount'] / 100, // Stripe utilise les centimes
            'currency' => strtoupper($charge['currency']),
            'status' => $charge['paid'] ? 'completed' : ($charge['refunded'] ? 'refunded' : 'failed'),
            'payment_method' => $charge['payment_method_details']['type'] ?? 'card',
            'provider' => 'stripe',
            'provider_fee' => ($charge['balance_transaction']['fee'] ?? 0) / 100,
            'net_amount' => ($charge['amount'] - ($charge['balance_transaction']['fee'] ?? 0)) / 100,
            'metadata' => json_encode(['stripe_charge_id' => $charge['id']]),
            'paid_at' => $charge['paid'] ? date('Y-m-d H:i:s', $charge['created']) : null,
            'created_at' => date('Y-m-d H:i:s', $charge['created'])
        ]);
        
        $result['created']++;
    }
    
    return $result;
}

// Fonction helper pour sync PayPal
function syncPayPalPayments(array $credentials, string $adminId): array {
    $clientId = $credentials['client_id'] ?? '';
    $clientSecret = $credentials['client_secret'] ?? '';
    
    if (!$clientId || !$clientSecret) {
        throw new Exception('Credentials PayPal manquants');
    }
    
    // Obtenir un access token
    $ch = curl_init('https://api-m.paypal.com/v1/oauth2/token');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => 'grant_type=client_credentials',
        CURLOPT_USERPWD => $clientId . ':' . $clientSecret,
        CURLOPT_HTTPHEADER => ['Accept: application/json', 'Accept-Language: en_US'],
        CURLOPT_TIMEOUT => 30
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) {
        throw new Exception('Erreur auth PayPal: ' . $httpCode);
    }
    
    $tokenData = json_decode($response, true);
    $accessToken = $tokenData['access_token'] ?? '';
    
    if (!$accessToken) {
        throw new Exception('Token PayPal non obtenu');
    }
    
    // Récupérer les transactions
    $startDate = date('Y-m-d', strtotime('-30 days')) . 'T00:00:00Z';
    $endDate = date('Y-m-d') . 'T23:59:59Z';
    
    $ch = curl_init("https://api-m.paypal.com/v1/reporting/transactions?start_date=$startDate&end_date=$endDate&fields=all");
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'Authorization: Bearer ' . $accessToken,
            'Content-Type: application/json'
        ],
        CURLOPT_TIMEOUT => 30
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) {
        throw new Exception('Erreur API PayPal: ' . $httpCode);
    }
    
    $data = json_decode($response, true);
    $transactions = $data['transaction_details'] ?? [];
    
    $site = Database::fetch("SELECT id FROM sites LIMIT 1");
    $siteId = $site['id'] ?? null;
    
    $result = ['processed' => 0, 'created' => 0, 'updated' => 0];
    
    foreach ($transactions as $tx) {
        $info = $tx['transaction_info'] ?? [];
        if (($info['transaction_event_code'] ?? '') !== 'T0006') continue; // Uniquement les paiements reçus
        
        $result['processed']++;
        
        $txId = $info['transaction_id'] ?? '';
        $existing = Database::fetch(
            "SELECT id FROM payments WHERE external_id = ? AND provider = 'paypal'",
            [$txId]
        );
        
        if ($existing) {
            $result['updated']++;
            continue;
        }
        
        $amount = abs((float)($info['transaction_amount']['value'] ?? 0));
        $fee = abs((float)($info['fee_amount']['value'] ?? 0));
        
        $id = generateId('pay');
        Database::insert('payments', [
            'id' => $id,
            'site_id' => $siteId,
            'external_id' => $txId,
            'amount' => $amount,
            'currency' => $info['transaction_amount']['currency_code'] ?? 'EUR',
            'status' => 'completed',
            'payment_method' => 'paypal',
            'provider' => 'paypal',
            'provider_fee' => $fee,
            'net_amount' => $amount - $fee,
            'metadata' => json_encode(['paypal_tx_id' => $txId]),
            'paid_at' => date('Y-m-d H:i:s', strtotime($info['transaction_initiation_date'] ?? 'now')),
            'created_at' => date('Y-m-d H:i:s')
        ]);
        
        $result['created']++;
    }
    
    return $result;
}

// Fonction helper pour sync Google Analytics
function syncGoogleAnalytics(array $credentials, string $adminId): array {
    $propertyId = $credentials['property_id'] ?? '';
    $credentialsJson = $credentials['credentials_json'] ?? '';
    
    if (!$propertyId) {
        throw new Exception('ID de propriété Google Analytics manquant');
    }
    
    if (!$credentialsJson) {
        throw new Exception('Credentials JSON manquants');
    }
    
    // Parser les credentials JSON
    $serviceAccount = is_string($credentialsJson) ? json_decode($credentialsJson, true) : $credentialsJson;
    
    if (!$serviceAccount || !isset($serviceAccount['client_email']) || !isset($serviceAccount['private_key'])) {
        throw new Exception('Format des credentials invalide');
    }
    
    // Générer un JWT pour l'authentification
    $now = time();
    $header = base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
    $claims = base64_encode(json_encode([
        'iss' => $serviceAccount['client_email'],
        'scope' => 'https://www.googleapis.com/auth/analytics.readonly',
        'aud' => 'https://oauth2.googleapis.com/token',
        'iat' => $now,
        'exp' => $now + 3600
    ]));
    
    $signatureInput = $header . '.' . $claims;
    $privateKey = openssl_pkey_get_private($serviceAccount['private_key']);
    
    if (!$privateKey) {
        throw new Exception('Clé privée invalide');
    }
    
    openssl_sign($signatureInput, $signature, $privateKey, OPENSSL_ALGO_SHA256);
    $jwt = $signatureInput . '.' . base64_encode($signature);
    
    // Échanger le JWT contre un access token
    $ch = curl_init('https://oauth2.googleapis.com/token');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion' => $jwt
        ]),
        CURLOPT_TIMEOUT => 30
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) {
        throw new Exception('Erreur authentification Google: ' . $response);
    }
    
    $tokenData = json_decode($response, true);
    $accessToken = $tokenData['access_token'] ?? '';
    
    if (!$accessToken) {
        throw new Exception('Token Google non obtenu');
    }
    
    // Récupérer les données Analytics (derniers 30 jours)
    $startDate = date('Y-m-d', strtotime('-30 days'));
    $endDate = date('Y-m-d');
    
    $requestBody = json_encode([
        'dateRanges' => [['startDate' => $startDate, 'endDate' => $endDate]],
        'dimensions' => [
            ['name' => 'date'],
            ['name' => 'sessionSource'],
            ['name' => 'country']
        ],
        'metrics' => [
            ['name' => 'sessions'],
            ['name' => 'totalUsers'],
            ['name' => 'newUsers'],
            ['name' => 'screenPageViews'],
            ['name' => 'averageSessionDuration'],
            ['name' => 'bounceRate']
        ]
    ]);
    
    $ch = curl_init("https://analyticsdata.googleapis.com/v1beta/properties/{$propertyId}:runReport");
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $requestBody,
        CURLOPT_HTTPHEADER => [
            'Authorization: Bearer ' . $accessToken,
            'Content-Type: application/json'
        ],
        CURLOPT_TIMEOUT => 30
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) {
        $error = json_decode($response, true);
        throw new Exception('Erreur API Analytics: ' . ($error['error']['message'] ?? $response));
    }
    
    $data = json_decode($response, true);
    $rows = $data['rows'] ?? [];
    
    // Récupérer le premier site
    $site = Database::fetch("SELECT id FROM sites LIMIT 1");
    $siteId = $site['id'] ?? null;
    
    $result = ['processed' => 0, 'created' => 0, 'updated' => 0];
    
    // Stocker les données dans la table analytics
    foreach ($rows as $row) {
        $dimensions = $row['dimensionValues'] ?? [];
        $metrics = $row['metricValues'] ?? [];
        
        $date = $dimensions[0]['value'] ?? date('Ymd');
        $source = $dimensions[1]['value'] ?? 'direct';
        $country = $dimensions[2]['value'] ?? 'unknown';
        
        // Formater la date (YYYYMMDD -> YYYY-MM-DD)
        $formattedDate = substr($date, 0, 4) . '-' . substr($date, 4, 2) . '-' . substr($date, 6, 2);
        
        $result['processed']++;
        
        // Vérifier si déjà importé
        $existing = Database::fetch(
            "SELECT id FROM analytics WHERE site_id = ? AND DATE(recorded_at) = ? AND metric = 'ga_sessions' AND source = ?",
            [$siteId, $formattedDate, $source]
        );
        
        if ($existing) {
            $result['updated']++;
            continue;
        }
        
        // Insérer les métriques
        $metricsData = [
            'ga_sessions' => (float)($metrics[0]['value'] ?? 0),
            'ga_users' => (float)($metrics[1]['value'] ?? 0),
            'ga_new_users' => (float)($metrics[2]['value'] ?? 0),
            'ga_pageviews' => (float)($metrics[3]['value'] ?? 0),
            'ga_avg_session_duration' => (float)($metrics[4]['value'] ?? 0),
            'ga_bounce_rate' => (float)($metrics[5]['value'] ?? 0)
        ];
        
        foreach ($metricsData as $metricName => $metricValue) {
            Database::insert('analytics', [
                'site_id' => $siteId,
                'metric' => $metricName,
                'value' => $metricValue,
                'source' => $source,
                'country' => $country,
                'recorded_at' => $formattedDate . ' 00:00:00'
            ]);
        }
        
        $result['created']++;
    }
    
    return $result;
}

// ============== RECHERCHE GLOBALE ==============

// GET /search - Recherche globale
if ($method === 'GET' && $uri === '/search') {
    $admin = requireAuth();
    $query = trim($_GET['q'] ?? '');
    $type = $_GET['type'] ?? null; // user, payment, site, subscription
    $limit = min((int)($_GET['limit'] ?? 20), 50);
    
    if (strlen($query) < 2) {
        response([]);
    }
    
    $results = [];
    $searchTerm = '%' . $query . '%';
    
    // Recherche dans les utilisateurs
    if (!$type || $type === 'user') {
        $users = Database::fetchAll(
            "SELECT u.*, s.name as site_name FROM users u 
             LEFT JOIN sites s ON u.site_id = s.id
             WHERE u.email LIKE ? OR u.name LIKE ? OR u.external_id LIKE ?
             ORDER BY u.created_at DESC LIMIT ?",
            [$searchTerm, $searchTerm, $searchTerm, $limit]
        );
        
        foreach ($users as $u) {
            $results[] = [
                'type' => 'user',
                'id' => $u['id'],
                'title' => $u['name'] ?: $u['email'],
                'subtitle' => $u['email'],
                'icon' => '👤',
                'site' => $u['site_name'],
                'url' => '/users/' . $u['id'],
                'createdAt' => $u['created_at']
            ];
        }
    }
    
    // Recherche dans les paiements
    if (!$type || $type === 'payment') {
        $payments = Database::fetchAll(
            "SELECT p.*, s.name as site_name FROM payments p 
             LEFT JOIN sites s ON p.site_id = s.id
             WHERE p.id LIKE ? OR p.external_id LIKE ? OR CAST(p.amount AS CHAR) LIKE ?
             ORDER BY p.created_at DESC LIMIT ?",
            [$searchTerm, $searchTerm, $searchTerm, $limit]
        );
        
        foreach ($payments as $p) {
            $results[] = [
                'type' => 'payment',
                'id' => $p['id'],
                'title' => number_format($p['amount'], 2) . ' ' . $p['currency'],
                'subtitle' => $p['status'] . ' • ' . ($p['payment_method'] ?? 'N/A'),
                'icon' => '💳',
                'site' => $p['site_name'],
                'url' => '/payments?id=' . $p['id'],
                'createdAt' => $p['created_at']
            ];
        }
    }
    
    // Recherche dans les sites
    if (!$type || $type === 'site') {
        $sites = Database::fetchAll(
            "SELECT * FROM sites WHERE name LIKE ? OR url LIKE ? OR id LIKE ? LIMIT ?",
            [$searchTerm, $searchTerm, $searchTerm, $limit]
        );
        
        foreach ($sites as $s) {
            $results[] = [
                'type' => 'site',
                'id' => $s['id'],
                'title' => $s['name'],
                'subtitle' => $s['url'],
                'icon' => '🌐',
                'site' => null,
                'url' => '/sites/' . $s['id'],
                'status' => $s['status'],
                'createdAt' => $s['created_at']
            ];
        }
    }
    
    // Recherche dans les abonnements
    if (!$type || $type === 'subscription') {
        $subs = Database::fetchAll(
            "SELECT sub.*, s.name as site_name FROM subscriptions sub 
             LEFT JOIN sites s ON sub.site_id = s.id
             WHERE sub.plan LIKE ? OR sub.external_id LIKE ?
             ORDER BY sub.created_at DESC LIMIT ?",
            [$searchTerm, $searchTerm, $limit]
        );
        
        foreach ($subs as $sub) {
            $results[] = [
                'type' => 'subscription',
                'id' => $sub['id'],
                'title' => 'Plan ' . $sub['plan'],
                'subtitle' => number_format($sub['amount'], 2) . ' ' . $sub['currency'] . '/' . ($sub['interval_type'] ?? 'mois'),
                'icon' => '🔄',
                'site' => $sub['site_name'],
                'url' => '/subscriptions?id=' . $sub['id'],
                'status' => $sub['status'],
                'createdAt' => $sub['created_at']
            ];
        }
    }
    
    // Trier par date
    usort($results, fn($a, $b) => strtotime($b['createdAt']) - strtotime($a['createdAt']));
    
    // Limiter le total
    $results = array_slice($results, 0, $limit);
    
    response([
        'query' => $query,
        'count' => count($results),
        'results' => $results
    ]);
}

// GET /search/recent - Recherches récentes (simplifié - basé sur l'activité)
if ($method === 'GET' && $uri === '/search/recent') {
    $admin = requireAuth();
    
    // Retourner les dernières entités consultées/modifiées
    $recent = [
        'users' => Database::fetchAll("SELECT id, email, name FROM users ORDER BY created_at DESC LIMIT 5"),
        'payments' => Database::fetchAll("SELECT id, amount, currency, status FROM payments ORDER BY created_at DESC LIMIT 5"),
        'sites' => Database::fetchAll("SELECT id, name, url FROM sites ORDER BY created_at DESC LIMIT 5")
    ];
    
    response($recent);
}

// ============== RAPPORTS AVANCÉS ==============

// GET /reports/scheduled - Rapports programmés
if ($method === 'GET' && $uri === '/reports/scheduled') {
    $admin = requireAuth();
    
    $reports = Database::fetchAll(
        "SELECT * FROM scheduled_reports WHERE admin_id = ? ORDER BY created_at DESC",
        [$admin['id']]
    );
    
    $result = array_map(fn($r) => [
        'id' => $r['id'],
        'name' => $r['name'],
        'reportType' => $r['report_type'],
        'frequency' => $r['frequency'],
        'dayOfWeek' => $r['day_of_week'],
        'dayOfMonth' => $r['day_of_month'],
        'hour' => (int)$r['hour'],
        'recipients' => json_decode($r['recipients'] ?? '[]', true),
        'format' => $r['format'],
        'includeCharts' => (bool)$r['include_charts'],
        'siteIds' => json_decode($r['site_ids'] ?? 'null', true),
        'isActive' => (bool)$r['is_active'],
        'lastSentAt' => $r['last_sent_at'],
        'nextSendAt' => $r['next_send_at'],
        'createdAt' => $r['created_at']
    ], $reports);
    
    response($result);
}

// POST /reports/scheduled - Créer un rapport programmé
if ($method === 'POST' && $uri === '/reports/scheduled') {
    $admin = requireAuth();
    $input = getInput();
    
    $name = $input['name'] ?? '';
    $reportType = $input['reportType'] ?? 'full';
    $frequency = $input['frequency'] ?? 'weekly';
    
    if (!$name) {
        error('Nom du rapport requis', 400);
    }
    
    // Calculer la prochaine date d'envoi
    $nextSend = calculateNextSendDate($frequency, $input['dayOfWeek'] ?? null, $input['dayOfMonth'] ?? null, $input['hour'] ?? 8);
    
    $id = generateId('report');
    Database::insert('scheduled_reports', [
        'id' => $id,
        'admin_id' => $admin['id'],
        'name' => $name,
        'report_type' => $reportType,
        'frequency' => $frequency,
        'day_of_week' => $input['dayOfWeek'] ?? null,
        'day_of_month' => $input['dayOfMonth'] ?? null,
        'hour' => $input['hour'] ?? 8,
        'recipients' => json_encode($input['recipients'] ?? [$admin['email']]),
        'format' => $input['format'] ?? 'pdf',
        'include_charts' => ($input['includeCharts'] ?? true) ? 1 : 0,
        'site_ids' => isset($input['siteIds']) ? json_encode($input['siteIds']) : null,
        'is_active' => 1,
        'next_send_at' => $nextSend
    ]);
    
    response(['id' => $id, 'nextSendAt' => $nextSend], 201);
}

// PUT /reports/scheduled/{id} - Modifier un rapport programmé
if ($method === 'PUT' && ($params = matchRoute('/reports/scheduled/{id}', $uri))) {
    $admin = requireAuth();
    $input = getInput();
    
    $report = Database::fetch(
        "SELECT * FROM scheduled_reports WHERE id = ? AND admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    if (!$report) {
        error('Rapport non trouvé', 404);
    }
    
    $updateData = [];
    if (isset($input['name'])) $updateData['name'] = $input['name'];
    if (isset($input['reportType'])) $updateData['report_type'] = $input['reportType'];
    if (isset($input['frequency'])) $updateData['frequency'] = $input['frequency'];
    if (isset($input['dayOfWeek'])) $updateData['day_of_week'] = $input['dayOfWeek'];
    if (isset($input['dayOfMonth'])) $updateData['day_of_month'] = $input['dayOfMonth'];
    if (isset($input['hour'])) $updateData['hour'] = $input['hour'];
    if (isset($input['recipients'])) $updateData['recipients'] = json_encode($input['recipients']);
    if (isset($input['format'])) $updateData['format'] = $input['format'];
    if (isset($input['includeCharts'])) $updateData['include_charts'] = $input['includeCharts'] ? 1 : 0;
    if (isset($input['siteIds'])) $updateData['site_ids'] = json_encode($input['siteIds']);
    if (isset($input['isActive'])) $updateData['is_active'] = $input['isActive'] ? 1 : 0;
    
    // Recalculer la prochaine date si paramètres changés
    if (isset($input['frequency']) || isset($input['dayOfWeek']) || isset($input['dayOfMonth']) || isset($input['hour'])) {
        $updateData['next_send_at'] = calculateNextSendDate(
            $input['frequency'] ?? $report['frequency'],
            $input['dayOfWeek'] ?? $report['day_of_week'],
            $input['dayOfMonth'] ?? $report['day_of_month'],
            $input['hour'] ?? $report['hour']
        );
    }
    
    if (!empty($updateData)) {
        Database::update('scheduled_reports', $updateData, ['id' => $params['id']]);
    }
    
    response(['success' => true]);
}

// DELETE /reports/scheduled/{id} - Supprimer un rapport programmé
if ($method === 'DELETE' && ($params = matchRoute('/reports/scheduled/{id}', $uri))) {
    $admin = requireAuth();
    
    Database::query(
        "DELETE FROM scheduled_reports WHERE id = ? AND admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    response(['success' => true]);
}

// POST /reports/generate - Générer un rapport à la demande
if ($method === 'POST' && $uri === '/reports/generate') {
    $admin = requireAuth();
    $input = getInput();
    
    $reportType = $input['reportType'] ?? 'full';
    $format = $input['format'] ?? 'pdf';
    $periodStart = $input['periodStart'] ?? date('Y-m-01');
    $periodEnd = $input['periodEnd'] ?? date('Y-m-d');
    $siteIds = $input['siteIds'] ?? null;
    
    // Collecter les données
    $data = generateReportData($reportType, $periodStart, $periodEnd, $siteIds);
    
    $id = generateId('report');
    $name = 'Rapport ' . ucfirst($reportType) . ' - ' . date('d/m/Y', strtotime($periodStart)) . ' au ' . date('d/m/Y', strtotime($periodEnd));
    
    Database::insert('generated_reports', [
        'id' => $id,
        'admin_id' => $admin['id'],
        'name' => $name,
        'report_type' => $reportType,
        'period_start' => $periodStart,
        'period_end' => $periodEnd,
        'format' => $format,
        'data' => json_encode($data)
    ]);
    
    // Si PDF demandé, générer le HTML pour conversion
    if ($format === 'pdf') {
        $html = generateReportHTML($data, $name, $periodStart, $periodEnd);
        
        response([
            'id' => $id,
            'name' => $name,
            'format' => $format,
            'html' => $html,
            'data' => $data
        ]);
    }
    
    response([
        'id' => $id,
        'name' => $name,
        'format' => $format,
        'data' => $data
    ]);
}

// GET /reports/generated - Liste des rapports générés
if ($method === 'GET' && $uri === '/reports/generated') {
    $admin = requireAuth();
    
    $reports = Database::fetchAll(
        "SELECT id, name, report_type, period_start, period_end, format, file_size, created_at 
         FROM generated_reports WHERE admin_id = ? ORDER BY created_at DESC LIMIT 50",
        [$admin['id']]
    );
    
    response(array_map(fn($r) => [
        'id' => $r['id'],
        'name' => $r['name'],
        'reportType' => $r['report_type'],
        'periodStart' => $r['period_start'],
        'periodEnd' => $r['period_end'],
        'format' => $r['format'],
        'fileSize' => $r['file_size'],
        'createdAt' => $r['created_at']
    ], $reports));
}

// GET /reports/generated/{id} - Télécharger un rapport
if ($method === 'GET' && ($params = matchRoute('/reports/generated/{id}', $uri))) {
    $admin = requireAuth();
    
    $report = Database::fetch(
        "SELECT * FROM generated_reports WHERE id = ? AND admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    if (!$report) {
        error('Rapport non trouvé', 404);
    }
    
    $data = json_decode($report['data'], true);
    
    response([
        'id' => $report['id'],
        'name' => $report['name'],
        'reportType' => $report['report_type'],
        'periodStart' => $report['period_start'],
        'periodEnd' => $report['period_end'],
        'format' => $report['format'],
        'data' => $data,
        'html' => generateReportHTML($data, $report['name'], $report['period_start'], $report['period_end'])
    ]);
}

// Helper pour calculer la prochaine date d'envoi
function calculateNextSendDate(string $frequency, ?int $dayOfWeek, ?int $dayOfMonth, int $hour): string {
    $now = new DateTime();
    $next = clone $now;
    $next->setTime($hour, 0, 0);
    
    switch ($frequency) {
        case 'daily':
            if ($next <= $now) {
                $next->modify('+1 day');
            }
            break;
            
        case 'weekly':
            $targetDay = $dayOfWeek ?? 1; // Lundi par défaut
            $currentDay = (int)$next->format('w');
            $daysUntil = ($targetDay - $currentDay + 7) % 7;
            if ($daysUntil === 0 && $next <= $now) {
                $daysUntil = 7;
            }
            $next->modify("+$daysUntil days");
            break;
            
        case 'monthly':
            $targetDay = $dayOfMonth ?? 1;
            $next->setDate((int)$next->format('Y'), (int)$next->format('m'), min($targetDay, 28));
            if ($next <= $now) {
                $next->modify('+1 month');
            }
            break;
    }
    
    return $next->format('Y-m-d H:i:s');
}

// Helper pour générer les données du rapport
function generateReportData(string $type, string $start, string $end, ?array $siteIds): array {
    $siteCondition = '';
    $params = [$start, $end . ' 23:59:59'];
    
    if ($siteIds && count($siteIds) > 0) {
        $placeholders = implode(',', array_fill(0, count($siteIds), '?'));
        $siteCondition = " AND site_id IN ($placeholders)";
        $params = array_merge($params, $siteIds);
    }
    
    $data = [
        'period' => ['start' => $start, 'end' => $end],
        'generatedAt' => date('Y-m-d H:i:s')
    ];
    
    // Revenus
    if (in_array($type, ['full', 'revenue'])) {
        $data['revenue'] = [
            'total' => (float)Database::fetchColumn(
                "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status = 'completed' AND created_at BETWEEN ? AND ? $siteCondition",
                $params
            ),
            'count' => (int)Database::fetchColumn(
                "SELECT COUNT(*) FROM payments WHERE status = 'completed' AND created_at BETWEEN ? AND ? $siteCondition",
                $params
            ),
            'byDay' => Database::fetchAll(
                "SELECT DATE(created_at) as date, SUM(amount) as amount, COUNT(*) as count 
                 FROM payments WHERE status = 'completed' AND created_at BETWEEN ? AND ? $siteCondition
                 GROUP BY DATE(created_at) ORDER BY date",
                $params
            ),
            'byMethod' => Database::fetchAll(
                "SELECT payment_method, SUM(amount) as amount, COUNT(*) as count 
                 FROM payments WHERE status = 'completed' AND created_at BETWEEN ? AND ? $siteCondition
                 GROUP BY payment_method",
                $params
            )
        ];
    }
    
    // Utilisateurs
    if (in_array($type, ['full', 'users'])) {
        $data['users'] = [
            'total' => (int)Database::fetchColumn(
                "SELECT COUNT(*) FROM users WHERE created_at BETWEEN ? AND ? $siteCondition",
                $params
            ),
            'byDay' => Database::fetchAll(
                "SELECT DATE(created_at) as date, COUNT(*) as count 
                 FROM users WHERE created_at BETWEEN ? AND ? $siteCondition
                 GROUP BY DATE(created_at) ORDER BY date",
                $params
            )
        ];
    }
    
    // Abonnements
    if (in_array($type, ['full', 'subscriptions'])) {
        $data['subscriptions'] = [
            'active' => (int)Database::fetchColumn(
                "SELECT COUNT(*) FROM subscriptions WHERE status = 'active'" . str_replace('site_id', 'site_id', $siteCondition),
                $siteIds ?: []
            ),
            'mrr' => (float)Database::fetchColumn(
                "SELECT COALESCE(SUM(amount), 0) FROM subscriptions WHERE status = 'active' AND interval_type = 'month'" . str_replace('site_id', 'site_id', $siteCondition),
                $siteIds ?: []
            ),
            'churn' => (int)Database::fetchColumn(
                "SELECT COUNT(*) FROM subscriptions WHERE status = 'cancelled' AND cancelled_at BETWEEN ? AND ? $siteCondition",
                $params
            )
        ];
    }
    
    // Top clients
    if (in_array($type, ['full'])) {
        $data['topCustomers'] = Database::fetchAll(
            "SELECT u.id, u.email, u.name, SUM(p.amount) as total_spent, COUNT(p.id) as payment_count
             FROM users u 
             JOIN payments p ON u.id = p.user_id 
             WHERE p.status = 'completed' AND p.created_at BETWEEN ? AND ? $siteCondition
             GROUP BY u.id ORDER BY total_spent DESC LIMIT 10",
            $params
        );
    }
    
    return $data;
}

// Helper pour générer le HTML du rapport
function generateReportHTML(array $data, string $title, string $start, string $end): string {
    $revenue = $data['revenue'] ?? [];
    $users = $data['users'] ?? [];
    $subs = $data['subscriptions'] ?? [];
    
    $html = '<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>' . htmlspecialchars($title) . '</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 40px; color: #1a1a1a; background: #fff; }
        .header { text-align: center; margin-bottom: 40px; padding-bottom: 20px; border-bottom: 2px solid #e5e5e5; }
        .header h1 { font-size: 28px; margin-bottom: 8px; }
        .header p { color: #666; font-size: 14px; }
        .period { background: #f5f5f5; padding: 12px 20px; border-radius: 8px; display: inline-block; margin-top: 16px; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 40px; }
        .stat-card { background: #f8f9fa; border-radius: 12px; padding: 24px; text-align: center; }
        .stat-value { font-size: 32px; font-weight: 700; color: #2563eb; }
        .stat-label { font-size: 14px; color: #666; margin-top: 8px; }
        .section { margin-bottom: 40px; }
        .section-title { font-size: 20px; font-weight: 600; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #e5e5e5; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #e5e5e5; }
        th { background: #f8f9fa; font-weight: 600; }
        .footer { margin-top: 60px; text-align: center; color: #999; font-size: 12px; padding-top: 20px; border-top: 1px solid #e5e5e5; }
        @media print { body { padding: 20px; } }
    </style>
</head>
<body>
    <div class="header">
        <h1>📊 ' . htmlspecialchars($title) . '</h1>
        <p>Généré le ' . date('d/m/Y à H:i') . '</p>
        <div class="period">Du ' . date('d/m/Y', strtotime($start)) . ' au ' . date('d/m/Y', strtotime($end)) . '</div>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value">' . number_format($revenue['total'] ?? 0, 2, ',', ' ') . ' €</div>
            <div class="stat-label">Revenus totaux</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">' . number_format($revenue['count'] ?? 0) . '</div>
            <div class="stat-label">Paiements</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">' . number_format($users['total'] ?? 0) . '</div>
            <div class="stat-label">Nouveaux utilisateurs</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">' . number_format($subs['mrr'] ?? 0, 2, ',', ' ') . ' €</div>
            <div class="stat-label">MRR</div>
        </div>
    </div>';
    
    // Top clients
    if (!empty($data['topCustomers'])) {
        $html .= '
    <div class="section">
        <h2 class="section-title">🏆 Top 10 Clients</h2>
        <table>
            <thead>
                <tr>
                    <th>Client</th>
                    <th>Email</th>
                    <th>Paiements</th>
                    <th>Total dépensé</th>
                </tr>
            </thead>
            <tbody>';
        
        foreach ($data['topCustomers'] as $c) {
            $html .= '
                <tr>
                    <td>' . htmlspecialchars($c['name'] ?: 'N/A') . '</td>
                    <td>' . htmlspecialchars($c['email']) . '</td>
                    <td>' . $c['payment_count'] . '</td>
                    <td><strong>' . number_format($c['total_spent'], 2, ',', ' ') . ' €</strong></td>
                </tr>';
        }
        
        $html .= '
            </tbody>
        </table>
    </div>';
    }
    
    // Revenus par méthode
    if (!empty($revenue['byMethod'])) {
        $html .= '
    <div class="section">
        <h2 class="section-title">💳 Revenus par méthode de paiement</h2>
        <table>
            <thead>
                <tr>
                    <th>Méthode</th>
                    <th>Nombre</th>
                    <th>Montant</th>
                </tr>
            </thead>
            <tbody>';
        
        foreach ($revenue['byMethod'] as $m) {
            $html .= '
                <tr>
                    <td>' . ucfirst($m['payment_method'] ?: 'Autre') . '</td>
                    <td>' . $m['count'] . '</td>
                    <td><strong>' . number_format($m['amount'], 2, ',', ' ') . ' €</strong></td>
                </tr>';
        }
        
        $html .= '
            </tbody>
        </table>
    </div>';
    }
    
    $html .= '
    <div class="footer">
        <p>Rapport généré automatiquement par Noteso</p>
    </div>
</body>
</html>';
    
    return $html;
}

// ============== EXPORT ==============

if ($method === 'GET' && $uri === '/export/payments') {
    requireAuth();
    
    $format = $_GET['format'] ?? 'csv';
    
    $payments = Database::fetchAll(
        "SELECT p.*, s.name as site_name 
         FROM payments p 
         LEFT JOIN sites s ON p.site_id = s.id 
         ORDER BY p.created_at DESC"
    );
    
    if ($format === 'csv') {
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="paiements_' . date('Y-m-d') . '.csv"');
        
        $output = fopen('php://output', 'w');
        fprintf($output, chr(0xEF).chr(0xBB).chr(0xBF));
        fputcsv($output, ['ID', 'Date', 'Site', 'Montant', 'Devise', 'Méthode', 'Statut'], ';');
        
        foreach ($payments as $p) {
            fputcsv($output, [
                $p['id'],
                date('d/m/Y H:i', strtotime($p['created_at'])),
                $p['site_name'] ?? 'N/A',
                number_format($p['amount'], 2, ',', ''),
                $p['currency'],
                $p['payment_method'] ?? 'N/A',
                $p['status']
            ], ';');
        }
        fclose($output);
        exit;
    }
    
    response($payments);
}

// ============== REPORTS ==============

if ($method === 'GET' && $uri === '/reports') {
    $reports = Database::fetchAll("SELECT * FROM reports ORDER BY created_at DESC LIMIT 20");
    
    $result = array_map(fn($r) => [
        'id' => $r['id'],
        'type' => $r['type'],
        'siteId' => $r['site_id'],
        'period' => json_decode($r['period'] ?? '{}', true),
        'data' => json_decode($r['data'] ?? '{}', true),
        'createdAt' => $r['created_at']
    ], $reports);
    
    response($result);
}

if ($method === 'POST' && $uri === '/reports/generate') {
    $input = getInput();
    $siteId = $input['siteId'] ?? null;
    $type = $input['type'] ?? 'monthly';
    
    $startOfMonth = date('Y-m-01');
    
    // Construire les requêtes avec filtre site optionnel
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
    
    if ($format === 'html') {
        header('Content-Type: text/html; charset=utf-8');
        $label = match($type) { 'daily' => 'Journalier', 'weekly' => 'Hebdomadaire', 'monthly' => 'Mensuel', default => 'Rapport' };
        echo "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Rapport {$label}</title>
        <style>body{font-family:Inter,sans-serif;max-width:800px;margin:40px auto;padding:20px;background:#0a0a0b;color:#fafafa}
        .card{background:#141416;border:1px solid #27272a;border-radius:12px;padding:24px;margin-bottom:20px}
        .stat{display:inline-block;margin-right:40px;text-align:center;padding:20px}
        .stat-value{font-size:32px;font-weight:700;color:#3b82f6}
        .stat-label{color:#a1a1aa;font-size:13px}</style></head><body>
        <div class='card'><h1>📊 Rapport {$label}</h1><p style='color:#a1a1aa'>Période: {$report['period']['start']} → {$report['period']['end']}</p></div>
        <div class='card'><h2>Résumé</h2>
        <div class='stat'><div class='stat-value'>" . number_format($report['summary']['totalRevenue'], 2) . " €</div><div class='stat-label'>Revenus</div></div>
        <div class='stat'><div class='stat-value'>{$report['summary']['totalPayments']}</div><div class='stat-label'>Paiements</div></div>
        <div class='stat'><div class='stat-value'>{$report['summary']['newUsers']}</div><div class='stat-label'>Nouveaux utilisateurs</div></div>
        </div></body></html>";
        exit;
    }
    
    response($report);
}

// ============== TEMPS RÉEL (POLLING) ==============

// GET /realtime/events - Récupérer les événements récents
if ($method === 'GET' && $uri === '/realtime/events') {
    $admin = requireAuth();
    $since = $_GET['since'] ?? null;
    $limit = min((int)($_GET['limit'] ?? 20), 100);
    
    $params = [$admin['id']];
    $whereClause = "WHERE (admin_id = ? OR admin_id IS NULL)";
    
    if ($since) {
        $whereClause .= " AND created_at > ?";
        $params[] = $since;
    }
    
    $events = Database::fetchAll(
        "SELECT * FROM realtime_events $whereClause ORDER BY created_at DESC LIMIT ?",
        array_merge($params, [$limit])
    );
    
    // Marquer comme lus
    if (!empty($events)) {
        $ids = array_column($events, 'id');
        Database::query(
            "UPDATE realtime_events SET is_read = 1 WHERE id IN (" . implode(',', $ids) . ")"
        );
    }
    
    response([
        'events' => array_map(fn($e) => [
            'id' => $e['id'],
            'type' => $e['event_type'],
            'data' => json_decode($e['event_data'], true),
            'siteId' => $e['site_id'],
            'createdAt' => $e['created_at']
        ], $events),
        'timestamp' => date('Y-m-d H:i:s'),
        'hasMore' => count($events) >= $limit
    ]);
}

// GET /realtime/stats - Stats en temps réel
if ($method === 'GET' && $uri === '/realtime/stats') {
    $admin = requireAuth();
    
    // Stats des dernières 24h
    $todayRevenue = (float)Database::fetchColumn(
        "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status = 'completed' AND created_at >= CURDATE()"
    );
    
    $todayPayments = (int)Database::fetchColumn(
        "SELECT COUNT(*) FROM payments WHERE status = 'completed' AND created_at >= CURDATE()"
    );
    
    $todayUsers = (int)Database::fetchColumn(
        "SELECT COUNT(*) FROM users WHERE created_at >= CURDATE()"
    );
    
    $activeVisitors = (int)Database::fetchColumn(
        "SELECT COUNT(DISTINCT user_id) FROM activities WHERE created_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)"
    );
    
    $unreadNotifications = (int)Database::fetchColumn(
        "SELECT COUNT(*) FROM notifications WHERE (admin_id = ? OR admin_id IS NULL) AND is_read = 0",
        [$admin['id']]
    );
    
    $pendingAlerts = (int)Database::fetchColumn(
        "SELECT COUNT(*) FROM alert_history WHERE notified = 0 AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)"
    );
    
    response([
        'todayRevenue' => $todayRevenue,
        'todayPayments' => $todayPayments,
        'todayUsers' => $todayUsers,
        'activeVisitors' => $activeVisitors,
        'unreadNotifications' => $unreadNotifications,
        'pendingAlerts' => $pendingAlerts,
        'timestamp' => date('Y-m-d H:i:s')
    ]);
}

// ============== API PUBLIQUE ==============

// GET /api-keys - Liste des clés API
if ($method === 'GET' && $uri === '/api-keys') {
    $admin = requireAuth();
    
    $keys = Database::fetchAll(
        "SELECT id, name, key_prefix, permissions, rate_limit, allowed_origins, last_used_at, usage_count, is_active, expires_at, created_at 
         FROM api_keys WHERE admin_id = ? ORDER BY created_at DESC",
        [$admin['id']]
    );
    
    response(array_map(fn($k) => [
        'id' => $k['id'],
        'name' => $k['name'],
        'keyPrefix' => $k['key_prefix'],
        'permissions' => json_decode($k['permissions'] ?? '[]', true),
        'rateLimit' => (int)$k['rate_limit'],
        'allowedOrigins' => json_decode($k['allowed_origins'] ?? '[]', true),
        'lastUsedAt' => $k['last_used_at'],
        'usageCount' => (int)$k['usage_count'],
        'isActive' => (bool)$k['is_active'],
        'expiresAt' => $k['expires_at'],
        'createdAt' => $k['created_at']
    ], $keys));
}

// POST /api-keys - Créer une clé API
if ($method === 'POST' && $uri === '/api-keys') {
    $admin = requireAuth();
    $input = getInput();
    
    $name = $input['name'] ?? '';
    if (!$name) {
        error('Nom requis', 400);
    }
    
    // Générer une clé unique
    $keyRaw = 'pk_' . bin2hex(random_bytes(24)); // pk_xxxxxx...
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
        'allowed_origins' => json_encode($input['allowedOrigins'] ?? []),
        'is_active' => 1,
        'expires_at' => isset($input['expiresIn']) ? date('Y-m-d H:i:s', time() + $input['expiresIn']) : null
    ]);
    
    // Retourner la clé complète (une seule fois!)
    response([
        'id' => $id,
        'name' => $name,
        'key' => $keyRaw, // ⚠️ Affiché une seule fois
        'keyPrefix' => $keyPrefix,
        'message' => 'Conservez cette clé précieusement, elle ne sera plus affichée.'
    ], 201);
}

// PUT /api-keys/{id} - Modifier une clé API
if ($method === 'PUT' && ($params = matchRoute('/api-keys/{id}', $uri))) {
    $admin = requireAuth();
    $input = getInput();
    
    $key = Database::fetch(
        "SELECT * FROM api_keys WHERE id = ? AND admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    if (!$key) {
        error('Clé non trouvée', 404);
    }
    
    $updateData = [];
    if (isset($input['name'])) $updateData['name'] = $input['name'];
    if (isset($input['permissions'])) $updateData['permissions'] = json_encode($input['permissions']);
    if (isset($input['rateLimit'])) $updateData['rate_limit'] = $input['rateLimit'];
    if (isset($input['allowedOrigins'])) $updateData['allowed_origins'] = json_encode($input['allowedOrigins']);
    if (isset($input['isActive'])) $updateData['is_active'] = $input['isActive'] ? 1 : 0;
    
    if (!empty($updateData)) {
        Database::update('api_keys', $updateData, ['id' => $params['id']]);
    }
    
    response(['success' => true]);
}

// DELETE /api-keys/{id} - Supprimer une clé API
if ($method === 'DELETE' && ($params = matchRoute('/api-keys/{id}', $uri))) {
    $admin = requireAuth();
    
    Database::query(
        "DELETE FROM api_keys WHERE id = ? AND admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    response(['success' => true]);
}

// GET /api-keys/{id}/logs - Logs d'utilisation d'une clé
if ($method === 'GET' && ($params = matchRoute('/api-keys/{id}/logs', $uri))) {
    $admin = requireAuth();
    
    $key = Database::fetch(
        "SELECT * FROM api_keys WHERE id = ? AND admin_id = ?",
        [$params['id'], $admin['id']]
    );
    
    if (!$key) {
        error('Clé non trouvée', 404);
    }
    
    $logs = Database::fetchAll(
        "SELECT endpoint, method, status_code, response_time_ms, ip_address, created_at 
         FROM api_logs WHERE api_key_id = ? ORDER BY created_at DESC LIMIT 100",
        [$params['id']]
    );
    
    response($logs);
}

// GET /docs - Documentation API publique
if ($method === 'GET' && $uri === '/docs') {
    header('Content-Type: text/html; charset=utf-8');
    echo '<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Noteso API Documentation</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0a0a0b; color: #fafafa; line-height: 1.6; }
        .container { max-width: 1000px; margin: 0 auto; padding: 40px 20px; }
        h1 { font-size: 2.5rem; margin-bottom: 8px; }
        h2 { font-size: 1.5rem; margin: 40px 0 20px; padding-bottom: 10px; border-bottom: 1px solid #27272a; }
        h3 { font-size: 1.1rem; margin: 24px 0 12px; color: #3b82f6; }
        p { color: #a1a1aa; margin-bottom: 16px; }
        code { background: #1e1e20; padding: 2px 6px; border-radius: 4px; font-family: "SF Mono", Monaco, monospace; font-size: 0.9em; }
        pre { background: #1e1e20; padding: 16px; border-radius: 8px; overflow-x: auto; margin: 16px 0; }
        pre code { padding: 0; background: none; }
        .endpoint { background: #141416; border: 1px solid #27272a; border-radius: 8px; padding: 16px; margin: 16px 0; }
        .method { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; margin-right: 8px; }
        .method.get { background: #22c55e20; color: #22c55e; }
        .method.post { background: #3b82f620; color: #3b82f6; }
        .method.put { background: #f59e0b20; color: #f59e0b; }
        .method.delete { background: #ef444420; color: #ef4444; }
        .path { font-family: monospace; color: #fafafa; }
        .desc { color: #a1a1aa; margin-top: 8px; font-size: 14px; }
        .badge { display: inline-block; background: #3b82f6; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin-left: 8px; }
        table { width: 100%; border-collapse: collapse; margin: 16px 0; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #27272a; }
        th { color: #a1a1aa; font-weight: 500; }
        .note { background: #3b82f610; border: 1px solid #3b82f640; padding: 16px; border-radius: 8px; margin: 16px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📚 Noteso API</h1>
        <p>API REST pour intégrer Noteso à vos applications</p>
        
        <div class="note">
            <strong>🔑 Authentification</strong><br>
            Toutes les requêtes doivent inclure votre clé API dans le header:<br>
            <code>Authorization: Bearer pk_votre_cle_api</code>
        </div>
        
        <h2>🚀 Démarrage rapide</h2>
        <pre><code>curl -X GET "https://api.noteso.fr/v1/stats" \\
  -H "Authorization: Bearer pk_votre_cle_api"</code></pre>
        
        <h2>📊 Endpoints</h2>
        
        <h3>Stats globales</h3>
        <div class="endpoint">
            <span class="method get">GET</span>
            <span class="path">/v1/stats</span>
            <div class="desc">Récupère les statistiques globales de votre compte</div>
        </div>
        
        <h3>Utilisateurs</h3>
        <div class="endpoint">
            <span class="method get">GET</span>
            <span class="path">/v1/users</span>
            <div class="desc">Liste tous les utilisateurs</div>
        </div>
        <div class="endpoint">
            <span class="method get">GET</span>
            <span class="path">/v1/users/{id}</span>
            <div class="desc">Récupère un utilisateur spécifique</div>
        </div>
        <div class="endpoint">
            <span class="method post">POST</span>
            <span class="path">/v1/users</span>
            <div class="desc">Crée un nouvel utilisateur</div>
        </div>
        
        <h3>Paiements</h3>
        <div class="endpoint">
            <span class="method get">GET</span>
            <span class="path">/v1/payments</span>
            <div class="desc">Liste tous les paiements</div>
        </div>
        <div class="endpoint">
            <span class="method post">POST</span>
            <span class="path">/v1/payments</span>
            <div class="desc">Enregistre un nouveau paiement</div>
        </div>
        
        <h3>Abonnements</h3>
        <div class="endpoint">
            <span class="method get">GET</span>
            <span class="path">/v1/subscriptions</span>
            <div class="desc">Liste tous les abonnements actifs</div>
        </div>
        <div class="endpoint">
            <span class="method post">POST</span>
            <span class="path">/v1/subscriptions</span>
            <div class="desc">Crée un nouvel abonnement</div>
        </div>
        
        <h3>Événements</h3>
        <div class="endpoint">
            <span class="method post">POST</span>
            <span class="path">/v1/events</span>
            <div class="desc">Envoie un événement personnalisé</div>
        </div>
        
        <h2>📝 Exemples</h2>
        
        <h3>Créer un utilisateur</h3>
        <pre><code>curl -X POST "https://api.noteso.fr/v1/users" \\
  -H "Authorization: Bearer pk_votre_cle_api" \\
  -H "Content-Type: application/json" \\
  -d \'{"email": "user@example.com", "name": "John Doe"}\'</code></pre>
        
        <h3>Enregistrer un paiement</h3>
        <pre><code>curl -X POST "https://api.noteso.fr/v1/payments" \\
  -H "Authorization: Bearer pk_votre_cle_api" \\
  -H "Content-Type: application/json" \\
  -d \'{"userId": "user_xxx", "amount": 29.99, "currency": "EUR"}\'</code></pre>
        
        <h2>⚠️ Limites</h2>
        <table>
            <tr><th>Plan</th><th>Requêtes/heure</th><th>Requêtes/jour</th></tr>
            <tr><td>Gratuit</td><td>100</td><td>1 000</td></tr>
            <tr><td>Pro</td><td>1 000</td><td>10 000</td></tr>
            <tr><td>Business</td><td>10 000</td><td>100 000</td></tr>
        </table>
        
        <h2>🔗 SDKs</h2>
        <p>SDKs officiels bientôt disponibles pour JavaScript, PHP, Python et Ruby.</p>
        
        <p style="margin-top:60px;text-align:center;color:#52525b">
            © ' . date('Y') . ' Noteso - <a href="/" style="color:#3b82f6">Retour au dashboard</a>
        </p>
    </div>
</body>
</html>';
    exit;
}

// ============== API PUBLIQUE V1 ==============

// Authentification par clé API pour les routes /v1/*
if (strpos($uri, '/v1/') === 0) {
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $apiKey = null;
    
    if (preg_match('/^Bearer\s+(pk_[a-f0-9]+)$/i', $authHeader, $matches)) {
        $apiKey = $matches[1];
    }
    
    if (!$apiKey) {
        error('Clé API requise. Utilisez: Authorization: Bearer pk_xxx', 401);
    }
    
    // Vérifier la clé
    $keyHash = hash('sha256', $apiKey);
    $keyData = Database::fetch(
        "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1 AND (expires_at IS NULL OR expires_at > NOW())",
        [$keyHash]
    );
    
    if (!$keyData) {
        error('Clé API invalide ou expirée', 401);
    }
    
    // Vérifier rate limit
    $hourlyCount = (int)Database::fetchColumn(
        "SELECT COUNT(*) FROM api_logs WHERE api_key_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)",
        [$keyData['id']]
    );
    
    if ($hourlyCount >= $keyData['rate_limit']) {
        header('X-RateLimit-Limit: ' . $keyData['rate_limit']);
        header('X-RateLimit-Remaining: 0');
        header('Retry-After: 3600');
        error('Rate limit dépassé. Limite: ' . $keyData['rate_limit'] . '/heure', 429);
    }
    
    // Mettre à jour usage
    Database::update('api_keys', [
        'last_used_at' => date('Y-m-d H:i:s'),
        'usage_count' => $keyData['usage_count'] + 1
    ], ['id' => $keyData['id']]);
    
    // Log la requête
    $apiKeyId = $keyData['id'];
    $apiAdminId = $keyData['admin_id'];
    register_shutdown_function(function() use ($apiKeyId, $uri, $method) {
        global $pdo;
        $statusCode = http_response_code();
        Database::insert('api_logs', [
            'api_key_id' => $apiKeyId,
            'endpoint' => $uri,
            'method' => $method,
            'status_code' => $statusCode,
            'ip_address' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]);
    });
    
    // Headers rate limit
    header('X-RateLimit-Limit: ' . $keyData['rate_limit']);
    header('X-RateLimit-Remaining: ' . max(0, $keyData['rate_limit'] - $hourlyCount - 1));
}

// GET /v1/stats - Stats globales
if ($method === 'GET' && $uri === '/v1/stats') {
    $overview = [
        'totalUsers' => (int)Database::fetchColumn("SELECT COUNT(*) FROM users"),
        'totalPayments' => (int)Database::fetchColumn("SELECT COUNT(*) FROM payments WHERE status = 'completed'"),
        'totalRevenue' => (float)Database::fetchColumn("SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status = 'completed'"),
        'activeSubscriptions' => (int)Database::fetchColumn("SELECT COUNT(*) FROM subscriptions WHERE status = 'active'"),
        'mrr' => (float)Database::fetchColumn("SELECT COALESCE(SUM(amount), 0) FROM subscriptions WHERE status = 'active' AND interval_type = 'month'")
    ];
    response($overview);
}

// GET /v1/users - Liste utilisateurs
if ($method === 'GET' && $uri === '/v1/users') {
    $limit = min((int)($_GET['limit'] ?? 100), 500);
    $offset = (int)($_GET['offset'] ?? 0);
    
    $users = Database::fetchAll(
        "SELECT id, site_id, email, name, external_id, created_at FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
        [$limit, $offset]
    );
    
    $total = (int)Database::fetchColumn("SELECT COUNT(*) FROM users");
    
    response(['data' => $users, 'total' => $total, 'limit' => $limit, 'offset' => $offset]);
}

// GET /v1/users/{id} - Détail utilisateur
if ($method === 'GET' && ($params = matchRoute('/v1/users/{id}', $uri))) {
    $user = Database::fetch(
        "SELECT id, site_id, email, name, external_id, metadata, created_at FROM users WHERE id = ?",
        [$params['id']]
    );
    
    if (!$user) {
        error('Utilisateur non trouvé', 404);
    }
    
    $user['metadata'] = json_decode($user['metadata'] ?? '{}', true);
    response($user);
}

// POST /v1/users - Créer utilisateur
if ($method === 'POST' && $uri === '/v1/users') {
    $input = getInput();
    
    $siteId = $input['siteId'] ?? Database::fetchColumn("SELECT id FROM sites LIMIT 1");
    $email = $input['email'] ?? '';
    
    if (!$email) {
        error('Email requis', 400);
    }
    
    $id = generateId('user');
    Database::insert('users', [
        'id' => $id,
        'site_id' => $siteId,
        'email' => $email,
        'name' => $input['name'] ?? null,
        'external_id' => $input['externalId'] ?? null,
        'metadata' => json_encode($input['metadata'] ?? [])
    ]);
    
    // Événement temps réel
    Database::insert('realtime_events', [
        'site_id' => $siteId,
        'event_type' => 'user_created',
        'event_data' => json_encode(['userId' => $id, 'email' => $email])
    ]);
    
    response(['id' => $id, 'email' => $email], 201);
}

// GET /v1/payments - Liste paiements
if ($method === 'GET' && $uri === '/v1/payments') {
    $limit = min((int)($_GET['limit'] ?? 100), 500);
    $offset = (int)($_GET['offset'] ?? 0);
    
    $payments = Database::fetchAll(
        "SELECT id, site_id, user_id, amount, currency, status, payment_method, external_id, created_at 
         FROM payments ORDER BY created_at DESC LIMIT ? OFFSET ?",
        [$limit, $offset]
    );
    
    $total = (int)Database::fetchColumn("SELECT COUNT(*) FROM payments");
    
    response(['data' => $payments, 'total' => $total, 'limit' => $limit, 'offset' => $offset]);
}

// POST /v1/payments - Créer paiement
if ($method === 'POST' && $uri === '/v1/payments') {
    $input = getInput();
    
    $amount = (float)($input['amount'] ?? 0);
    if ($amount <= 0) {
        error('Montant invalide', 400);
    }
    
    $siteId = $input['siteId'] ?? Database::fetchColumn("SELECT id FROM sites LIMIT 1");
    
    $id = generateId('pay');
    Database::insert('payments', [
        'id' => $id,
        'site_id' => $siteId,
        'user_id' => $input['userId'] ?? null,
        'amount' => $amount,
        'currency' => $input['currency'] ?? 'EUR',
        'status' => $input['status'] ?? 'completed',
        'payment_method' => $input['paymentMethod'] ?? 'card',
        'external_id' => $input['externalId'] ?? null,
        'metadata' => json_encode($input['metadata'] ?? []),
        'paid_at' => date('Y-m-d H:i:s')
    ]);
    
    // Événement temps réel
    Database::insert('realtime_events', [
        'site_id' => $siteId,
        'event_type' => 'payment_received',
        'event_data' => json_encode(['paymentId' => $id, 'amount' => $amount, 'currency' => $input['currency'] ?? 'EUR'])
    ]);
    
    response(['id' => $id, 'amount' => $amount], 201);
}

// GET /v1/subscriptions - Liste abonnements
if ($method === 'GET' && $uri === '/v1/subscriptions') {
    $limit = min((int)($_GET['limit'] ?? 100), 500);
    $offset = (int)($_GET['offset'] ?? 0);
    
    $subs = Database::fetchAll(
        "SELECT id, site_id, user_id, plan, amount, currency, status, interval_type, current_period_start, current_period_end, created_at 
         FROM subscriptions ORDER BY created_at DESC LIMIT ? OFFSET ?",
        [$limit, $offset]
    );
    
    $total = (int)Database::fetchColumn("SELECT COUNT(*) FROM subscriptions");
    
    response(['data' => $subs, 'total' => $total, 'limit' => $limit, 'offset' => $offset]);
}

// POST /v1/subscriptions - Créer abonnement
if ($method === 'POST' && $uri === '/v1/subscriptions') {
    $input = getInput();
    
    $plan = $input['plan'] ?? '';
    $amount = (float)($input['amount'] ?? 0);
    
    if (!$plan || $amount <= 0) {
        error('Plan et montant requis', 400);
    }
    
    $siteId = $input['siteId'] ?? Database::fetchColumn("SELECT id FROM sites LIMIT 1");
    
    $id = generateId('sub');
    Database::insert('subscriptions', [
        'id' => $id,
        'site_id' => $siteId,
        'user_id' => $input['userId'] ?? null,
        'plan' => $plan,
        'amount' => $amount,
        'currency' => $input['currency'] ?? 'EUR',
        'status' => 'active',
        'interval_type' => $input['interval'] ?? 'month',
        'current_period_start' => date('Y-m-d H:i:s'),
        'current_period_end' => date('Y-m-d H:i:s', strtotime('+1 ' . ($input['interval'] ?? 'month')))
    ]);
    
    // Événement temps réel
    Database::insert('realtime_events', [
        'site_id' => $siteId,
        'event_type' => 'subscription_created',
        'event_data' => json_encode(['subscriptionId' => $id, 'plan' => $plan, 'amount' => $amount])
    ]);
    
    response(['id' => $id, 'plan' => $plan], 201);
}

// POST /v1/events - Événement personnalisé
if ($method === 'POST' && $uri === '/v1/events') {
    $input = getInput();
    
    $eventType = $input['type'] ?? $input['event'] ?? '';
    if (!$eventType) {
        error('Type d\'événement requis', 400);
    }
    
    $siteId = $input['siteId'] ?? Database::fetchColumn("SELECT id FROM sites LIMIT 1");
    
    Database::insert('realtime_events', [
        'site_id' => $siteId,
        'event_type' => $eventType,
        'event_data' => json_encode($input['data'] ?? $input)
    ]);
    
    // Si c'est une activité
    if ($input['userId'] ?? null) {
        logActivity($siteId, $input['userId'], $eventType, $input['description'] ?? null);
    }
    
    response(['success' => true, 'event' => $eventType], 201);
}

// Route non trouvée
error('Route non trouvée: ' . $method . ' ' . $uri, 404);
