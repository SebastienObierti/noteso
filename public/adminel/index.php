<?php
/**
 * NOTESO - Panneau d'Administration
 * Configuration SMTP, paramètres système, et gestion
 */

session_start();

// Configuration
define('CONFIG_FILE', __DIR__ . '/../data/config.json');
define('ADMINS_FILE', __DIR__ . '/../data/admins.json');

// Fonctions utilitaires
function readConfig() {
    if (file_exists(CONFIG_FILE)) {
        return json_decode(file_get_contents(CONFIG_FILE), true) ?: [];
    }
    return getDefaultConfig();
}

function writeConfig($config) {
    $dir = dirname(CONFIG_FILE);
    if (!is_dir($dir)) mkdir($dir, 0755, true);
    file_put_contents(CONFIG_FILE, json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

function getDefaultConfig() {
    return [
        'smtp' => [
            'enabled' => false,
            'host' => '',
            'port' => 587,
            'encryption' => 'tls',
            'username' => '',
            'password' => '',
            'from_email' => 'noreply@noteso.fr',
            'from_name' => 'Noteso'
        ],
        'app' => [
            'name' => 'Noteso',
            'url' => '',
            'debug' => false,
            'timezone' => 'Europe/Paris'
        ],
        'security' => [
            'session_duration' => 604800,
            'max_login_attempts' => 5,
            'lockout_duration' => 900,
            'min_password_length' => 8
        ]
    ];
}

function isLoggedIn() {
    return isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;
}

function checkAdminCredentials($email, $password) {
    if (file_exists(ADMINS_FILE)) {
        $admins = json_decode(file_get_contents(ADMINS_FILE), true) ?: [];
        foreach ($admins as $admin) {
            if (strtolower($admin['email']) === strtolower($email)) {
                if (password_verify($password, $admin['password'])) {
                    return $admin;
                }
            }
        }
    }
    return false;
}

function sendTestEmail($config, $to) {
    if (!$config['smtp']['enabled']) {
        return ['success' => false, 'message' => 'SMTP non activé'];
    }
    
    // Utiliser PHPMailer si disponible, sinon mail() natif
    $subject = '[Noteso] Test SMTP';
    $body = '
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 40px;">
        <div style="max-width: 500px; margin: 0 auto; background: white; border-radius: 12px; padding: 40px; text-align: center;">
            <div style="font-size: 48px; margin-bottom: 20px;">✅</div>
            <h1 style="color: #22c55e; margin-bottom: 16px;">SMTP Fonctionnel !</h1>
            <p style="color: #666;">Votre configuration SMTP est correcte.</p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
            <p style="color: #999; font-size: 12px;">Envoyé depuis Noteso Admin</p>
        </div>
    </body>
    </html>';
    
    // Si PHPMailer est disponible
    $phpmailerPath = __DIR__ . '/../../vendor/autoload.php';
    if (file_exists($phpmailerPath)) {
        require_once $phpmailerPath;
        
        try {
            $mail = new PHPMailer\PHPMailer\PHPMailer(true);
            $mail->isSMTP();
            $mail->Host = $config['smtp']['host'];
            $mail->Port = $config['smtp']['port'];
            $mail->SMTPAuth = true;
            $mail->Username = $config['smtp']['username'];
            $mail->Password = $config['smtp']['password'];
            
            if ($config['smtp']['encryption'] === 'tls') {
                $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
            } elseif ($config['smtp']['encryption'] === 'ssl') {
                $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
            }
            
            $mail->setFrom($config['smtp']['from_email'], $config['smtp']['from_name']);
            $mail->addAddress($to);
            $mail->isHTML(true);
            $mail->CharSet = 'UTF-8';
            $mail->Subject = $subject;
            $mail->Body = $body;
            
            $mail->send();
            return ['success' => true, 'message' => 'Email envoyé avec succès!'];
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Erreur: ' . $mail->ErrorInfo];
        }
    }
    
    // Fallback: Utiliser fsockopen pour SMTP direct
    try {
        $result = sendSmtpEmail($config['smtp'], $to, $subject, $body);
        return $result;
    } catch (Exception $e) {
        return ['success' => false, 'message' => 'Erreur: ' . $e->getMessage()];
    }
}

function sendSmtpEmail($smtp, $to, $subject, $body) {
    $host = $smtp['encryption'] === 'ssl' ? 'ssl://' . $smtp['host'] : $smtp['host'];
    $port = $smtp['port'];
    
    $socket = @fsockopen($host, $port, $errno, $errstr, 10);
    if (!$socket) {
        throw new Exception("Connexion impossible: $errstr ($errno)");
    }
    
    stream_set_timeout($socket, 10);
    
    $response = fgets($socket, 512);
    if (substr($response, 0, 3) != '220') {
        throw new Exception("Erreur serveur: $response");
    }
    
    // EHLO
    fputs($socket, "EHLO " . gethostname() . "\r\n");
    $response = '';
    while ($line = fgets($socket, 512)) {
        $response .= $line;
        if (substr($line, 3, 1) == ' ') break;
    }
    
    // STARTTLS si nécessaire
    if ($smtp['encryption'] === 'tls') {
        fputs($socket, "STARTTLS\r\n");
        $response = fgets($socket, 512);
        if (substr($response, 0, 3) != '220') {
            throw new Exception("STARTTLS échoué: $response");
        }
        
        stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        
        fputs($socket, "EHLO " . gethostname() . "\r\n");
        $response = '';
        while ($line = fgets($socket, 512)) {
            $response .= $line;
            if (substr($line, 3, 1) == ' ') break;
        }
    }
    
    // AUTH LOGIN
    fputs($socket, "AUTH LOGIN\r\n");
    $response = fgets($socket, 512);
    
    fputs($socket, base64_encode($smtp['username']) . "\r\n");
    $response = fgets($socket, 512);
    
    fputs($socket, base64_encode($smtp['password']) . "\r\n");
    $response = fgets($socket, 512);
    if (substr($response, 0, 3) != '235') {
        throw new Exception("Authentification échouée: $response");
    }
    
    // MAIL FROM
    fputs($socket, "MAIL FROM:<{$smtp['from_email']}>\r\n");
    $response = fgets($socket, 512);
    
    // RCPT TO
    fputs($socket, "RCPT TO:<$to>\r\n");
    $response = fgets($socket, 512);
    
    // DATA
    fputs($socket, "DATA\r\n");
    $response = fgets($socket, 512);
    
    $headers = "From: {$smtp['from_name']} <{$smtp['from_email']}>\r\n";
    $headers .= "To: $to\r\n";
    $headers .= "Subject: $subject\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
    $headers .= "\r\n";
    
    fputs($socket, $headers . $body . "\r\n.\r\n");
    $response = fgets($socket, 512);
    if (substr($response, 0, 3) != '250') {
        throw new Exception("Envoi échoué: $response");
    }
    
    fputs($socket, "QUIT\r\n");
    fclose($socket);
    
    return ['success' => true, 'message' => 'Email envoyé avec succès!'];
}

// Traitement des actions
$message = '';
$messageType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    // Login
    if ($action === 'login') {
        $email = $_POST['email'] ?? '';
        $password = $_POST['password'] ?? '';
        
        $admin = checkAdminCredentials($email, $password);
        if ($admin) {
            $_SESSION['admin_logged_in'] = true;
            $_SESSION['admin_email'] = $admin['email'];
            $_SESSION['admin_name'] = ($admin['firstName'] ?? '') . ' ' . ($admin['lastName'] ?? '');
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $message = 'Identifiants incorrects';
            $messageType = 'error';
        }
    }
    
    // Logout
    if ($action === 'logout') {
        session_destroy();
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
    
    // Actions nécessitant une connexion
    if (isLoggedIn()) {
        // Sauvegarder SMTP
        if ($action === 'save_smtp') {
            $config = readConfig();
            $config['smtp'] = [
                'enabled' => isset($_POST['smtp_enabled']),
                'host' => trim($_POST['smtp_host'] ?? ''),
                'port' => (int)($_POST['smtp_port'] ?? 587),
                'encryption' => $_POST['smtp_encryption'] ?? 'tls',
                'username' => trim($_POST['smtp_username'] ?? ''),
                'password' => $_POST['smtp_password'] ?? $config['smtp']['password'] ?? '',
                'from_email' => trim($_POST['smtp_from_email'] ?? ''),
                'from_name' => trim($_POST['smtp_from_name'] ?? 'Noteso')
            ];
            
            // Si nouveau mot de passe fourni
            if (!empty($_POST['smtp_password_new'])) {
                $config['smtp']['password'] = $_POST['smtp_password_new'];
            }
            
            writeConfig($config);
            $message = 'Configuration SMTP enregistrée!';
            $messageType = 'success';
        }
        
        // Tester SMTP
        if ($action === 'test_smtp') {
            $config = readConfig();
            $testEmail = $_POST['test_email'] ?? '';
            
            if (empty($testEmail)) {
                $message = 'Veuillez entrer une adresse email de test';
                $messageType = 'error';
            } else {
                $result = sendTestEmail($config, $testEmail);
                $message = $result['message'];
                $messageType = $result['success'] ? 'success' : 'error';
            }
        }
        
        // Sauvegarder paramètres application
        if ($action === 'save_app') {
            $config = readConfig();
            $config['app'] = [
                'name' => trim($_POST['app_name'] ?? 'Noteso'),
                'url' => trim($_POST['app_url'] ?? ''),
                'debug' => isset($_POST['app_debug']),
                'timezone' => $_POST['app_timezone'] ?? 'Europe/Paris'
            ];
            writeConfig($config);
            $message = 'Paramètres application enregistrés!';
            $messageType = 'success';
        }
        
        // Sauvegarder paramètres sécurité
        if ($action === 'save_security') {
            $config = readConfig();
            $config['security'] = [
                'session_duration' => (int)($_POST['session_duration'] ?? 604800),
                'max_login_attempts' => (int)($_POST['max_login_attempts'] ?? 5),
                'lockout_duration' => (int)($_POST['lockout_duration'] ?? 900),
                'min_password_length' => (int)($_POST['min_password_length'] ?? 8)
            ];
            writeConfig($config);
            $message = 'Paramètres de sécurité enregistrés!';
            $messageType = 'success';
        }
    }
}

$config = readConfig();
$currentTab = $_GET['tab'] ?? 'smtp';
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Noteso Admin - Configuration</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --bg-card: #1e293b;
            --border: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent: #3b82f6;
            --accent-hover: #2563eb;
            --success: #22c55e;
            --warning: #f59e0b;
            --danger: #ef4444;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', sans-serif; background: var(--bg-primary); color: var(--text-primary); min-height: 100vh; }
        
        /* Login */
        .login-container { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .login-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px; padding: 40px; width: 100%; max-width: 400px; }
        .login-header { text-align: center; margin-bottom: 32px; }
        .login-logo { width: 60px; height: 60px; background: linear-gradient(135deg, #3b82f6, #8b5cf6); border-radius: 12px; display: flex; align-items: center; justify-content: center; margin: 0 auto 16px; font-size: 24px; font-weight: 700; color: white; }
        .login-title { font-size: 24px; font-weight: 700; margin-bottom: 8px; }
        .login-subtitle { color: var(--text-secondary); font-size: 14px; }
        
        /* Layout */
        .admin-container { display: flex; min-height: 100vh; }
        .sidebar { width: 260px; background: var(--bg-secondary); border-right: 1px solid var(--border); padding: 24px; position: fixed; height: 100vh; overflow-y: auto; }
        .main-content { flex: 1; margin-left: 260px; padding: 32px; }
        
        .sidebar-header { display: flex; align-items: center; gap: 12px; margin-bottom: 32px; padding-bottom: 24px; border-bottom: 1px solid var(--border); }
        .sidebar-logo { width: 40px; height: 40px; background: linear-gradient(135deg, #3b82f6, #8b5cf6); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-weight: 700; color: white; }
        .sidebar-title { font-weight: 700; font-size: 16px; }
        .sidebar-badge { font-size: 10px; background: var(--accent); color: white; padding: 2px 8px; border-radius: 10px; margin-left: 8px; }
        
        .nav-section { margin-bottom: 24px; }
        .nav-label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); margin-bottom: 12px; }
        .nav-item { display: flex; align-items: center; gap: 12px; padding: 10px 12px; border-radius: 8px; color: var(--text-secondary); text-decoration: none; transition: all 0.2s; margin-bottom: 4px; font-size: 14px; }
        .nav-item:hover, .nav-item.active { background: var(--bg-tertiary); color: var(--text-primary); }
        .nav-item.active { border-left: 3px solid var(--accent); margin-left: -3px; }
        
        .user-card { margin-top: auto; padding: 16px; background: var(--bg-tertiary); border-radius: 10px; }
        .user-info { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
        .user-avatar { width: 36px; height: 36px; background: linear-gradient(135deg, #22c55e, #06b6d4); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 600; font-size: 12px; }
        .user-name { font-weight: 600; font-size: 13px; }
        .user-email { font-size: 11px; color: var(--text-muted); }
        
        /* Header */
        .page-header { margin-bottom: 32px; }
        .page-header h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
        .page-header p { color: var(--text-secondary); }
        
        /* Cards */
        .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 24px; }
        .card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; padding-bottom: 16px; border-bottom: 1px solid var(--border); }
        .card-title { font-size: 16px; font-weight: 600; display: flex; align-items: center; gap: 10px; }
        .card-icon { font-size: 20px; }
        
        /* Forms */
        .form-group { margin-bottom: 20px; }
        .form-label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 8px; color: var(--text-secondary); }
        .form-input, .form-select { width: 100%; padding: 12px 16px; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; color: var(--text-primary); font-size: 14px; font-family: inherit; transition: all 0.2s; }
        .form-input:focus, .form-select:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); }
        .form-input::placeholder { color: var(--text-muted); }
        .form-hint { font-size: 12px; color: var(--text-muted); margin-top: 6px; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
        
        /* Checkbox/Toggle */
        .form-check { display: flex; align-items: center; gap: 12px; cursor: pointer; }
        .form-check input { display: none; }
        .form-check-box { width: 44px; height: 24px; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 12px; position: relative; transition: all 0.3s; }
        .form-check-box::after { content: ''; position: absolute; width: 18px; height: 18px; background: var(--text-secondary); border-radius: 50%; top: 2px; left: 2px; transition: all 0.3s; }
        .form-check input:checked + .form-check-box { background: var(--accent); border-color: var(--accent); }
        .form-check input:checked + .form-check-box::after { left: 22px; background: white; }
        .form-check-label { font-size: 14px; }
        
        /* Buttons */
        .btn { display: inline-flex; align-items: center; gap: 8px; padding: 12px 20px; border-radius: 8px; font-size: 14px; font-weight: 500; cursor: pointer; transition: all 0.2s; border: none; font-family: inherit; }
        .btn-primary { background: var(--accent); color: white; }
        .btn-primary:hover { background: var(--accent-hover); }
        .btn-secondary { background: var(--bg-tertiary); color: var(--text-primary); border: 1px solid var(--border); }
        .btn-secondary:hover { background: var(--border); }
        .btn-danger { background: var(--danger); color: white; }
        .btn-success { background: var(--success); color: white; }
        .btn-sm { padding: 8px 14px; font-size: 13px; }
        
        .btn-group { display: flex; gap: 12px; margin-top: 24px; }
        
        /* Alerts */
        .alert { padding: 16px 20px; border-radius: 10px; margin-bottom: 24px; display: flex; align-items: center; gap: 12px; font-size: 14px; }
        .alert-success { background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); color: var(--success); }
        .alert-error { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); color: var(--danger); }
        .alert-warning { background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); color: var(--warning); }
        .alert-info { background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3); color: var(--accent); }
        
        /* Status badge */
        .status { display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 500; }
        .status-active { background: rgba(34, 197, 94, 0.15); color: var(--success); }
        .status-inactive { background: rgba(239, 68, 68, 0.15); color: var(--danger); }
        
        /* Info box */
        .info-box { background: var(--bg-tertiary); border-radius: 8px; padding: 16px; margin-top: 16px; }
        .info-box-title { font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 8px; text-transform: uppercase; }
        .info-box code { background: var(--bg-primary); padding: 8px 12px; border-radius: 6px; display: block; font-size: 12px; margin-top: 8px; word-break: break-all; }
        
        /* Test section */
        .test-section { background: var(--bg-tertiary); border-radius: 10px; padding: 20px; margin-top: 24px; }
        .test-section h4 { font-size: 14px; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
        .test-row { display: flex; gap: 12px; align-items: flex-end; }
        .test-row .form-group { flex: 1; margin-bottom: 0; }
        
        /* Responsive */
        @media (max-width: 900px) {
            .sidebar { display: none; }
            .main-content { margin-left: 0; }
            .form-row { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
<?php if (!isLoggedIn()): ?>
    <!-- Login Page -->
    <div class="login-container">
        <div class="login-card">
            <div class="login-header">
                <div class="login-logo">N</div>
                <h1 class="login-title">Administration</h1>
                <p class="login-subtitle">Connectez-vous pour accéder aux paramètres</p>
            </div>
            
            <?php if ($message): ?>
                <div class="alert alert-<?= $messageType ?>" style="margin-bottom: 24px;">
                    <?= $messageType === 'error' ? '❌' : '✅' ?> <?= htmlspecialchars($message) ?>
                </div>
            <?php endif; ?>
            
            <form method="POST">
                <input type="hidden" name="action" value="login">
                <div class="form-group">
                    <label class="form-label">Email</label>
                    <input type="email" name="email" class="form-input" placeholder="admin@noteso.fr" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Mot de passe</label>
                    <input type="password" name="password" class="form-input" placeholder="••••••••" required>
                </div>
                <button type="submit" class="btn btn-primary" style="width: 100%; justify-content: center;">
                    Se connecter
                </button>
            </form>
            
            <p style="text-align: center; margin-top: 20px; font-size: 12px; color: var(--text-muted);">
                <a href="../" style="color: var(--accent); text-decoration: none;">← Retour au dashboard</a>
            </p>
        </div>
    </div>
<?php else: ?>
    <!-- Admin Panel -->
    <div class="admin-container">
        <aside class="sidebar">
            <div class="sidebar-header">
                <div class="sidebar-logo">N</div>
                <div>
                    <span class="sidebar-title">Noteso</span>
                    <span class="sidebar-badge">Admin</span>
                </div>
            </div>
            
            <nav class="nav-section">
                <div class="nav-label">Configuration</div>
                <a href="?tab=smtp" class="nav-item <?= $currentTab === 'smtp' ? 'active' : '' ?>">
                    📧 SMTP / Email
                </a>
                <a href="?tab=app" class="nav-item <?= $currentTab === 'app' ? 'active' : '' ?>">
                    ⚙️ Application
                </a>
                <a href="?tab=security" class="nav-item <?= $currentTab === 'security' ? 'active' : '' ?>">
                    🔐 Sécurité
                </a>
            </nav>
            
            <nav class="nav-section">
                <div class="nav-label">Outils</div>
                <a href="?tab=logs" class="nav-item <?= $currentTab === 'logs' ? 'active' : '' ?>">
                    📋 Logs
                </a>
                <a href="?tab=info" class="nav-item <?= $currentTab === 'info' ? 'active' : '' ?>">
                    ℹ️ Informations
                </a>
            </nav>
            
            <nav class="nav-section">
                <div class="nav-label">Navigation</div>
                <a href="../" class="nav-item">
                    📊 Dashboard Noteso
                </a>
            </nav>
            
            <div style="margin-top: auto; padding-top: 24px; border-top: 1px solid var(--border);">
                <div class="user-card">
                    <div class="user-info">
                        <div class="user-avatar"><?= strtoupper(substr($_SESSION['admin_email'] ?? 'A', 0, 1)) ?></div>
                        <div>
                            <div class="user-name"><?= htmlspecialchars($_SESSION['admin_name'] ?? 'Admin') ?></div>
                            <div class="user-email"><?= htmlspecialchars($_SESSION['admin_email'] ?? '') ?></div>
                        </div>
                    </div>
                    <form method="POST" style="margin: 0;">
                        <input type="hidden" name="action" value="logout">
                        <button type="submit" class="btn btn-secondary btn-sm" style="width: 100%; justify-content: center;">
                            🚪 Déconnexion
                        </button>
                    </form>
                </div>
            </div>
        </aside>
        
        <main class="main-content">
            <?php if ($message): ?>
                <div class="alert alert-<?= $messageType ?>">
                    <?= $messageType === 'error' ? '❌' : ($messageType === 'success' ? '✅' : 'ℹ️') ?> 
                    <?= htmlspecialchars($message) ?>
                </div>
            <?php endif; ?>
            
            <?php if ($currentTab === 'smtp'): ?>
                <!-- SMTP Configuration -->
                <div class="page-header">
                    <h1>📧 Configuration SMTP</h1>
                    <p>Configurez l'envoi d'emails pour les notifications et réinitialisations de mot de passe</p>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><span class="card-icon">⚡</span> Paramètres SMTP</h3>
                        <span class="status <?= $config['smtp']['enabled'] ? 'status-active' : 'status-inactive' ?>">
                            <?= $config['smtp']['enabled'] ? '● Actif' : '○ Inactif' ?>
                        </span>
                    </div>
                    
                    <form method="POST">
                        <input type="hidden" name="action" value="save_smtp">
                        
                        <label class="form-check">
                            <input type="checkbox" name="smtp_enabled" <?= $config['smtp']['enabled'] ? 'checked' : '' ?>>
                            <span class="form-check-box"></span>
                            <span class="form-check-label">Activer l'envoi SMTP</span>
                        </label>
                        
                        <div style="margin-top: 24px;">
                            <div class="form-row">
                                <div class="form-group">
                                    <label class="form-label">Serveur SMTP</label>
                                    <input type="text" name="smtp_host" class="form-input" placeholder="smtp.gmail.com" value="<?= htmlspecialchars($config['smtp']['host'] ?? '') ?>">
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Port</label>
                                    <input type="number" name="smtp_port" class="form-input" placeholder="587" value="<?= $config['smtp']['port'] ?? 587 ?>">
                                </div>
                            </div>
                            
                            <div class="form-group">
                                <label class="form-label">Chiffrement</label>
                                <select name="smtp_encryption" class="form-select">
                                    <option value="tls" <?= ($config['smtp']['encryption'] ?? '') === 'tls' ? 'selected' : '' ?>>TLS (port 587)</option>
                                    <option value="ssl" <?= ($config['smtp']['encryption'] ?? '') === 'ssl' ? 'selected' : '' ?>>SSL (port 465)</option>
                                    <option value="none" <?= ($config['smtp']['encryption'] ?? '') === 'none' ? 'selected' : '' ?>>Aucun</option>
                                </select>
                            </div>
                            
                            <div class="form-row">
                                <div class="form-group">
                                    <label class="form-label">Nom d'utilisateur</label>
                                    <input type="text" name="smtp_username" class="form-input" placeholder="votre@email.com" value="<?= htmlspecialchars($config['smtp']['username'] ?? '') ?>">
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Mot de passe</label>
                                    <input type="password" name="smtp_password_new" class="form-input" placeholder="<?= !empty($config['smtp']['password']) ? '••••••••' : 'Mot de passe SMTP' ?>">
                                    <p class="form-hint">Laissez vide pour conserver l'actuel</p>
                                </div>
                            </div>
                            
                            <div class="form-row">
                                <div class="form-group">
                                    <label class="form-label">Email expéditeur</label>
                                    <input type="email" name="smtp_from_email" class="form-input" placeholder="noreply@noteso.fr" value="<?= htmlspecialchars($config['smtp']['from_email'] ?? '') ?>">
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Nom expéditeur</label>
                                    <input type="text" name="smtp_from_name" class="form-input" placeholder="Noteso" value="<?= htmlspecialchars($config['smtp']['from_name'] ?? 'Noteso') ?>">
                                </div>
                            </div>
                        </div>
                        
                        <div class="btn-group">
                            <button type="submit" class="btn btn-primary">💾 Enregistrer</button>
                        </div>
                    </form>
                    
                    <!-- Test SMTP -->
                    <div class="test-section">
                        <h4>🧪 Tester la configuration</h4>
                        <form method="POST">
                            <input type="hidden" name="action" value="test_smtp">
                            <div class="test-row">
                                <div class="form-group">
                                    <input type="email" name="test_email" class="form-input" placeholder="destinataire@email.com">
                                </div>
                                <button type="submit" class="btn btn-secondary">Envoyer un test</button>
                            </div>
                        </form>
                    </div>
                </div>
                
                <!-- Presets -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><span class="card-icon">📋</span> Configurations courantes</h3>
                    </div>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
                        <div class="info-box">
                            <div class="info-box-title">Gmail</div>
                            <p style="font-size: 12px; color: var(--text-secondary);">smtp.gmail.com:587 (TLS)</p>
                            <p style="font-size: 11px; color: var(--text-muted); margin-top: 8px;">Utilisez un mot de passe d'application</p>
                        </div>
                        <div class="info-box">
                            <div class="info-box-title">OVH</div>
                            <p style="font-size: 12px; color: var(--text-secondary);">ssl0.ovh.net:587 (TLS)</p>
                        </div>
                        <div class="info-box">
                            <div class="info-box-title">Outlook/Office 365</div>
                            <p style="font-size: 12px; color: var(--text-secondary);">smtp.office365.com:587 (TLS)</p>
                        </div>
                        <div class="info-box">
                            <div class="info-box-title">SendGrid</div>
                            <p style="font-size: 12px; color: var(--text-secondary);">smtp.sendgrid.net:587 (TLS)</p>
                        </div>
                    </div>
                </div>
                
            <?php elseif ($currentTab === 'app'): ?>
                <!-- Application Settings -->
                <div class="page-header">
                    <h1>⚙️ Paramètres Application</h1>
                    <p>Configuration générale de l'application Noteso</p>
                </div>
                
                <div class="card">
                    <form method="POST">
                        <input type="hidden" name="action" value="save_app">
                        
                        <div class="form-row">
                            <div class="form-group">
                                <label class="form-label">Nom de l'application</label>
                                <input type="text" name="app_name" class="form-input" value="<?= htmlspecialchars($config['app']['name'] ?? 'Noteso') ?>">
                            </div>
                            <div class="form-group">
                                <label class="form-label">URL de l'application</label>
                                <input type="url" name="app_url" class="form-input" placeholder="https://noteso.fr" value="<?= htmlspecialchars($config['app']['url'] ?? '') ?>">
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Fuseau horaire</label>
                            <select name="app_timezone" class="form-select">
                                <option value="Europe/Paris" <?= ($config['app']['timezone'] ?? '') === 'Europe/Paris' ? 'selected' : '' ?>>Europe/Paris</option>
                                <option value="Europe/London" <?= ($config['app']['timezone'] ?? '') === 'Europe/London' ? 'selected' : '' ?>>Europe/London</option>
                                <option value="America/New_York" <?= ($config['app']['timezone'] ?? '') === 'America/New_York' ? 'selected' : '' ?>>America/New_York</option>
                                <option value="UTC" <?= ($config['app']['timezone'] ?? '') === 'UTC' ? 'selected' : '' ?>>UTC</option>
                            </select>
                        </div>
                        
                        <label class="form-check" style="margin-top: 16px;">
                            <input type="checkbox" name="app_debug" <?= ($config['app']['debug'] ?? false) ? 'checked' : '' ?>>
                            <span class="form-check-box"></span>
                            <span class="form-check-label">Mode debug (affiche les erreurs détaillées)</span>
                        </label>
                        
                        <div class="btn-group">
                            <button type="submit" class="btn btn-primary">💾 Enregistrer</button>
                        </div>
                    </form>
                </div>
                
            <?php elseif ($currentTab === 'security'): ?>
                <!-- Security Settings -->
                <div class="page-header">
                    <h1>🔐 Paramètres de Sécurité</h1>
                    <p>Configuration de la sécurité et des sessions</p>
                </div>
                
                <div class="card">
                    <form method="POST">
                        <input type="hidden" name="action" value="save_security">
                        
                        <div class="form-group">
                            <label class="form-label">Durée de session (secondes)</label>
                            <input type="number" name="session_duration" class="form-input" value="<?= $config['security']['session_duration'] ?? 604800 ?>">
                            <p class="form-hint">604800 = 7 jours, 86400 = 1 jour</p>
                        </div>
                        
                        <div class="form-row">
                            <div class="form-group">
                                <label class="form-label">Tentatives de connexion max</label>
                                <input type="number" name="max_login_attempts" class="form-input" value="<?= $config['security']['max_login_attempts'] ?? 5 ?>">
                            </div>
                            <div class="form-group">
                                <label class="form-label">Durée de blocage (secondes)</label>
                                <input type="number" name="lockout_duration" class="form-input" value="<?= $config['security']['lockout_duration'] ?? 900 ?>">
                                <p class="form-hint">900 = 15 minutes</p>
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Longueur minimale mot de passe</label>
                            <input type="number" name="min_password_length" class="form-input" value="<?= $config['security']['min_password_length'] ?? 8 ?>" min="6" max="32">
                        </div>
                        
                        <div class="btn-group">
                            <button type="submit" class="btn btn-primary">💾 Enregistrer</button>
                        </div>
                    </form>
                </div>
                
            <?php elseif ($currentTab === 'logs'): ?>
                <!-- Logs -->
                <div class="page-header">
                    <h1>📋 Logs de Sécurité</h1>
                    <p>Historique des événements de sécurité</p>
                </div>
                
                <div class="card">
                    <?php
                    $logsFile = __DIR__ . '/../data/security_logs.json';
                    $logs = file_exists($logsFile) ? json_decode(file_get_contents($logsFile), true) : [];
                    $logs = array_reverse(array_slice($logs, -50));
                    ?>
                    
                    <?php if (empty($logs)): ?>
                        <p style="color: var(--text-muted); text-align: center; padding: 40px;">Aucun log disponible</p>
                    <?php else: ?>
                        <div style="max-height: 500px; overflow-y: auto;">
                            <table style="width: 100%; border-collapse: collapse;">
                                <thead>
                                    <tr style="border-bottom: 1px solid var(--border);">
                                        <th style="text-align: left; padding: 12px; font-size: 11px; color: var(--text-muted);">DATE</th>
                                        <th style="text-align: left; padding: 12px; font-size: 11px; color: var(--text-muted);">TYPE</th>
                                        <th style="text-align: left; padding: 12px; font-size: 11px; color: var(--text-muted);">DÉTAILS</th>
                                        <th style="text-align: left; padding: 12px; font-size: 11px; color: var(--text-muted);">IP</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($logs as $log): ?>
                                        <tr style="border-bottom: 1px solid var(--border);">
                                            <td style="padding: 12px; font-size: 12px; color: var(--text-muted);"><?= date('d/m/Y H:i', strtotime($log['timestamp'] ?? '')) ?></td>
                                            <td style="padding: 12px;">
                                                <span class="status <?= strpos($log['type'] ?? '', 'failed') !== false ? 'status-inactive' : 'status-active' ?>">
                                                    <?= htmlspecialchars($log['type'] ?? '') ?>
                                                </span>
                                            </td>
                                            <td style="padding: 12px; font-size: 13px;"><?= htmlspecialchars($log['details'] ?? '') ?></td>
                                            <td style="padding: 12px; font-size: 12px; font-family: monospace; color: var(--text-muted);"><?= htmlspecialchars($log['ip'] ?? '') ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
                
            <?php elseif ($currentTab === 'info'): ?>
                <!-- System Info -->
                <div class="page-header">
                    <h1>ℹ️ Informations Système</h1>
                    <p>Informations sur l'environnement serveur</p>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><span class="card-icon">🖥️</span> Serveur</h3>
                    </div>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px;">
                        <div class="info-box">
                            <div class="info-box-title">PHP Version</div>
                            <p style="font-size: 18px; font-weight: 600;"><?= phpversion() ?></p>
                        </div>
                        <div class="info-box">
                            <div class="info-box-title">Serveur Web</div>
                            <p style="font-size: 14px;"><?= $_SERVER['SERVER_SOFTWARE'] ?? 'N/A' ?></p>
                        </div>
                        <div class="info-box">
                            <div class="info-box-title">Système</div>
                            <p style="font-size: 14px;"><?= php_uname('s') . ' ' . php_uname('r') ?></p>
                        </div>
                        <div class="info-box">
                            <div class="info-box-title">Mémoire PHP</div>
                            <p style="font-size: 14px;"><?= ini_get('memory_limit') ?></p>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><span class="card-icon">📧</span> Extensions Email</h3>
                    </div>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
                        <div class="info-box">
                            <div class="info-box-title">mail()</div>
                            <span class="status <?= function_exists('mail') ? 'status-active' : 'status-inactive' ?>">
                                <?= function_exists('mail') ? '✓ Disponible' : '✗ Non disponible' ?>
                            </span>
                        </div>
                        <div class="info-box">
                            <div class="info-box-title">OpenSSL</div>
                            <span class="status <?= extension_loaded('openssl') ? 'status-active' : 'status-inactive' ?>">
                                <?= extension_loaded('openssl') ? '✓ Disponible' : '✗ Non disponible' ?>
                            </span>
                        </div>
                        <div class="info-box">
                            <div class="info-box-title">PHPMailer</div>
                            <span class="status <?= file_exists(__DIR__ . '/../../vendor/autoload.php') ? 'status-active' : 'status-inactive' ?>">
                                <?= file_exists(__DIR__ . '/../../vendor/autoload.php') ? '✓ Installé' : '✗ Non installé' ?>
                            </span>
                        </div>
                        <div class="info-box">
                            <div class="info-box-title">fsockopen</div>
                            <span class="status <?= function_exists('fsockopen') ? 'status-active' : 'status-inactive' ?>">
                                <?= function_exists('fsockopen') ? '✓ Disponible' : '✗ Non disponible' ?>
                            </span>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><span class="card-icon">📁</span> Chemins</h3>
                    </div>
                    
                    <div class="info-box">
                        <div class="info-box-title">Racine Noteso</div>
                        <code><?= realpath(__DIR__ . '/..') ?></code>
                    </div>
                    <div class="info-box" style="margin-top: 12px;">
                        <div class="info-box-title">Dossier Data</div>
                        <code><?= realpath(__DIR__ . '/../data') ?: __DIR__ . '/../data (à créer)' ?></code>
                    </div>
                    <div class="info-box" style="margin-top: 12px;">
                        <div class="info-box-title">Fichier Config</div>
                        <code><?= CONFIG_FILE ?></code>
                    </div>
                </div>
                
            <?php endif; ?>
        </main>
    </div>
<?php endif; ?>
</body>
</html>
