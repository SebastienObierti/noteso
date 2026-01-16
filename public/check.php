<?php
/**
 * NOTESO - Vérificateur d'installation
 * Accédez à ce fichier pour diagnostiquer votre installation
 * URL: https://votre-domaine.fr/check.php
 */

// Désactiver l'affichage d'erreurs pour le HTML
error_reporting(E_ALL);
ini_set('display_errors', 0);

// Collecter les erreurs
$errors = [];
$warnings = [];
$success = [];

// ============================================
// FONCTIONS HELPERS
// ============================================

function checkPassed($message) {
    global $success;
    $success[] = $message;
}

function checkWarning($message) {
    global $warnings;
    $warnings[] = $message;
}

function checkFailed($message) {
    global $errors;
    $errors[] = $message;
}

function formatBytes($bytes) {
    if ($bytes >= 1073741824) return number_format($bytes / 1073741824, 2) . ' GB';
    if ($bytes >= 1048576) return number_format($bytes / 1048576, 2) . ' MB';
    if ($bytes >= 1024) return number_format($bytes / 1024, 2) . ' KB';
    return $bytes . ' bytes';
}

// ============================================
// 1. VÉRIFICATION PHP
// ============================================

$phpVersion = phpversion();
if (version_compare($phpVersion, '8.0', '>=')) {
    checkPassed("PHP $phpVersion (requis: 8.0+)");
} elseif (version_compare($phpVersion, '7.4', '>=')) {
    checkWarning("PHP $phpVersion - Recommandé: PHP 8.0+");
} else {
    checkFailed("PHP $phpVersion - Requis: PHP 7.4+ minimum");
}

// Extensions PHP requises
$requiredExtensions = ['pdo', 'pdo_mysql', 'json', 'mbstring', 'openssl', 'curl'];
$optionalExtensions = ['gd', 'zip', 'fileinfo'];

foreach ($requiredExtensions as $ext) {
    if (extension_loaded($ext)) {
        checkPassed("Extension PHP: $ext");
    } else {
        checkFailed("Extension PHP manquante: $ext");
    }
}

foreach ($optionalExtensions as $ext) {
    if (extension_loaded($ext)) {
        checkPassed("Extension PHP optionnelle: $ext");
    } else {
        checkWarning("Extension PHP optionnelle manquante: $ext");
    }
}

// ============================================
// 2. VÉRIFICATION FICHIERS
// ============================================

$baseDir = __DIR__;
$rootDir = dirname(__DIR__);

$requiredFiles = [
    'api.php' => $baseDir . '/api.php',
    'index.html' => $baseDir . '/index.html',
    'Database.php' => $baseDir . '/Database.php',
    '.htaccess' => $baseDir . '/.htaccess',
];

$optionalFiles = [
    'config.php' => $rootDir . '/config/config.php',
    'config.php (alt)' => $rootDir . '/config.php',
    'TOTP.php' => $baseDir . '/TOTP.php',
    'RateLimiter.php' => $baseDir . '/RateLimiter.php',
];

foreach ($requiredFiles as $name => $path) {
    if (file_exists($path)) {
        $size = filesize($path);
        checkPassed("Fichier $name présent (" . formatBytes($size) . ")");
    } else {
        checkFailed("Fichier manquant: $name");
    }
}

// Config file
$configFound = false;
$configPath = null;
$configPaths = [
    $rootDir . '/config/config.php',
    $rootDir . '/config.php',
    $baseDir . '/config.php',
];

foreach ($configPaths as $path) {
    if (file_exists($path)) {
        $configFound = true;
        $configPath = $path;
        checkPassed("Configuration trouvée: " . basename(dirname($path)) . '/' . basename($path));
        break;
    }
}

if (!$configFound) {
    checkFailed("Aucun fichier de configuration trouvé");
}

// ============================================
// 3. VÉRIFICATION BASE DE DONNÉES
// ============================================

$dbConnected = false;
$dbError = null;
$tablesStatus = [];

if ($configFound && $configPath) {
    try {
        $config = require $configPath;
        
        $dsn = sprintf(
            "mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4",
            $config['database']['host'] ?? 'localhost',
            $config['database']['port'] ?? 3306,
            $config['database']['name'] ?? 'noteso'
        );
        
        $pdo = new PDO($dsn, 
            $config['database']['user'] ?? 'root',
            $config['database']['password'] ?? '',
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
        );
        
        $dbConnected = true;
        checkPassed("Connexion MySQL réussie");
        
        // Vérifier la version MySQL
        $mysqlVersion = $pdo->query("SELECT VERSION()")->fetchColumn();
        if (strpos($mysqlVersion, '8.') === 0) {
            checkPassed("MySQL $mysqlVersion");
        } elseif (strpos($mysqlVersion, 'MariaDB') !== false) {
            checkPassed("MariaDB détecté: $mysqlVersion");
        } else {
            checkWarning("MySQL $mysqlVersion - Recommandé: MySQL 8.0+");
        }
        
        // Vérifier les tables
        $requiredTables = [
            'admins', 'sessions', 'sites', 'users', 'payments', 
            'subscriptions', 'activities', 'notifications', 'settings',
            'monitoring', 'reports', 'api_keys', 'security_events'
        ];
        
        $existingTables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);
        
        foreach ($requiredTables as $table) {
            if (in_array($table, $existingTables)) {
                $count = $pdo->query("SELECT COUNT(*) FROM `$table`")->fetchColumn();
                $tablesStatus[$table] = ['exists' => true, 'count' => $count];
                checkPassed("Table '$table' présente ($count enregistrements)");
            } else {
                $tablesStatus[$table] = ['exists' => false, 'count' => 0];
                checkFailed("Table manquante: $table");
            }
        }
        
        // Vérifier s'il y a un admin
        if (isset($tablesStatus['admins']) && $tablesStatus['admins']['exists']) {
            $adminCount = $tablesStatus['admins']['count'];
            if ($adminCount > 0) {
                checkPassed("$adminCount administrateur(s) configuré(s)");
            } else {
                checkWarning("Aucun administrateur configuré - Exécutez le script d'initialisation");
            }
        }
        
    } catch (PDOException $e) {
        $dbError = $e->getMessage();
        checkFailed("Connexion MySQL échouée: " . $e->getMessage());
    }
}

// ============================================
// 4. VÉRIFICATION PERMISSIONS
// ============================================

$dataDir = $baseDir . '/data';
if (!is_dir($dataDir)) {
    @mkdir($dataDir, 0755, true);
}

if (is_writable($baseDir)) {
    checkPassed("Dossier public/ accessible en écriture");
} else {
    checkWarning("Dossier public/ non accessible en écriture");
}

if (is_dir($dataDir) && is_writable($dataDir)) {
    checkPassed("Dossier data/ accessible en écriture");
} else {
    checkWarning("Dossier data/ non accessible en écriture");
}

// ============================================
// 5. VÉRIFICATION SERVEUR WEB
// ============================================

$serverSoftware = $_SERVER['SERVER_SOFTWARE'] ?? 'Inconnu';
if (stripos($serverSoftware, 'apache') !== false) {
    checkPassed("Serveur Web: Apache");
    
    // Vérifier mod_rewrite
    if (function_exists('apache_get_modules') && in_array('mod_rewrite', apache_get_modules())) {
        checkPassed("mod_rewrite activé");
    } else {
        checkWarning("mod_rewrite - Impossible de vérifier (mais probablement OK)");
    }
} elseif (stripos($serverSoftware, 'nginx') !== false) {
    checkPassed("Serveur Web: Nginx");
} else {
    checkPassed("Serveur Web: $serverSoftware");
}

// HTTPS
if ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || ($_SERVER['SERVER_PORT'] ?? 80) == 443) {
    checkPassed("HTTPS activé");
} else {
    checkWarning("HTTPS non détecté - Recommandé en production");
}

// ============================================
// 6. TEST API
// ============================================

$apiWorks = false;
$apiTestUrl = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http') 
    . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') 
    . dirname($_SERVER['REQUEST_URI']) . '/api.php';

if (function_exists('curl_init')) {
    $ch = curl_init($apiTestUrl);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_SSL_VERIFYPEER => false
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode === 200) {
        $data = json_decode($response, true);
        if (isset($data['status']) && $data['status'] === 'ok') {
            $apiWorks = true;
            checkPassed("API accessible et fonctionnelle");
        } else {
            checkWarning("API accessible mais réponse inattendue");
        }
    } else {
        checkFailed("API non accessible (HTTP $httpCode)");
    }
} else {
    checkWarning("cURL non disponible - Impossible de tester l'API");
}

// ============================================
// 7. CONFIGURATION SMTP (si disponible)
// ============================================

if ($configFound && isset($config['smtp'])) {
    if ($config['smtp']['enabled'] ?? false) {
        checkPassed("SMTP configuré: " . ($config['smtp']['host'] ?? 'N/A'));
    } else {
        checkWarning("SMTP désactivé - Les emails ne seront pas envoyés");
    }
}

// ============================================
// RÉSUMÉ
// ============================================

$totalChecks = count($success) + count($warnings) + count($errors);
$score = $totalChecks > 0 ? round((count($success) / $totalChecks) * 100) : 0;

$overallStatus = 'success';
if (count($errors) > 0) {
    $overallStatus = 'error';
} elseif (count($warnings) > 0) {
    $overallStatus = 'warning';
}

?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Noteso - Vérification d'installation</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0a0b;
            --bg-secondary: #111113;
            --bg-card: #141416;
            --border: #27272a;
            --text-primary: #fafafa;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            --success: #22c55e;
            --warning: #eab308;
            --danger: #ef4444;
            --info: #3b82f6;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 40px 20px;
        }
        
        .container {
            max-width: 900px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
        }
        
        .logo {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            font-size: 36px;
            font-weight: 700;
            color: white;
        }
        
        .header h1 {
            font-size: 28px;
            margin-bottom: 8px;
        }
        
        .header p {
            color: var(--text-secondary);
        }
        
        .score-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 32px;
            text-align: center;
            margin-bottom: 32px;
        }
        
        .score-circle {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            font-size: 36px;
            font-weight: 700;
        }
        
        .score-circle.success { background: rgba(34, 197, 94, 0.15); color: var(--success); border: 3px solid var(--success); }
        .score-circle.warning { background: rgba(234, 179, 8, 0.15); color: var(--warning); border: 3px solid var(--warning); }
        .score-circle.error { background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 3px solid var(--danger); }
        
        .score-label {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 8px;
        }
        
        .score-stats {
            display: flex;
            justify-content: center;
            gap: 32px;
            margin-top: 20px;
        }
        
        .score-stat {
            text-align: center;
        }
        
        .score-stat-value {
            font-size: 24px;
            font-weight: 700;
        }
        
        .score-stat-label {
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
        }
        
        .section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            margin-bottom: 24px;
            overflow: hidden;
        }
        
        .section-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .section-icon {
            font-size: 24px;
        }
        
        .section-title {
            font-size: 16px;
            font-weight: 600;
        }
        
        .check-list {
            padding: 8px 0;
        }
        
        .check-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 24px;
            border-bottom: 1px solid var(--border);
        }
        
        .check-item:last-child {
            border-bottom: none;
        }
        
        .check-icon {
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            flex-shrink: 0;
        }
        
        .check-icon.success { background: rgba(34, 197, 94, 0.15); color: var(--success); }
        .check-icon.warning { background: rgba(234, 179, 8, 0.15); color: var(--warning); }
        .check-icon.error { background: rgba(239, 68, 68, 0.15); color: var(--danger); }
        
        .check-text {
            font-size: 13px;
            color: var(--text-secondary);
        }
        
        .info-box {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin: 24px;
        }
        
        .info-box h4 {
            font-size: 14px;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .info-box code {
            display: block;
            background: var(--bg-primary);
            padding: 12px 16px;
            border-radius: 8px;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 12px;
            overflow-x: auto;
            margin-top: 8px;
        }
        
        .actions {
            display: flex;
            gap: 12px;
            justify-content: center;
            margin-top: 32px;
        }
        
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 12px 24px;
            border-radius: 10px;
            font-size: 14px;
            font-weight: 500;
            text-decoration: none;
            transition: all 0.2s;
            border: none;
            cursor: pointer;
            font-family: inherit;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            color: white;
        }
        
        .btn-primary:hover {
            opacity: 0.9;
            transform: translateY(-2px);
        }
        
        .btn-secondary {
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border: 1px solid var(--border);
        }
        
        .btn-secondary:hover {
            border-color: var(--info);
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 24px;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 12px;
        }
        
        @media (max-width: 600px) {
            .score-stats {
                flex-direction: column;
                gap: 16px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">N</div>
            <h1>Vérification d'installation</h1>
            <p>Diagnostic de votre installation Noteso</p>
        </div>
        
        <div class="score-card">
            <div class="score-circle <?= $overallStatus ?>">
                <?= $score ?>%
            </div>
            <div class="score-label">
                <?php if ($overallStatus === 'success'): ?>
                    ✅ Installation réussie
                <?php elseif ($overallStatus === 'warning'): ?>
                    ⚠️ Installation partielle
                <?php else: ?>
                    ❌ Problèmes détectés
                <?php endif; ?>
            </div>
            <div class="score-stats">
                <div class="score-stat">
                    <div class="score-stat-value" style="color: var(--success)"><?= count($success) ?></div>
                    <div class="score-stat-label">Réussis</div>
                </div>
                <div class="score-stat">
                    <div class="score-stat-value" style="color: var(--warning)"><?= count($warnings) ?></div>
                    <div class="score-stat-label">Avertissements</div>
                </div>
                <div class="score-stat">
                    <div class="score-stat-value" style="color: var(--danger)"><?= count($errors) ?></div>
                    <div class="score-stat-label">Erreurs</div>
                </div>
            </div>
        </div>
        
        <?php if (count($errors) > 0): ?>
        <div class="section">
            <div class="section-header">
                <span class="section-icon">❌</span>
                <span class="section-title">Erreurs (<?= count($errors) ?>)</span>
            </div>
            <div class="check-list">
                <?php foreach ($errors as $error): ?>
                <div class="check-item">
                    <div class="check-icon error">✗</div>
                    <div class="check-text"><?= htmlspecialchars($error) ?></div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>
        
        <?php if (count($warnings) > 0): ?>
        <div class="section">
            <div class="section-header">
                <span class="section-icon">⚠️</span>
                <span class="section-title">Avertissements (<?= count($warnings) ?>)</span>
            </div>
            <div class="check-list">
                <?php foreach ($warnings as $warning): ?>
                <div class="check-item">
                    <div class="check-icon warning">!</div>
                    <div class="check-text"><?= htmlspecialchars($warning) ?></div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>
        
        <div class="section">
            <div class="section-header">
                <span class="section-icon">✅</span>
                <span class="section-title">Vérifications réussies (<?= count($success) ?>)</span>
            </div>
            <div class="check-list">
                <?php foreach ($success as $item): ?>
                <div class="check-item">
                    <div class="check-icon success">✓</div>
                    <div class="check-text"><?= htmlspecialchars($item) ?></div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">
                <span class="section-icon">ℹ️</span>
                <span class="section-title">Informations système</span>
            </div>
            <div class="info-box">
                <h4>🖥️ Environnement</h4>
                <code>
PHP: <?= phpversion() ?><br>
Serveur: <?= $_SERVER['SERVER_SOFTWARE'] ?? 'Inconnu' ?><br>
OS: <?= php_uname('s') . ' ' . php_uname('r') ?><br>
Mémoire max: <?= ini_get('memory_limit') ?><br>
Upload max: <?= ini_get('upload_max_filesize') ?><br>
Timezone: <?= date_default_timezone_get() ?>
                </code>
            </div>
            
            <?php if ($dbConnected): ?>
            <div class="info-box">
                <h4>🗄️ Base de données</h4>
                <code>
MySQL: <?= $mysqlVersion ?? 'N/A' ?><br>
Host: <?= $config['database']['host'] ?? 'localhost' ?><br>
Database: <?= $config['database']['name'] ?? 'noteso' ?><br>
Tables: <?= count(array_filter($tablesStatus, fn($t) => $t['exists'])) ?> / <?= count($tablesStatus) ?>
                </code>
            </div>
            <?php endif; ?>
            
            <div class="info-box">
                <h4>📁 Chemins</h4>
                <code>
Document Root: <?= $_SERVER['DOCUMENT_ROOT'] ?? 'N/A' ?><br>
Script: <?= __FILE__ ?><br>
Config: <?= $configPath ?? 'Non trouvé' ?>
                </code>
            </div>
        </div>
        
        <?php if (count($errors) > 0): ?>
        <div class="section">
            <div class="section-header">
                <span class="section-icon">🔧</span>
                <span class="section-title">Solutions suggérées</span>
            </div>
            <div class="info-box">
                <?php if (in_array(true, array_map(fn($e) => strpos($e, 'Table manquante') !== false, $errors))): ?>
                <h4>📋 Tables manquantes</h4>
                <p style="color: var(--text-secondary); margin-bottom: 12px;">Exécutez le script SQL de création des tables:</p>
                <code>mysql -u root -p noteso < noteso_schema.sql</code>
                <?php endif; ?>
                
                <?php if (in_array(true, array_map(fn($e) => strpos($e, 'Connexion MySQL') !== false, $errors))): ?>
                <h4 style="margin-top: 16px;">🗄️ Connexion MySQL</h4>
                <p style="color: var(--text-secondary); margin-bottom: 12px;">Vérifiez votre fichier config.php:</p>
                <code>
'database' => [
    'host'     => 'localhost',
    'port'     => 3306,
    'name'     => 'noteso',
    'user'     => 'votre_user',
    'password' => 'votre_password',
]
                </code>
                <?php endif; ?>
                
                <?php if (in_array(true, array_map(fn($e) => strpos($e, 'Fichier manquant') !== false, $errors))): ?>
                <h4 style="margin-top: 16px;">📁 Fichiers manquants</h4>
                <p style="color: var(--text-secondary);">Vérifiez que tous les fichiers ont été correctement uploadés.</p>
                <?php endif; ?>
            </div>
        </div>
        <?php endif; ?>
        
        <div class="actions">
            <a href="/" class="btn btn-primary">🏠 Accéder au Dashboard</a>
            <button onclick="location.reload()" class="btn btn-secondary">🔄 Relancer le test</button>
        </div>
        
        <div class="footer">
            <p>Noteso Installation Checker v1.0</p>
            <p style="margin-top: 8px;">Généré le <?= date('d/m/Y à H:i:s') ?></p>
            <p style="margin-top: 16px; color: var(--warning);">⚠️ Supprimez ce fichier après vérification pour des raisons de sécurité.</p>
        </div>
    </div>
</body>
</html>
