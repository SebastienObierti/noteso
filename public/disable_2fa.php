<?php
/**
 * NOTESO - Désactiver le 2FA d'urgence
 * ⚠️ SUPPRIMER CE FICHIER APRÈS UTILISATION !
 */

header('Content-Type: text/html; charset=utf-8');

echo "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Désactiver 2FA</title>";
echo "<style>body{font-family:system-ui;background:#0f172a;color:#fff;padding:40px;max-width:600px;margin:0 auto}";
echo "input,button{padding:12px;border-radius:8px;border:1px solid #334155;background:#1e293b;color:#fff;width:100%;margin:8px 0}";
echo "button{background:#3b82f6;border:none;cursor:pointer}button:hover{background:#2563eb}";
echo ".warn{background:#7c2d12;padding:16px;border-radius:8px;margin:16px 0}</style></head><body>";

echo "<h1>🔓 Désactiver le 2FA</h1>";
echo "<div class='warn'>⚠️ <strong>ATTENTION</strong>: Supprimez ce fichier immédiatement après utilisation !</div>";

require_once __DIR__ . '/Database.php';

$CONFIG = [];
$configPaths = [
    dirname(__DIR__) . '/config/config.php',
    dirname(__DIR__) . '/config.php',
    __DIR__ . '/config.php',
];

foreach ($configPaths as $path) {
    if (file_exists($path)) {
        $CONFIG = require $path;
        break;
    }
}

if (empty($CONFIG)) {
    die("<p style='color:#ef4444'>❌ Configuration non trouvée</p></body></html>");
}

Database::configure([
    'host'     => $CONFIG['database']['host'] ?? 'localhost',
    'port'     => $CONFIG['database']['port'] ?? 3306,
    'database' => $CONFIG['database']['name'] ?? 'noteso',
    'username' => $CONFIG['database']['user'] ?? 'root',
    'password' => $CONFIG['database']['password'] ?? '',
    'charset'  => 'utf8mb4'
]);

// Traitement du formulaire
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['email'])) {
    $email = trim($_POST['email']);
    
    $admin = Database::fetch("SELECT id, email, first_name, last_name, two_factor_enabled FROM admins WHERE email = ?", [$email]);
    
    if (!$admin) {
        echo "<p style='color:#ef4444'>❌ Admin non trouvé: $email</p>";
    } elseif (!$admin['two_factor_enabled']) {
        echo "<p style='color:#f59e0b'>⚠️ Le 2FA n'est pas activé pour cet admin</p>";
    } else {
        Database::query(
            "UPDATE admins SET two_factor_enabled = 0, two_factor_secret = NULL, backup_codes = NULL WHERE id = ?",
            [$admin['id']]
        );
        
        echo "<p style='color:#22c55e'>✅ 2FA désactivé pour {$admin['first_name']} {$admin['last_name']} ({$admin['email']})</p>";
        echo "<p><a href='index.html' style='color:#3b82f6'>→ Retour au login</a></p>";
    }
}

// Liste des admins avec 2FA
$admins = Database::fetchAll("SELECT email, first_name, last_name, two_factor_enabled FROM admins WHERE is_active = 1 ORDER BY email");

echo "<h2>Admins actifs</h2><ul>";
foreach ($admins as $a) {
    $status = $a['two_factor_enabled'] ? '🔐 2FA activé' : '🔓 2FA désactivé';
    echo "<li>{$a['first_name']} {$a['last_name']} ({$a['email']}) - $status</li>";
}
echo "</ul>";

echo "<h2>Désactiver le 2FA</h2>";
echo "<form method='POST'>";
echo "<input type='email' name='email' placeholder='Email de l'admin' required>";
echo "<button type='submit'>Désactiver le 2FA</button>";
echo "</form>";

echo "</body></html>";
