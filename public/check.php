<?php
/**
 * NOTESO - Diagnostic
 */

header('Content-Type: text/html; charset=utf-8');

echo "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Noteso Check</title>";
echo "<style>body{font-family:system-ui;background:#0f172a;color:#fff;padding:40px;max-width:800px;margin:0 auto}";
echo ".ok{color:#22c55e}.err{color:#ef4444}.warn{color:#f59e0b}pre{background:#1e293b;padding:20px;border-radius:12px;overflow-x:auto}</style></head><body>";
echo "<h1>🔍 Noteso - Diagnostic</h1><pre>";

// PHP Version
$phpOk = version_compare(PHP_VERSION, '8.0', '>=');
echo ($phpOk ? "✅" : "❌") . " PHP " . PHP_VERSION . "\n";

// Extensions
$extensions = ['pdo', 'pdo_mysql', 'json', 'mbstring'];
foreach ($extensions as $ext) {
    $ok = extension_loaded($ext);
    echo ($ok ? "✅" : "❌") . " Extension $ext\n";
}

// Fichiers
echo "\n📁 FICHIERS:\n";
$files = [
    'Database.php' => __DIR__ . '/Database.php',
    'api.php' => __DIR__ . '/api.php',
    'index.html' => __DIR__ . '/index.html',
    'config.php' => dirname(__DIR__) . '/config/config.php',
];

foreach ($files as $name => $path) {
    $exists = file_exists($path);
    echo ($exists ? "✅" : "❌") . " $name\n";
}

// Config
echo "\n⚙️ CONFIGURATION:\n";
$CONFIG = [];
$configPaths = [
    dirname(__DIR__) . '/config/config.php',
    dirname(__DIR__) . '/config.php',
    __DIR__ . '/config.php',
];

foreach ($configPaths as $path) {
    if (file_exists($path)) {
        $CONFIG = require $path;
        echo "✅ Config trouvée: " . basename(dirname($path)) . "/" . basename($path) . "\n";
        break;
    }
}

if (empty($CONFIG)) {
    echo "❌ Aucune configuration trouvée!\n";
}

// Base de données
echo "\n🗄️ BASE DE DONNÉES:\n";
if (!empty($CONFIG['database'])) {
    try {
        require_once __DIR__ . '/Database.php';
        
        Database::configure([
            'host'     => $CONFIG['database']['host'] ?? 'localhost',
            'port'     => $CONFIG['database']['port'] ?? 3306,
            'database' => $CONFIG['database']['name'] ?? 'noteso',
            'username' => $CONFIG['database']['user'] ?? 'root',
            'password' => $CONFIG['database']['password'] ?? '',
            'charset'  => 'utf8mb4'
        ]);
        
        $version = Database::fetchColumn("SELECT VERSION()");
        echo "✅ MySQL connecté: $version\n";
        
        // Tables
        $tables = Database::fetchAll("SHOW TABLES");
        echo "✅ " . count($tables) . " tables trouvées\n";
        
        // Admin
        $adminCount = Database::fetchColumn("SELECT COUNT(*) FROM admins WHERE is_active = 1");
        if ($adminCount > 0) {
            echo "✅ $adminCount admin(s) actif(s)\n";
        } else {
            echo "⚠️ Aucun admin actif - exécutez init.php\n";
        }
        
    } catch (Exception $e) {
        echo "❌ Erreur MySQL: " . $e->getMessage() . "\n";
    }
}

// Test API
echo "\n🔌 TEST API:\n";
$apiUrl = (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['REQUEST_URI']) . '/api.php?action=health';
echo "URL: $apiUrl\n";

$ch = curl_init($apiUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 5);
$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($httpCode === 200) {
    $data = json_decode($response, true);
    echo "✅ API répond: " . ($data['status'] ?? 'ok') . "\n";
} else {
    echo "❌ API erreur (HTTP $httpCode)\n";
}

echo "\n" . str_repeat("=", 50) . "\n";
echo "📍 URLs:\n";
echo "   Dashboard: <a href='index.html'>index.html</a>\n";
echo "   Init admin: <a href='init.php'>init.php</a>\n";
echo "   API Health: <a href='api.php?action=health'>api.php?action=health</a>\n";

echo "</pre></body></html>";
