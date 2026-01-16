<?php
/**
 * NOTESO - Diagnostic API
 * Ce script teste l'API et affiche les erreurs détaillées
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

header('Content-Type: text/html; charset=utf-8');

echo '<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Noteso - Debug API</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #0a0a0b; color: #fafafa; padding: 40px; max-width: 1000px; margin: 0 auto; }
        h1 { color: #3b82f6; }
        h2 { color: #a1a1aa; margin-top: 30px; border-bottom: 1px solid #27272a; padding-bottom: 10px; }
        .success { color: #22c55e; }
        .error { color: #ef4444; }
        .warning { color: #eab308; }
        pre { background: #141416; padding: 20px; border-radius: 8px; overflow-x: auto; font-size: 13px; border: 1px solid #27272a; }
        .box { background: #141416; border: 1px solid #27272a; border-radius: 12px; padding: 20px; margin: 20px 0; }
        code { background: #27272a; padding: 2px 6px; border-radius: 4px; }
    </style>
</head>
<body>
<h1>🔧 Diagnostic API Noteso</h1>';

// ============================================
// 1. Test de chargement des fichiers
// ============================================

echo '<h2>1. Vérification des fichiers</h2>';

$baseDir = __DIR__;
$rootDir = dirname(__DIR__);

$files = [
    'Database.php' => $baseDir . '/Database.php',
    'api.php' => $baseDir . '/api.php',
    'config.php' => $rootDir . '/config/config.php',
];

foreach ($files as $name => $path) {
    if (file_exists($path)) {
        echo "<p class='success'>✅ $name trouvé</p>";
    } else {
        echo "<p class='error'>❌ $name MANQUANT: $path</p>";
    }
}

// ============================================
// 2. Test de la configuration
// ============================================

echo '<h2>2. Chargement de la configuration</h2>';

$configPaths = [
    $rootDir . '/config/config.php',
    $rootDir . '/config.php',
    $baseDir . '/config.php',
];

$CONFIG = null;
foreach ($configPaths as $configPath) {
    if (file_exists($configPath)) {
        echo "<p>Tentative de chargement: <code>$configPath</code></p>";
        try {
            $CONFIG = require $configPath;
            echo "<p class='success'>✅ Configuration chargée</p>";
            break;
        } catch (Throwable $e) {
            echo "<p class='error'>❌ Erreur: " . htmlspecialchars($e->getMessage()) . "</p>";
        }
    }
}

if ($CONFIG) {
    echo '<div class="box"><pre>';
    echo "Database Host: " . ($CONFIG['database']['host'] ?? 'N/A') . "\n";
    echo "Database Name: " . ($CONFIG['database']['name'] ?? 'N/A') . "\n";
    echo "Database User: " . ($CONFIG['database']['user'] ?? 'N/A') . "\n";
    echo "Database Port: " . ($CONFIG['database']['port'] ?? 3306) . "\n";
    echo '</pre></div>';
}

// ============================================
// 3. Test de la classe Database
// ============================================

echo '<h2>3. Test de la classe Database</h2>';

try {
    require_once $baseDir . '/Database.php';
    echo "<p class='success'>✅ Database.php chargé</p>";
    
    if (class_exists('Database')) {
        echo "<p class='success'>✅ Classe Database existe</p>";
        
        // Configurer
        Database::configure([
            'host'     => $CONFIG['database']['host'] ?? 'localhost',
            'port'     => $CONFIG['database']['port'] ?? 3306,
            'database' => $CONFIG['database']['name'] ?? 'noteso',
            'username' => $CONFIG['database']['user'] ?? 'root',
            'password' => $CONFIG['database']['password'] ?? '',
            'charset'  => 'utf8mb4'
        ]);
        echo "<p class='success'>✅ Database configurée</p>";
        
        // Test connexion
        $pdo = Database::pdo();
        echo "<p class='success'>✅ Connexion PDO réussie</p>";
        
        // Test requête simple
        $result = Database::fetchColumn("SELECT 1");
        echo "<p class='success'>✅ Requête test réussie</p>";
        
    } else {
        echo "<p class='error'>❌ Classe Database non trouvée</p>";
    }
    
} catch (Throwable $e) {
    echo "<p class='error'>❌ Erreur Database: " . htmlspecialchars($e->getMessage()) . "</p>";
    echo "<pre class='error'>" . htmlspecialchars($e->getTraceAsString()) . "</pre>";
}

// ============================================
// 4. Test des fonctions helper
// ============================================

echo '<h2>4. Test des fonctions helpers</h2>';

// Définir les fonctions si elles n'existent pas pour tester
if (!function_exists('generateId')) {
    echo "<p class='warning'>⚠️ Fonction generateId() non définie - Définition manquante dans api.php ou Database.php</p>";
} else {
    echo "<p class='success'>✅ Fonction generateId() existe</p>";
}

if (!function_exists('logSecurityEvent')) {
    echo "<p class='warning'>⚠️ Fonction logSecurityEvent() non définie</p>";
} else {
    echo "<p class='success'>✅ Fonction logSecurityEvent() existe</p>";
}

// ============================================
// 5. Test de chargement de api.php
// ============================================

echo '<h2>5. Test de syntaxe api.php</h2>';

$apiPath = $baseDir . '/api.php';
$output = [];
$returnCode = 0;

exec("php -l " . escapeshellarg($apiPath) . " 2>&1", $output, $returnCode);

if ($returnCode === 0) {
    echo "<p class='success'>✅ Syntaxe PHP valide</p>";
} else {
    echo "<p class='error'>❌ Erreur de syntaxe:</p>";
    echo "<pre class='error'>" . htmlspecialchars(implode("\n", $output)) . "</pre>";
}

// ============================================
// 6. Test d'inclusion api.php (sans exécution)
// ============================================

echo '<h2>6. Analyse de api.php</h2>';

$apiContent = file_get_contents($apiPath);

// Vérifier les fonctions critiques
$requiredFunctions = [
    'generateId' => 'Génération d\'ID unique',
    'logSecurityEvent' => 'Log des événements de sécurité',
    'getAuthAdmin' => 'Authentification admin',
    'requireAuth' => 'Vérification authentification',
    'response' => 'Réponse JSON',
    'error' => 'Réponse erreur',
];

foreach ($requiredFunctions as $func => $desc) {
    if (preg_match('/function\s+' . $func . '\s*\(/', $apiContent)) {
        echo "<p class='success'>✅ Fonction $func() définie - $desc</p>";
    } else {
        echo "<p class='error'>❌ Fonction $func() MANQUANTE - $desc</p>";
    }
}

// ============================================
// 7. Test réel de l'API
// ============================================

echo '<h2>7. Test réel de l\'API (endpoint /)</h2>';

// Simuler une requête API
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI'] = '/';
$_SERVER['SCRIPT_NAME'] = '/api.php';

ob_start();
$apiError = null;

try {
    // On ne peut pas vraiment inclure api.php car il fait exit()
    // Mais on peut tester avec cURL
    
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $apiUrl = "$protocol://$host/api.php";
    
    echo "<p>URL testée: <code>$apiUrl</code></p>";
    
    $ch = curl_init($apiUrl);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_HEADER => true
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $headers = substr($response, 0, $headerSize);
    $body = substr($response, $headerSize);
    $curlError = curl_error($ch);
    curl_close($ch);
    
    echo "<p>HTTP Code: <strong>$httpCode</strong></p>";
    
    if ($curlError) {
        echo "<p class='error'>cURL Error: $curlError</p>";
    }
    
    echo "<div class='box'><strong>Headers:</strong><pre>" . htmlspecialchars($headers) . "</pre></div>";
    echo "<div class='box'><strong>Body:</strong><pre>" . htmlspecialchars($body) . "</pre></div>";
    
    if ($httpCode === 200) {
        $json = json_decode($body, true);
        if ($json && isset($json['status']) && $json['status'] === 'ok') {
            echo "<p class='success'>✅ API fonctionne correctement!</p>";
        }
    } else {
        echo "<p class='error'>❌ L'API retourne une erreur $httpCode</p>";
    }
    
} catch (Throwable $e) {
    echo "<p class='error'>❌ Exception: " . htmlspecialchars($e->getMessage()) . "</p>";
    echo "<pre class='error'>" . htmlspecialchars($e->getTraceAsString()) . "</pre>";
}

ob_end_flush();

// ============================================
// 8. Logs d'erreur PHP
// ============================================

echo '<h2>8. Dernières erreurs PHP</h2>';

$errorLog = ini_get('error_log');
echo "<p>Fichier de log: <code>" . ($errorLog ?: 'Par défaut système') . "</code></p>";

// Essayer de lire les logs Apache
$apacheErrorLogs = [
    '/var/log/apache2/error.log',
    '/var/log/httpd/error_log',
    '/var/log/apache/error.log',
];

foreach ($apacheErrorLogs as $logFile) {
    if (file_exists($logFile) && is_readable($logFile)) {
        echo "<p>Log Apache trouvé: <code>$logFile</code></p>";
        $lines = array_slice(file($logFile), -20);
        $relevantLines = array_filter($lines, fn($l) => stripos($l, 'noteso') !== false || stripos($l, 'api.php') !== false);
        if ($relevantLines) {
            echo "<pre>" . htmlspecialchars(implode("", array_slice($relevantLines, -10))) . "</pre>";
        } else {
            echo "<p class='warning'>Aucune erreur récente liée à Noteso</p>";
        }
        break;
    }
}

echo '<h2>💡 Actions recommandées</h2>';
echo '<div class="box">
<ol>
<li>Vérifiez les logs Apache: <code>sudo tail -50 /var/log/apache2/error.log | grep -i noteso</code></li>
<li>Testez manuellement: <code>php -f /srv/web/noteso/public/api.php</code></li>
<li>Vérifiez les permissions: <code>ls -la /srv/web/noteso/public/</code></li>
</ol>
</div>';

echo '<p style="margin-top: 40px; color: #71717a; text-align: center;">
    <a href="/" style="color: #3b82f6;">← Retour au Dashboard</a> | 
    <a href="/check.php" style="color: #3b82f6;">Vérification complète</a>
</p>';

echo '</body></html>';
