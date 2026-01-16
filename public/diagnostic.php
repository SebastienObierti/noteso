<?php
/**
 * NOTESO - Diagnostic complet
 * Testez ce fichier pour voir les erreurs
 */

// Activer TOUTES les erreurs
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');

$diagnostic = [
    'php_version' => PHP_VERSION,
    'timestamp' => date('Y-m-d H:i:s'),
    'tests' => []
];

// Test 1: Chemins
$diagnostic['paths'] = [
    'BASE_DIR' => __DIR__,
    'ROOT_DIR' => dirname(__DIR__),
    'current_file' => __FILE__
];

// Test 2: Fichier Database.php existe ?
$databaseFile = __DIR__ . '/Database.php';
$diagnostic['tests']['database_file'] = [
    'path' => $databaseFile,
    'exists' => file_exists($databaseFile),
    'readable' => is_readable($databaseFile)
];

// Test 3: Config existe ?
$configPaths = [
    dirname(__DIR__) . '/config/config.php',
    dirname(__DIR__) . '/config.php',
    __DIR__ . '/config.php',
];

$configFound = null;
foreach ($configPaths as $path) {
    if (file_exists($path)) {
        $configFound = $path;
        break;
    }
}

$diagnostic['tests']['config'] = [
    'searched' => $configPaths,
    'found' => $configFound,
    'exists' => $configFound !== null
];

// Test 4: Charger la config
if ($configFound) {
    try {
        $CONFIG = require $configFound;
        $diagnostic['tests']['config_load'] = [
            'success' => true,
            'has_database' => isset($CONFIG['database']),
            'database_host' => $CONFIG['database']['host'] ?? 'NOT SET',
            'database_name' => $CONFIG['database']['name'] ?? 'NOT SET'
        ];
    } catch (Throwable $e) {
        $diagnostic['tests']['config_load'] = [
            'success' => false,
            'error' => $e->getMessage()
        ];
    }
}

// Test 5: Charger Database.php
if (file_exists($databaseFile)) {
    try {
        require_once $databaseFile;
        $diagnostic['tests']['database_class'] = [
            'loaded' => true,
            'class_exists' => class_exists('Database')
        ];
    } catch (Throwable $e) {
        $diagnostic['tests']['database_class'] = [
            'loaded' => false,
            'error' => $e->getMessage()
        ];
    }
}

// Test 6: Connexion MySQL
if (class_exists('Database') && isset($CONFIG['database'])) {
    try {
        Database::configure([
            'host'     => $CONFIG['database']['host'] ?? 'localhost',
            'port'     => $CONFIG['database']['port'] ?? 3306,
            'database' => $CONFIG['database']['name'] ?? 'noteso',
            'username' => $CONFIG['database']['user'] ?? 'root',
            'password' => $CONFIG['database']['password'] ?? '',
            'charset'  => 'utf8mb4'
        ]);
        
        // Test simple query
        $result = Database::fetchColumn("SELECT 1");
        
        $diagnostic['tests']['mysql_connection'] = [
            'success' => true,
            'test_query' => $result == 1
        ];
        
        // Test tables existent
        $tables = Database::fetchAll("SHOW TABLES");
        $diagnostic['tests']['mysql_tables'] = [
            'count' => count($tables),
            'list' => array_map(fn($t) => array_values($t)[0], $tables)
        ];
        
    } catch (Throwable $e) {
        $diagnostic['tests']['mysql_connection'] = [
            'success' => false,
            'error' => $e->getMessage(),
            'trace' => $e->getTraceAsString()
        ];
    }
}

// Test 7: Vérifier le routing
$diagnostic['routing'] = [
    'REQUEST_METHOD' => $_SERVER['REQUEST_METHOD'] ?? 'NOT SET',
    'REQUEST_URI' => $_SERVER['REQUEST_URI'] ?? 'NOT SET',
    'SCRIPT_NAME' => $_SERVER['SCRIPT_NAME'] ?? 'NOT SET',
    'PATH_INFO' => $_SERVER['PATH_INFO'] ?? 'NOT SET',
    'QUERY_STRING' => $_SERVER['QUERY_STRING'] ?? 'NOT SET',
    '_route_param' => $_GET['_route'] ?? 'NOT SET'
];

// Test 8: Vérifier api.php syntaxe
$apiFile = __DIR__ . '/api.php';
if (file_exists($apiFile)) {
    $output = [];
    $returnCode = 0;
    exec("php -l " . escapeshellarg($apiFile) . " 2>&1", $output, $returnCode);
    
    $diagnostic['tests']['api_syntax'] = [
        'file' => $apiFile,
        'valid' => $returnCode === 0,
        'output' => implode("\n", $output)
    ];
}

// Résultat
$allOk = true;
foreach ($diagnostic['tests'] as $test) {
    if (isset($test['success']) && !$test['success']) {
        $allOk = false;
        break;
    }
    if (isset($test['exists']) && !$test['exists']) {
        $allOk = false;
        break;
    }
}

$diagnostic['overall'] = $allOk ? 'OK' : 'ERRORS FOUND';

echo json_encode($diagnostic, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
