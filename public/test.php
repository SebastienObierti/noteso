<?php
/**
 * TEST NOTESO - Diagnostic
 * Accédez à ce fichier pour vérifier que tout fonctionne
 */

header('Content-Type: application/json');

// Dossiers
$baseDir = __DIR__;                    // /public
$rootDir = dirname(__DIR__);           // /srv/web/noteso
$dataDir = $baseDir . '/data';

$tests = [];

// Test 1: PHP fonctionne
$tests['php'] = [
    'status' => 'ok',
    'version' => PHP_VERSION
];

// Test 2: Dossier data accessible en écriture
if (!is_dir($dataDir)) {
    @mkdir($dataDir, 0755, true);
}
$tests['data_dir'] = [
    'status' => is_writable($dataDir) ? 'ok' : 'error',
    'path' => $dataDir,
    'writable' => is_writable($dataDir),
    'exists' => is_dir($dataDir)
];

// Test 3: Config existe et est lisible
$configPaths = [
    $rootDir . '/config/config.php',
    $rootDir . '/config.php',
    $baseDir . '/config.php',
];

$configFile = null;
$configLoaded = false;
$configData = null;

foreach ($configPaths as $path) {
    if (file_exists($path)) {
        $configFile = $path;
        $configData = require $path;
        $configLoaded = is_array($configData);
        break;
    }
}

$tests['config'] = [
    'status' => $configLoaded ? 'ok' : 'error',
    'path' => $configFile,
    'searched_paths' => $configPaths,
    'loaded' => $configLoaded,
    'has_admins' => isset($configData['admins']),
    'admin_count' => isset($configData['admins']) ? count($configData['admins']) : 0,
    'first_admin_email' => isset($configData['admins'][0]['email']) ? $configData['admins'][0]['email'] : 'N/A'
];

// Test 4: JSON fonctionne
$tests['json'] = [
    'status' => 'ok',
    'test' => json_encode(['test' => true]) === '{"test":true}'
];

// Test 5: cURL disponible
$tests['curl'] = [
    'status' => function_exists('curl_init') ? 'ok' : 'warning',
    'available' => function_exists('curl_init')
];

// Test 6: API accessible
$apiFile = $baseDir . '/api.php';
$tests['api'] = [
    'status' => file_exists($apiFile) ? 'ok' : 'error',
    'exists' => file_exists($apiFile),
    'size' => file_exists($apiFile) ? filesize($apiFile) : 0
];

// Test 7: Fichier admins.json
$adminsFile = $dataDir . '/admins.json';
$adminsData = null;
if (file_exists($adminsFile)) {
    $adminsData = json_decode(file_get_contents($adminsFile), true);
}
$tests['admins_data'] = [
    'status' => 'ok',
    'exists' => file_exists($adminsFile),
    'count' => is_array($adminsData) ? count($adminsData) : 0,
    'message' => file_exists($adminsFile) ? 'Données admins existantes' : 'Sera créé à la première connexion'
];

// Résultat global
$allOk = true;
foreach ($tests as $test) {
    if ($test['status'] === 'error') {
        $allOk = false;
        break;
    }
}

echo json_encode([
    'success' => $allOk,
    'message' => $allOk ? 'Tout fonctionne!' : 'Certains tests ont échoué',
    'structure' => [
        'base_dir' => $baseDir,
        'root_dir' => $rootDir,
        'data_dir' => $dataDir
    ],
    'tests' => $tests
], JSON_PRETTY_PRINT);
