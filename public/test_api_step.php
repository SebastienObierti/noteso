<?php
/**
 * Test étape par étape du chargement de api.php
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<pre style='background:#111;color:#0f0;padding:20px;font-family:monospace;'>";
echo "=== TEST API.PHP ÉTAPE PAR ÉTAPE ===\n\n";

$baseDir = __DIR__;
$rootDir = dirname(__DIR__);

// Étape 1: Config
echo "[1] Chargement config...\n";
$CONFIG = [];
$configPaths = [
    $rootDir . '/config/config.php',
    $rootDir . '/config.php',
    $baseDir . '/config.php',
];

foreach ($configPaths as $configPath) {
    if (file_exists($configPath)) {
        $CONFIG = require $configPath;
        echo "    ✓ Config chargée: $configPath\n";
        break;
    }
}

// Étape 2: Database.php
echo "\n[2] Chargement Database.php...\n";
try {
    require_once $baseDir . '/Database.php';
    echo "    ✓ Database.php chargé\n";
} catch (Throwable $e) {
    echo "    ✗ ERREUR: " . $e->getMessage() . "\n";
    exit;
}

// Étape 3: Configuration Database
echo "\n[3] Configuration Database::configure()...\n";
try {
    Database::configure([
        'host'     => $CONFIG['database']['host'] ?? 'localhost',
        'port'     => $CONFIG['database']['port'] ?? 3306,
        'database' => $CONFIG['database']['name'] ?? 'noteso',
        'username' => $CONFIG['database']['user'] ?? 'root',
        'password' => $CONFIG['database']['password'] ?? '',
        'charset'  => 'utf8mb4'
    ]);
    echo "    ✓ Database configurée\n";
} catch (Throwable $e) {
    echo "    ✗ ERREUR: " . $e->getMessage() . "\n";
    exit;
}

// Étape 4: Test connexion
echo "\n[4] Test connexion PDO...\n";
try {
    $pdo = Database::pdo();
    echo "    ✓ Connexion OK\n";
} catch (Throwable $e) {
    echo "    ✗ ERREUR: " . $e->getMessage() . "\n";
    exit;
}

// Étape 5: Vérifier les fonctions
echo "\n[5] Vérification des fonctions...\n";
$functions = ['generateId', 'logSecurityEvent', 'getConfig', 'setConfig', 'logActivity'];
foreach ($functions as $func) {
    if (function_exists($func)) {
        echo "    ✓ $func() existe\n";
    } else {
        echo "    ✗ $func() MANQUANTE!\n";
    }
}

// Étape 6: Test des constantes
echo "\n[6] Définition des constantes...\n";
try {
    if (!defined('BASE_DIR')) define('BASE_DIR', $baseDir);
    if (!defined('ROOT_DIR')) define('ROOT_DIR', $rootDir);
    if (!defined('SESSION_DURATION')) define('SESSION_DURATION', $CONFIG['security']['session_duration'] ?? 604800);
    if (!defined('BCRYPT_COST')) define('BCRYPT_COST', $CONFIG['security']['bcrypt_cost'] ?? 12);
    if (!defined('RATE_LIMITING_ENABLED')) define('RATE_LIMITING_ENABLED', false);
    echo "    ✓ Constantes définies\n";
} catch (Throwable $e) {
    echo "    ✗ ERREUR: " . $e->getMessage() . "\n";
}

// Étape 7: Chargement fichiers optionnels
echo "\n[7] Fichiers optionnels...\n";
if (file_exists($baseDir . '/TOTP.php')) {
    require_once $baseDir . '/TOTP.php';
    echo "    ✓ TOTP.php chargé\n";
} else {
    echo "    - TOTP.php absent (optionnel)\n";
}

if (file_exists($baseDir . '/RateLimiter.php')) {
    require_once $baseDir . '/RateLimiter.php';
    echo "    ✓ RateLimiter.php chargé\n";
} else {
    echo "    - RateLimiter.php absent (optionnel)\n";
}

// Étape 8: Test requête dashboard
echo "\n[8] Test requête dashboard/overview...\n";
try {
    $totalUsers = Database::count('users');
    echo "    ✓ Count users: $totalUsers\n";
    
    $totalSites = Database::count('sites');
    echo "    ✓ Count sites: $totalSites\n";
    
    $today = date('Y-m-d');
    $todayUsers = Database::fetchColumn(
        "SELECT COUNT(*) FROM users WHERE DATE(created_at) = ?",
        [$today]
    );
    echo "    ✓ Users today: $todayUsers\n";
    
} catch (Throwable $e) {
    echo "    ✗ ERREUR: " . $e->getMessage() . "\n";
    echo "    Trace: " . $e->getTraceAsString() . "\n";
}

// Étape 9: Simuler le routing
echo "\n[9] Test routing...\n";
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI'] = '/api/dashboard/overview';

$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uri = preg_replace('#^/api\.php#', '', $uri);
$uri = preg_replace('#^/api(?=/|$)#', '', $uri);
$uri = '/' . trim($uri, '/');

echo "    Method: $method\n";
echo "    URI parsed: $uri\n";

// Étape 10: Contenu de api.php (premières lignes)
echo "\n[10] Analyse api.php...\n";
$apiContent = file_get_contents($baseDir . '/api.php');
$lines = explode("\n", $apiContent);
echo "    Nombre de lignes: " . count($lines) . "\n";

// Chercher des erreurs potentielles
if (strpos($apiContent, '<?php') === false) {
    echo "    ✗ ERREUR: Pas de tag <?php trouvé!\n";
}

// Vérifier si le fichier utilise des fonctions non définies
preg_match_all('/function\s+(\w+)\s*\(/', $apiContent, $definedFunctions);
echo "    Fonctions définies dans api.php: " . count($definedFunctions[1]) . "\n";
echo "    Liste: " . implode(', ', array_slice($definedFunctions[1], 0, 10)) . "...\n";

// Étape 11: Test d'inclusion partielle
echo "\n[11] Test d'exécution partielle...\n";
echo "    Tentative d'inclusion de api.php...\n";

// Créer un contexte isolé pour tester
$testCode = '
<?php
error_reporting(E_ALL);
ini_set("display_errors", 1);

// Simuler les superglobales
$_SERVER["REQUEST_METHOD"] = "GET";
$_SERVER["REQUEST_URI"] = "/";
$_SERVER["SCRIPT_NAME"] = "/api.php";

// Output buffering pour capturer
ob_start();

try {
    // Ne pas inclure car ça fait exit()
    // On va juste parser
    echo "OK - Test passé";
} catch (Throwable $e) {
    echo "ERREUR: " . $e->getMessage();
}

$output = ob_get_clean();
echo $output;
';

echo "    (Test d'inclusion désactivé pour éviter exit())\n";

echo "\n=== FIN DES TESTS ===\n";
echo "\n";

// Résumé
echo "RÉSUMÉ:\n";
echo "-------\n";
echo "Si tout est ✓ ci-dessus mais l'API retourne 500,\n";
echo "le problème est probablement dans le parsing du routing\n";
echo "ou une incompatibilité de syntaxe PHP.\n\n";

echo "COMMANDE À EXÉCUTER:\n";
echo "sudo tail -100 /var/log/apache2/error.log\n";
echo "</pre>";

// Bouton pour télécharger les logs
echo '<br><br>';
echo '<a href="/api.php" target="_blank" style="background:#3b82f6;color:white;padding:10px 20px;border-radius:8px;text-decoration:none;">Tester /api.php directement</a>';
echo ' ';
echo '<a href="/" style="background:#27272a;color:white;padding:10px 20px;border-radius:8px;text-decoration:none;border:1px solid #3f3f46;">Retour Dashboard</a>';
