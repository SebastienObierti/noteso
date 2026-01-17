<?php
/**
 * NOTESO - Script d'initialisation
 * Exécuter une seule fois pour créer l'admin par défaut
 * Supprimer ce fichier après utilisation !
 */

header('Content-Type: text/html; charset=utf-8');

echo "<h1>Noteso - Initialisation</h1>";
echo "<pre>";

// Charger les fichiers
require_once __DIR__ . '/Database.php';

$CONFIG = [];
$configPaths = [
    dirname(__DIR__) . '/config/config.php',
    dirname(__DIR__) . '/config.php',
    __DIR__ . '/config.php',
];

foreach ($configPaths as $configPath) {
    if (file_exists($configPath)) {
        $CONFIG = require $configPath;
        echo "✅ Configuration chargée: $configPath\n";
        break;
    }
}

if (empty($CONFIG)) {
    die("❌ Aucun fichier de configuration trouvé!\n");
}

// Configurer la base de données
try {
    Database::configure([
        'host'     => $CONFIG['database']['host'] ?? 'localhost',
        'port'     => $CONFIG['database']['port'] ?? 3306,
        'database' => $CONFIG['database']['name'] ?? 'noteso',
        'username' => $CONFIG['database']['user'] ?? 'root',
        'password' => $CONFIG['database']['password'] ?? '',
        'charset'  => 'utf8mb4'
    ]);
    
    // Test connexion
    Database::fetchColumn("SELECT 1");
    echo "✅ Connexion MySQL réussie\n";
    
} catch (Exception $e) {
    die("❌ Erreur connexion MySQL: " . $e->getMessage() . "\n");
}

// Vérifier si admin existe déjà
$adminEmail = $CONFIG['admins'][0]['email'] ?? 'contact@obierti.fr';
$existingAdmin = Database::fetch("SELECT id FROM admins WHERE email = ?", [$adminEmail]);

if ($existingAdmin) {
    echo "⚠️ Admin existe déjà: $adminEmail\n";
    echo "\n🔑 Réinitialisation du mot de passe...\n";
    
    $newPassword = $CONFIG['admins'][0]['password'] ?? 'Admin123!';
    $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 12]);
    
    Database::query(
        "UPDATE admins SET password = ?, is_active = 1 WHERE email = ?",
        [$hashedPassword, $adminEmail]
    );
    
    echo "✅ Mot de passe réinitialisé!\n";
    echo "\n📧 Email: $adminEmail\n";
    echo "🔐 Mot de passe: $newPassword\n";
    
} else {
    echo "➕ Création de l'admin...\n";
    
    $adminId = 'admin_' . bin2hex(random_bytes(12));
    $password = $CONFIG['admins'][0]['password'] ?? 'Admin123!';
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    
    Database::insert('admins', [
        'id' => $adminId,
        'email' => $adminEmail,
        'password' => $hashedPassword,
        'first_name' => $CONFIG['admins'][0]['firstName'] ?? 'Admin',
        'last_name' => $CONFIG['admins'][0]['lastName'] ?? 'Principal',
        'role' => 'super_admin',
        'is_active' => 1,
        'created_at' => date('Y-m-d H:i:s')
    ]);
    
    echo "✅ Admin créé avec succès!\n";
    echo "\n📧 Email: $adminEmail\n";
    echo "🔐 Mot de passe: $password\n";
}

// Nettoyer les anciennes sessions
Database::query("DELETE FROM sessions WHERE expires_at < NOW()");
echo "\n🧹 Sessions expirées nettoyées\n";

echo "\n" . str_repeat("=", 50) . "\n";
echo "🎉 INITIALISATION TERMINÉE!\n";
echo str_repeat("=", 50) . "\n";
echo "\n⚠️ SUPPRIMEZ CE FICHIER (init.php) IMMÉDIATEMENT!\n";
echo "\n🔗 Accédez au dashboard: <a href='index.html'>index.html</a>\n";
echo "</pre>";
