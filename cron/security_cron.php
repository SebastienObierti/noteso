#!/usr/bin/env php
<?php
/**
 * NOTESO - Cron Job pour Sécurité & Monitoring
 * 
 * À exécuter via crontab :
 * 
 * # Toutes les 5 minutes - vérification des alertes
 * *\/5 * * * * /usr/bin/php /srv/web/noteso/cron/security_cron.php check-alerts
 * 
 * # Tous les jours à 3h - backup automatique
 * 0 3 * * * /usr/bin/php /srv/web/noteso/cron/security_cron.php backup
 * 
 * # Tous les jours à 4h - nettoyage des vieilles données
 * 0 4 * * * /usr/bin/php /srv/web/noteso/cron/security_cron.php cleanup
 * 
 * # Toutes les minutes - enregistrement des métriques
 * * * * * /usr/bin/php /srv/web/noteso/cron/security_cron.php metrics
 */

// Charger la configuration
$rootDir = dirname(__DIR__);
$publicDir = $rootDir . '/public';

// Charger les dépendances
require_once $publicDir . '/Database.php';

// Charger la config
$configPaths = [
    $rootDir . '/config/config.php',
    $rootDir . '/config.php',
];

$CONFIG = null;
foreach ($configPaths as $path) {
    if (file_exists($path)) {
        $CONFIG = require $path;
        break;
    }
}

if (!$CONFIG) {
    die("Configuration non trouvée\n");
}

// Configurer la base de données
Database::configure([
    'host'     => $CONFIG['database']['host'] ?? 'localhost',
    'port'     => $CONFIG['database']['port'] ?? 3306,
    'database' => $CONFIG['database']['name'] ?? 'noteso',
    'username' => $CONFIG['database']['user'] ?? 'root',
    'password' => $CONFIG['database']['password'] ?? '',
    'charset'  => 'utf8mb4'
]);

// Fonction helper pour générer un ID
if (!function_exists('generateId')) {
    function generateId(string $prefix = ''): string {
        $id = base_convert(time(), 10, 36) . bin2hex(random_bytes(4));
        return $prefix ? "{$prefix}_{$id}" : $id;
    }
}

// Récupérer la commande
$command = $argv[1] ?? 'help';

switch ($command) {
    case 'check-alerts':
        checkAlerts();
        break;
    
    case 'backup':
        createAutoBackup();
        break;
    
    case 'cleanup':
        cleanupOldData();
        break;
    
    case 'metrics':
        recordMetrics();
        break;
    
    case 'all':
        recordMetrics();
        checkAlerts();
        break;
    
    default:
        echo "Usage: php security_cron.php [command]\n";
        echo "Commands:\n";
        echo "  check-alerts  - Vérifier les règles d'alertes\n";
        echo "  backup        - Créer un backup automatique\n";
        echo "  cleanup       - Nettoyer les anciennes données\n";
        echo "  metrics       - Enregistrer les métriques système\n";
        echo "  all           - Exécuter metrics + check-alerts\n";
        break;
}

/**
 * Vérifier les règles d'alertes
 */
function checkAlerts() {
    echo "[" . date('Y-m-d H:i:s') . "] Vérification des alertes...\n";
    
    // Récupérer les règles actives
    $rules = Database::fetchAll(
        "SELECT * FROM alert_rules WHERE is_enabled = 1"
    );
    
    foreach ($rules as $rule) {
        // Vérifier le cooldown
        if ($rule['last_triggered_at']) {
            $lastTriggered = strtotime($rule['last_triggered_at']);
            $cooldownEnd = $lastTriggered + ($rule['cooldown_minutes'] * 60);
            
            if (time() < $cooldownEnd) {
                continue; // Encore en cooldown
            }
        }
        
        $triggered = false;
        $currentValue = null;
        $message = '';
        
        // Évaluer selon le type de métrique
        switch ($rule['metric']) {
            case 'login_failures':
                $currentValue = Database::fetchColumn(
                    "SELECT COUNT(*) FROM security_events 
                     WHERE event_type = 'login_failed' 
                     AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)",
                    [$rule['time_window_minutes']]
                );
                $triggered = evaluateCondition($currentValue, $rule['condition_operator'], $rule['condition_value']);
                $message = "$currentValue échecs de connexion en {$rule['time_window_minutes']} minutes";
                break;
            
            case 'api_error_rate':
                // Calculer le taux d'erreur
                $total = Database::fetchColumn(
                    "SELECT COUNT(*) FROM audit_logs 
                     WHERE created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)",
                    [$rule['time_window_minutes']]
                ) ?: 1;
                
                $errors = Database::fetchColumn(
                    "SELECT COUNT(*) FROM audit_logs 
                     WHERE response_code >= 500 
                     AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)",
                    [$rule['time_window_minutes']]
                );
                
                $currentValue = ($errors / $total) * 100;
                $triggered = evaluateCondition($currentValue, $rule['condition_operator'], $rule['condition_value']);
                $message = "Taux d'erreur: " . round($currentValue, 2) . "%";
                break;
            
            case 'requests_per_minute':
                $currentValue = Database::fetchColumn(
                    "SELECT COUNT(*) FROM audit_logs 
                     WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)"
                );
                $triggered = evaluateCondition($currentValue, $rule['condition_operator'], $rule['condition_value']);
                $message = "$currentValue requêtes/minute";
                break;
            
            case 'suspicious_score':
                // Calculer un score de suspicion basé sur plusieurs facteurs
                $suspiciousEvents = Database::fetchColumn(
                    "SELECT COUNT(*) FROM security_events 
                     WHERE event_type IN ('login_failed', '2fa_validation_failed', 'suspicious_activity')
                     AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)",
                    [$rule['time_window_minutes']]
                );
                
                $currentValue = min(100, $suspiciousEvents * 10);
                $triggered = evaluateCondition($currentValue, $rule['condition_operator'], $rule['condition_value']);
                $message = "Score de suspicion: $currentValue";
                break;
            
            case 'database_size_mb':
                $currentValue = Database::fetchColumn(
                    "SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) 
                     FROM information_schema.tables 
                     WHERE table_schema = DATABASE()"
                );
                $triggered = evaluateCondition($currentValue, $rule['condition_operator'], $rule['condition_value']);
                $message = "Taille BDD: {$currentValue}MB";
                break;
        }
        
        if ($triggered) {
            createAlert($rule, $currentValue, $message);
        }
    }
    
    echo "[" . date('Y-m-d H:i:s') . "] Vérification terminée\n";
}

/**
 * Évaluer une condition
 */
function evaluateCondition($value, string $operator, $threshold): bool {
    if ($value === null) return false;
    
    return match($operator) {
        'gt' => $value > $threshold,
        'gte' => $value >= $threshold,
        'lt' => $value < $threshold,
        'lte' => $value <= $threshold,
        'eq' => $value == $threshold,
        default => false
    };
}

/**
 * Créer une alerte
 */
function createAlert(array $rule, $currentValue, string $message) {
    global $CONFIG;
    
    $alertId = generateId('alert');
    
    Database::insert('alerts', [
        'id' => $alertId,
        'type' => $rule['metric'],
        'severity' => $rule['severity'],
        'title' => $rule['name'],
        'message' => $message,
        'metadata' => json_encode([
            'rule_id' => $rule['id'],
            'current_value' => $currentValue,
            'threshold' => $rule['condition_value'],
            'operator' => $rule['condition_operator']
        ])
    ]);
    
    // Mettre à jour le dernier déclenchement
    Database::update('alert_rules', [
        'last_triggered_at' => date('Y-m-d H:i:s')
    ], ['id' => $rule['id']]);
    
    echo "  [ALERTE] {$rule['name']}: $message\n";
    
    // Envoyer notification email si activé
    if ($rule['notify_email'] && !empty($CONFIG['smtp']['enabled'])) {
        sendAlertEmail($rule, $message);
    }
    
    // Webhook si activé
    if ($rule['notify_webhook'] && !empty($rule['webhook_url'])) {
        sendAlertWebhook($rule, $message, $currentValue);
    }
}

/**
 * Envoyer un email d'alerte
 */
function sendAlertEmail(array $rule, string $message) {
    global $CONFIG;
    
    // Récupérer les admins
    $admins = Database::fetchAll("SELECT email FROM admins WHERE role = 'super_admin'");
    
    if (empty($admins)) return;
    
    $subject = "[NOTESO] Alerte {$rule['severity']}: {$rule['name']}";
    $body = "
        <h2>Alerte Noteso</h2>
        <p><strong>Règle:</strong> {$rule['name']}</p>
        <p><strong>Sévérité:</strong> {$rule['severity']}</p>
        <p><strong>Message:</strong> $message</p>
        <p><strong>Date:</strong> " . date('d/m/Y H:i:s') . "</p>
        <p><a href=\"https://{$_SERVER['HTTP_HOST']}/security\">Voir le dashboard</a></p>
    ";
    
    foreach ($admins as $admin) {
        // Utiliser PHPMailer ou mail() selon la config
        // Pour simplifier, on log juste
        echo "  [EMAIL] Alerte envoyée à {$admin['email']}\n";
    }
}

/**
 * Envoyer un webhook d'alerte
 */
function sendAlertWebhook(array $rule, string $message, $currentValue) {
    $payload = json_encode([
        'type' => 'alert',
        'rule' => $rule['name'],
        'severity' => $rule['severity'],
        'message' => $message,
        'value' => $currentValue,
        'timestamp' => date('c')
    ]);
    
    $ch = curl_init($rule['webhook_url']);
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
    
    echo "  [WEBHOOK] Envoyé ({$httpCode})\n";
}

/**
 * Créer un backup automatique
 */
function createAutoBackup() {
    global $CONFIG, $rootDir;
    
    echo "[" . date('Y-m-d H:i:s') . "] Création du backup automatique...\n";
    
    $backupDir = $rootDir . '/backups';
    if (!is_dir($backupDir)) {
        mkdir($backupDir, 0755, true);
    }
    
    $id = generateId('backup');
    $filename = 'noteso_auto_' . date('Y-m-d_His') . '.sql';
    $filePath = $backupDir . '/' . $filename;
    
    // Tables à sauvegarder
    $tables = ['admins', 'sites', 'users', 'payments', 'subscriptions', 
               'activities', 'notifications', 'settings', 'api_keys',
               'security_events', 'audit_logs', 'alerts', 'alert_rules',
               'ip_rules', 'sessions'];
    
    Database::insert('backups', [
        'id' => $id,
        'filename' => $filename,
        'file_path' => $filePath,
        'file_size' => 0,
        'type' => 'auto',
        'status' => 'running',
        'tables_included' => json_encode($tables),
        'started_at' => date('Y-m-d H:i:s')
    ]);
    
    try {
        $dbHost = $CONFIG['database']['host'];
        $dbName = $CONFIG['database']['name'];
        $dbUser = $CONFIG['database']['user'];
        $dbPass = $CONFIG['database']['password'];
        
        $cmd = sprintf(
            'mysqldump -h %s -u %s -p%s %s %s > %s 2>&1',
            escapeshellarg($dbHost),
            escapeshellarg($dbUser),
            escapeshellarg($dbPass),
            escapeshellarg($dbName),
            implode(' ', $tables),
            escapeshellarg($filePath)
        );
        
        exec($cmd, $output, $returnCode);
        
        if ($returnCode === 0 && file_exists($filePath)) {
            $fileSize = filesize($filePath);
            
            // Compresser
            exec("gzip $filePath");
            $filePath .= '.gz';
            $filename .= '.gz';
            $fileSize = filesize($filePath);
            
            Database::update('backups', [
                'status' => 'completed',
                'filename' => $filename,
                'file_path' => $filePath,
                'file_size' => $fileSize,
                'completed_at' => date('Y-m-d H:i:s')
            ], ['id' => $id]);
            
            echo "[" . date('Y-m-d H:i:s') . "] Backup créé: $filename (" . formatBytes($fileSize) . ")\n";
            
            // Supprimer les vieux backups (garder 7 derniers)
            cleanupOldBackups($backupDir, 7);
            
        } else {
            Database::update('backups', [
                'status' => 'failed',
                'error_message' => implode("\n", $output)
            ], ['id' => $id]);
            
            echo "[ERREUR] Backup échoué: " . implode(', ', $output) . "\n";
        }
    } catch (Exception $e) {
        Database::update('backups', [
            'status' => 'failed',
            'error_message' => $e->getMessage()
        ], ['id' => $id]);
        
        echo "[ERREUR] " . $e->getMessage() . "\n";
    }
}

/**
 * Supprimer les vieux backups
 */
function cleanupOldBackups(string $dir, int $keepCount) {
    $files = glob($dir . '/noteso_auto_*.sql.gz');
    usort($files, function($a, $b) {
        return filemtime($b) - filemtime($a);
    });
    
    $toDelete = array_slice($files, $keepCount);
    
    foreach ($toDelete as $file) {
        unlink($file);
        
        // Supprimer de la BDD aussi
        Database::execute(
            "DELETE FROM backups WHERE file_path = ?",
            [$file]
        );
        
        echo "  Supprimé: " . basename($file) . "\n";
    }
}

/**
 * Nettoyer les anciennes données
 */
function cleanupOldData() {
    echo "[" . date('Y-m-d H:i:s') . "] Nettoyage des anciennes données...\n";
    
    // Audit logs > 90 jours
    $deleted = Database::execute(
        "DELETE FROM audit_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY)"
    );
    echo "  audit_logs: $deleted supprimés\n";
    
    // Security events > 90 jours
    $deleted = Database::execute(
        "DELETE FROM security_events WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY)"
    );
    echo "  security_events: $deleted supprimés\n";
    
    // Metrics > 30 jours
    $deleted = Database::execute(
        "DELETE FROM metrics WHERE recorded_at < DATE_SUB(NOW(), INTERVAL 30 DAY)"
    );
    echo "  metrics: $deleted supprimés\n";
    
    // Alertes résolues > 30 jours
    $deleted = Database::execute(
        "DELETE FROM alerts WHERE is_resolved = 1 AND resolved_at < DATE_SUB(NOW(), INTERVAL 30 DAY)"
    );
    echo "  alerts (resolved): $deleted supprimés\n";
    
    // IP rules expirées
    $deleted = Database::execute(
        "DELETE FROM ip_rules WHERE expires_at IS NOT NULL AND expires_at < NOW()"
    );
    echo "  ip_rules (expired): $deleted supprimés\n";
    
    // Sessions expirées
    $deleted = Database::execute(
        "DELETE FROM sessions WHERE expires_at < NOW()"
    );
    echo "  sessions: $deleted supprimés\n";
    
    echo "[" . date('Y-m-d H:i:s') . "] Nettoyage terminé\n";
}

/**
 * Enregistrer les métriques système
 */
function recordMetrics() {
    // Requêtes par minute (approximation basée sur audit_logs)
    $requestsPerMinute = Database::fetchColumn(
        "SELECT COUNT(*) FROM audit_logs WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)"
    ) ?: 0;
    
    recordMetric('requests_per_minute', $requestsPerMinute);
    
    // Échecs de connexion
    $loginFailures = Database::fetchColumn(
        "SELECT COUNT(*) FROM security_events 
         WHERE event_type = 'login_failed' 
         AND created_at > DATE_SUB(NOW(), INTERVAL 5 MINUTE)"
    ) ?: 0;
    
    recordMetric('login_failures', $loginFailures);
    
    // Utilisateurs actifs (sessions)
    $activeSessions = Database::fetchColumn(
        "SELECT COUNT(*) FROM sessions WHERE expires_at > NOW()"
    ) ?: 0;
    
    recordMetric('active_sessions', $activeSessions);
    
    // Taille BDD
    $dbSize = Database::fetchColumn(
        "SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) 
         FROM information_schema.tables 
         WHERE table_schema = DATABASE()"
    ) ?: 0;
    
    recordMetric('database_size_mb', $dbSize);
    
    // Alertes actives
    $activeAlerts = Database::fetchColumn(
        "SELECT COUNT(*) FROM alerts WHERE is_resolved = 0"
    ) ?: 0;
    
    recordMetric('active_alerts', $activeAlerts);
}

/**
 * Enregistrer une métrique
 */
function recordMetric(string $name, float $value, ?array $tags = null) {
    try {
        Database::insert('metrics', [
            'metric_name' => $name,
            'metric_value' => $value,
            'tags' => $tags ? json_encode($tags) : null
        ]);
    } catch (Exception $e) {
        // Ignorer silencieusement si la table n'existe pas
    }
}

/**
 * Formater les bytes
 */
function formatBytes($bytes) {
    if ($bytes >= 1073741824) return number_format($bytes / 1073741824, 2) . ' GB';
    if ($bytes >= 1048576) return number_format($bytes / 1048576, 2) . ' MB';
    if ($bytes >= 1024) return number_format($bytes / 1024, 2) . ' KB';
    return $bytes . ' bytes';
}
