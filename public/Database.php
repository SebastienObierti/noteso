<?php
/**
 * NOTESO - Database Class
 * Connexion PDO MySQL 8 avec méthodes CRUD
 */

class Database {
    private static ?PDO $instance = null;
    private static array $config = [];
    
    /**
     * Configuration de la base de données
     */
    public static function configure(array $config): void {
        self::$config = $config;
    }
    
    /**
     * Singleton PDO
     */
    public static function getInstance(): PDO {
        if (self::$instance === null) {
            $host = self::$config['host'] ?? 'localhost';
            $port = self::$config['port'] ?? 3306;
            $dbname = self::$config['database'] ?? 'noteso';
            $username = self::$config['username'] ?? 'root';
            $password = self::$config['password'] ?? '';
            $charset = self::$config['charset'] ?? 'utf8mb4';
            
            $dsn = "mysql:host={$host};port={$port};dbname={$dbname};charset={$charset}";
            
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES {$charset} COLLATE {$charset}_unicode_ci"
            ];
            
            self::$instance = new PDO($dsn, $username, $password, $options);
        }
        
        return self::$instance;
    }
    
    /**
     * Raccourci pour getInstance()
     */
    public static function pdo(): PDO {
        return self::getInstance();
    }
    
    /**
     * Execute une requête préparée
     */
    public static function query(string $sql, array $params = []): PDOStatement {
        $stmt = self::pdo()->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }
    
    /**
     * Récupère une seule ligne
     */
    public static function fetch(string $sql, array $params = []): ?array {
        $result = self::query($sql, $params)->fetch();
        return $result ?: null;
    }
    
    /**
     * Récupère toutes les lignes
     */
    public static function fetchAll(string $sql, array $params = []): array {
        return self::query($sql, $params)->fetchAll();
    }
    
    /**
     * Récupère une valeur scalaire
     */
    public static function fetchColumn(string $sql, array $params = [], int $column = 0): mixed {
        return self::query($sql, $params)->fetchColumn($column);
    }
    
    /**
     * Insert et retourne l'ID
     */
    public static function insert(string $table, array $data): string|int {
        $columns = implode(', ', array_map(fn($c) => "`{$c}`", array_keys($data)));
        $placeholders = implode(', ', array_fill(0, count($data), '?'));
        
        $sql = "INSERT INTO `{$table}` ({$columns}) VALUES ({$placeholders})";
        self::query($sql, array_values($data));
        
        // Retourner l'ID custom si présent, sinon lastInsertId
        return $data['id'] ?? self::pdo()->lastInsertId();
    }
    
    /**
     * Update avec conditions
     */
    public static function update(string $table, array $data, array $where): int {
        $setClauses = implode(', ', array_map(fn($c) => "`{$c}` = ?", array_keys($data)));
        $whereClauses = implode(' AND ', array_map(fn($c) => "`{$c}` = ?", array_keys($where)));
        
        $sql = "UPDATE `{$table}` SET {$setClauses} WHERE {$whereClauses}";
        $params = array_merge(array_values($data), array_values($where));
        
        return self::query($sql, $params)->rowCount();
    }
    
    /**
     * Delete avec conditions
     */
    public static function delete(string $table, array $where): int {
        $whereClauses = implode(' AND ', array_map(fn($c) => "`{$c}` = ?", array_keys($where)));
        $sql = "DELETE FROM `{$table}` WHERE {$whereClauses}";
        
        return self::query($sql, array_values($where))->rowCount();
    }
    
    /**
     * Compte les lignes
     */
    public static function count(string $table, array $where = []): int {
        $sql = "SELECT COUNT(*) FROM `{$table}`";
        $params = [];
        
        if (!empty($where)) {
            $whereClauses = implode(' AND ', array_map(fn($c) => "`{$c}` = ?", array_keys($where)));
            $sql .= " WHERE {$whereClauses}";
            $params = array_values($where);
        }
        
        return (int) self::fetchColumn($sql, $params);
    }
    
    /**
     * Vérifie si une ligne existe
     */
    public static function exists(string $table, array $where): bool {
        return self::count($table, $where) > 0;
    }
    
    /**
     * Récupère une ligne par ID
     */
    public static function find(string $table, string|int $id, string $idColumn = 'id'): ?array {
        return self::fetch("SELECT * FROM `{$table}` WHERE `{$idColumn}` = ?", [$id]);
    }
    
    /**
     * Récupère toutes les lignes d'une table
     */
    public static function all(string $table, ?string $orderBy = null, ?int $limit = null): array {
        $sql = "SELECT * FROM `{$table}`";
        if ($orderBy) $sql .= " ORDER BY {$orderBy}";
        if ($limit) $sql .= " LIMIT {$limit}";
        return self::fetchAll($sql);
    }
    
    /**
     * Transaction helper
     */
    public static function transaction(callable $callback): mixed {
        self::pdo()->beginTransaction();
        try {
            $result = $callback(self::pdo());
            self::pdo()->commit();
            return $result;
        } catch (Exception $e) {
            self::pdo()->rollBack();
            throw $e;
        }
    }
}

// ============================================
// FONCTIONS HELPER SPECIFIQUES NOTESO
// ============================================

/**
 * Génère un ID unique préfixé
 */
function generateId(string $prefix = ''): string {
    $id = base_convert(time(), 10, 36) . bin2hex(random_bytes(4));
    return $prefix ? "{$prefix}_{$id}" : $id;
}

/**
 * Récupère la config depuis la table config
 */
function getConfig(string $key): ?array {
    $row = Database::fetch("SELECT `value` FROM `config` WHERE `key` = ?", [$key]);
    return $row ? json_decode($row['value'], true) : null;
}

/**
 * Met à jour la config
 */
function setConfig(string $key, array $value): void {
    $json = json_encode($value, JSON_UNESCAPED_UNICODE);
    Database::query(
        "INSERT INTO `config` (`key`, `value`, `updated_at`) VALUES (?, ?, NOW())
         ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), `updated_at` = NOW()",
        [$key, $json]
    );
}

/**
 * Log une activité
 */
function logActivity(string $siteId, ?string $userId, string $type, ?string $description = null, ?string $details = null): void {
    Database::insert('activities', [
        'id' => generateId('act'),
        'site_id' => $siteId,
        'user_id' => $userId,
        'type' => $type,
        'description' => $description,
        'metadata' => $details ? json_encode(['details' => $details]) : null,
        'created_at' => date('Y-m-d H:i:s')
    ]);
}

/**
 * Log un événement de sécurité
 */
function logSecurityEvent(string $type, string $details, ?string $adminId = null, ?string $ip = null): void {
    try {
        Database::insert('security_events', [
            'admin_id' => $adminId,
            'event_type' => $type,
            'severity' => 'info',
            'ip_address' => $ip ?? ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown'),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'details' => json_encode(['message' => $details]),
            'created_at' => date('Y-m-d H:i:s')
        ]);
    } catch (Exception $e) {
        // Silently fail - ne pas bloquer l'application si le log échoue
        error_log('Security log failed: ' . $e->getMessage());
    }
}

/**
 * Ajoute une notification
 */
function addNotification(string $type, string $title, string $message, ?string $adminId = null): void {
    Database::insert('notifications', [
        'id' => generateId('notif'),
        'admin_id' => $adminId,
        'type' => $type,
        'title' => $title,
        'message' => $message,
        'is_read' => 0,
        'created_at' => date('Y-m-d H:i:s')
    ]);
}
