<?php
/**
 * NOTESO - Database Class MySQL 8
 */

class Database {
    private static ?PDO $instance = null;
    private static array $config = [];
    
    public static function configure(array $config): void {
        self::$config = $config;
    }
    
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
            ];
            
            self::$instance = new PDO($dsn, $username, $password, $options);
        }
        
        return self::$instance;
    }
    
    public static function pdo(): PDO {
        return self::getInstance();
    }
    
    public static function query(string $sql, array $params = []): PDOStatement {
        $stmt = self::pdo()->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }
    
    public static function fetch(string $sql, array $params = []): ?array {
        $result = self::query($sql, $params)->fetch();
        return $result ?: null;
    }
    
    public static function fetchAll(string $sql, array $params = []): array {
        return self::query($sql, $params)->fetchAll();
    }
    
    public static function fetchColumn(string $sql, array $params = [], int $column = 0): mixed {
        return self::query($sql, $params)->fetchColumn($column);
    }
    
    public static function insert(string $table, array $data): string|int {
        $columns = implode(', ', array_map(fn($c) => "`{$c}`", array_keys($data)));
        $placeholders = implode(', ', array_fill(0, count($data), '?'));
        
        $sql = "INSERT INTO `{$table}` ({$columns}) VALUES ({$placeholders})";
        self::query($sql, array_values($data));
        
        return $data['id'] ?? self::pdo()->lastInsertId();
    }
    
    public static function update(string $table, array $data, string $where, array $whereParams = []): int {
        $set = implode(', ', array_map(fn($c) => "`{$c}` = ?", array_keys($data)));
        $sql = "UPDATE `{$table}` SET {$set} WHERE {$where}";
        
        return self::query($sql, [...array_values($data), ...$whereParams])->rowCount();
    }
    
    public static function delete(string $table, string $where, array $params = []): int {
        return self::query("DELETE FROM `{$table}` WHERE {$where}", $params)->rowCount();
    }
}
