-- ============================================
-- PATCH v1.4 - API Publique, PWA, Temps réel
-- ============================================

-- 1. Table pour les clés API publiques
CREATE TABLE IF NOT EXISTS `api_keys` (
    `id` VARCHAR(50) NOT NULL,
    `admin_id` VARCHAR(50) NOT NULL,
    `name` VARCHAR(100) NOT NULL,
    `key_hash` VARCHAR(255) NOT NULL COMMENT 'SHA256 hash de la clé',
    `key_prefix` VARCHAR(10) NOT NULL COMMENT 'Préfixe pour identification (pk_xxx)',
    `permissions` JSON DEFAULT NULL COMMENT 'Liste des permissions',
    `rate_limit` INT UNSIGNED NOT NULL DEFAULT 1000 COMMENT 'Requêtes par heure',
    `allowed_origins` JSON DEFAULT NULL COMMENT 'Domaines autorisés CORS',
    `last_used_at` DATETIME DEFAULT NULL,
    `usage_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
    `is_active` TINYINT(1) NOT NULL DEFAULT 1,
    `expires_at` DATETIME DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_api_keys_prefix` (`key_prefix`),
    KEY `idx_api_keys_admin` (`admin_id`),
    KEY `idx_api_keys_active` (`is_active`),
    CONSTRAINT `fk_api_keys_admin` FOREIGN KEY (`admin_id`) 
        REFERENCES `admins` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Table pour les logs d'API publique
CREATE TABLE IF NOT EXISTS `api_logs` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `api_key_id` VARCHAR(50) DEFAULT NULL,
    `endpoint` VARCHAR(255) NOT NULL,
    `method` VARCHAR(10) NOT NULL,
    `status_code` SMALLINT UNSIGNED NOT NULL,
    `response_time_ms` INT UNSIGNED DEFAULT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `user_agent` VARCHAR(500) DEFAULT NULL,
    `request_body` TEXT DEFAULT NULL,
    `error_message` TEXT DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_api_logs_key` (`api_key_id`),
    KEY `idx_api_logs_created` (`created_at`),
    KEY `idx_api_logs_endpoint` (`endpoint`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Table pour les événements temps réel
CREATE TABLE IF NOT EXISTS `realtime_events` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `site_id` VARCHAR(50) DEFAULT NULL,
    `admin_id` VARCHAR(50) DEFAULT NULL,
    `event_type` VARCHAR(50) NOT NULL COMMENT 'payment, user, subscription, alert',
    `event_data` JSON NOT NULL,
    `is_read` TINYINT(1) NOT NULL DEFAULT 0,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_realtime_site` (`site_id`),
    KEY `idx_realtime_admin` (`admin_id`),
    KEY `idx_realtime_type` (`event_type`),
    KEY `idx_realtime_created` (`created_at`),
    KEY `idx_realtime_unread` (`is_read`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Nettoyage automatique des logs API (garder 30 jours)
CREATE EVENT `cleanup_api_logs`
ON SCHEDULE EVERY 1 DAY
DO DELETE FROM `api_logs` WHERE `created_at` < DATE_SUB(NOW(), INTERVAL 30 DAY);

-- 5. Nettoyage des événements temps réel (garder 7 jours)
CREATE EVENT `cleanup_realtime_events`
ON SCHEDULE EVERY 1 HOUR
DO DELETE FROM `realtime_events` WHERE `created_at` < DATE_SUB(NOW(), INTERVAL 7 DAY);
