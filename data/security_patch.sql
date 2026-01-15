-- ============================================
-- PATCH SÉCURITÉ v1.1
-- Tables pour 2FA, Rate Limiting, Webhooks sécurisés
-- ============================================

-- 1. Ajouter colonnes 2FA à la table admins
ALTER TABLE `admins` 
    ADD COLUMN    `two_factor_secret` VARCHAR(32) DEFAULT NULL AFTER `password`,
    ADD COLUMN    `two_factor_enabled` TINYINT(1) NOT NULL DEFAULT 0 AFTER `two_factor_secret`,
    ADD COLUMN    `two_factor_verified_at` DATETIME DEFAULT NULL AFTER `two_factor_enabled`,
    ADD COLUMN   `backup_codes` JSON DEFAULT NULL AFTER `two_factor_verified_at`;

-- 2. Table pour le rate limiting
CREATE TABLE IF NOT EXISTS `rate_limits` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `key` VARCHAR(255) NOT NULL COMMENT 'IP, token, ou combinaison',
    `endpoint` VARCHAR(100) DEFAULT NULL COMMENT 'Route spécifique ou NULL pour global',
    `hits` INT UNSIGNED NOT NULL DEFAULT 1,
    `window_start` DATETIME NOT NULL,
    `blocked_until` DATETIME DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_rate_limits_key_endpoint` (`key`, `endpoint`),
    KEY `idx_rate_limits_window` (`window_start`),
    KEY `idx_rate_limits_blocked` (`blocked_until`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Améliorer la table sessions pour gestion multi-appareils
ALTER TABLE `sessions`
    ADD COLUMN   `device_name` VARCHAR(100) DEFAULT NULL AFTER `user_agent`,
    ADD COLUMN   `device_type` ENUM('desktop', 'mobile', 'tablet', 'unknown') DEFAULT 'unknown' AFTER `device_name`,
    ADD COLUMN   `location` VARCHAR(100) DEFAULT NULL AFTER `device_type`,
    ADD COLUMN   `last_activity_at` DATETIME DEFAULT NULL AFTER `location`,
    ADD COLUMN   `is_current` TINYINT(1) NOT NULL DEFAULT 0 AFTER `last_activity_at`;

-- 4. Table pour les logs de sécurité détaillés
CREATE TABLE IF NOT EXISTS `security_events` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `admin_id` VARCHAR(50) DEFAULT NULL,
    `event_type` VARCHAR(50) NOT NULL COMMENT 'login, logout, 2fa_enabled, password_change, etc.',
    `severity` ENUM('info', 'warning', 'critical') NOT NULL DEFAULT 'info',
    `ip_address` VARCHAR(45) NOT NULL,
    `user_agent` TEXT DEFAULT NULL,
    `location` VARCHAR(100) DEFAULT NULL,
    `details` JSON DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_security_events_admin` (`admin_id`),
    KEY `idx_security_events_type` (`event_type`),
    KEY `idx_security_events_severity` (`severity`),
    KEY `idx_security_events_created` (`created_at`),
    KEY `idx_security_events_ip` (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Table pour la file d'attente des webhooks
CREATE TABLE IF NOT EXISTS `webhook_queue` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `site_id` VARCHAR(50) NOT NULL,
    `event_type` VARCHAR(50) NOT NULL,
    `payload` JSON NOT NULL,
    `signature` VARCHAR(64) DEFAULT NULL,
    `status` ENUM('pending', 'processing', 'completed', 'failed') NOT NULL DEFAULT 'pending',
    `attempts` TINYINT UNSIGNED NOT NULL DEFAULT 0,
    `max_attempts` TINYINT UNSIGNED NOT NULL DEFAULT 3,
    `error_message` TEXT DEFAULT NULL,
    `processed_at` DATETIME DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_webhook_queue_site` (`site_id`),
    KEY `idx_webhook_queue_status` (`status`),
    KEY `idx_webhook_queue_created` (`created_at`),
    CONSTRAINT `fk_webhook_queue_site` FOREIGN KEY (`site_id`) 
        REFERENCES `sites` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Ajouter colonne webhook_secret aux sites
ALTER TABLE `sites`
    ADD COLUMN   `webhook_secret` VARCHAR(64) DEFAULT NULL AFTER `api_key`;

-- Générer des secrets pour les sites existants
UPDATE `sites` SET `webhook_secret` = SUBSTRING(SHA2(CONCAT(id, api_key, RAND()), 256), 1, 32) WHERE `webhook_secret` IS NULL;

-- 7. Index pour nettoyage automatique
CREATE EVENT   `cleanup_rate_limits`
ON SCHEDULE EVERY 1 HOUR
DO DELETE FROM `rate_limits` WHERE `window_start` < DATE_SUB(NOW(), INTERVAL 1 HOUR);

CREATE EVENT   `cleanup_security_events`
ON SCHEDULE EVERY 1 DAY
DO DELETE FROM `security_events` WHERE `created_at` < DATE_SUB(NOW(), INTERVAL 90 DAY);

-- Activer le scheduler si pas déjà fait
SET GLOBAL event_scheduler = ON;
