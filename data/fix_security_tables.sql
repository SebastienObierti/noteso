-- ============================================
-- PATCH: Correction tables sécurité
-- Exécuter si erreur "Data truncated for column 'type'"
-- ============================================

-- Supprimer l'ancienne table security_logs si elle existe
DROP TABLE IF EXISTS `security_logs`;

-- Recréer security_events avec la bonne structure
DROP TABLE IF EXISTS `security_events`;

CREATE TABLE `security_events` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `admin_id` VARCHAR(50) DEFAULT NULL,
    `event_type` VARCHAR(50) NOT NULL COMMENT 'login, logout, 2fa_enabled, etc.',
    `severity` ENUM('info', 'warning', 'critical') NOT NULL DEFAULT 'info',
    `ip_address` VARCHAR(45) NOT NULL DEFAULT 'unknown',
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

-- Vérifier que la table sessions a les bonnes colonnes
ALTER TABLE `sessions`
    ADD COLUMN   `device_name` VARCHAR(100) DEFAULT NULL,
    ADD COLUMN   `device_type` VARCHAR(20) DEFAULT 'unknown',
    ADD COLUMN   `location` VARCHAR(100) DEFAULT NULL,
    ADD COLUMN   `last_activity_at` DATETIME DEFAULT NULL,
    ADD COLUMN   `is_current` TINYINT(1) NOT NULL DEFAULT 0;
