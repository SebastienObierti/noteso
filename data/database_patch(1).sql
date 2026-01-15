-- ============================================
-- PATCH: Mise à jour des tables
-- Exécuter ce script pour mettre à jour la base existante
-- ============================================

-- 1. Supprimer et recréer notification_settings
DROP TABLE IF EXISTS `notification_settings`;

CREATE TABLE `notification_settings` (
    `id` VARCHAR(50) NOT NULL,
    `admin_id` VARCHAR(50) NOT NULL,
    `email_enabled` TINYINT(1) NOT NULL DEFAULT 0,
    `email_address` VARCHAR(255) DEFAULT NULL,
    `slack_enabled` TINYINT(1) NOT NULL DEFAULT 0,
    `slack_webhook_url` VARCHAR(500) DEFAULT NULL,
    `discord_enabled` TINYINT(1) NOT NULL DEFAULT 0,
    `discord_webhook_url` VARCHAR(500) DEFAULT NULL,
    `report_daily` TINYINT(1) NOT NULL DEFAULT 0,
    `report_weekly` TINYINT(1) NOT NULL DEFAULT 1,
    `report_monthly` TINYINT(1) NOT NULL DEFAULT 1,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_notification_settings_admin` (`admin_id`),
    CONSTRAINT `fk_notification_settings_admin` FOREIGN KEY (`admin_id`) 
        REFERENCES `admins` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Créer la table reports si elle n'existe pas
CREATE TABLE IF NOT EXISTS `reports` (
    `id` VARCHAR(50) NOT NULL,
    `type` VARCHAR(20) NOT NULL DEFAULT 'monthly' COMMENT 'daily, weekly, monthly',
    `site_id` VARCHAR(50) DEFAULT NULL COMMENT 'NULL = tous les sites',
    `period` JSON NOT NULL COMMENT 'start, end dates',
    `data` JSON NOT NULL COMMENT 'données du rapport',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_reports_type` (`type`),
    KEY `idx_reports_site` (`site_id`),
    KEY `idx_reports_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Créer la table password_resets si elle n'existe pas
CREATE TABLE IF NOT EXISTS `password_resets` (
    `id` VARCHAR(50) NOT NULL,
    `admin_id` VARCHAR(50) NOT NULL,
    `email` VARCHAR(255) NOT NULL,
    `token` VARCHAR(64) NOT NULL,
    `used` TINYINT(1) NOT NULL DEFAULT 0,
    `used_at` DATETIME DEFAULT NULL,
    `expires_at` DATETIME NOT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_password_resets_token` (`token`),
    KEY `idx_password_resets_admin` (`admin_id`),
    KEY `idx_password_resets_expires` (`expires_at`),
    CONSTRAINT `fk_password_resets_admin` FOREIGN KEY (`admin_id`) 
        REFERENCES `admins` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

