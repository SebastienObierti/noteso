-- ============================================
-- PATCH: Mise à jour des tables notification_settings et webhooks_outgoing
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

-- 2. Ajouter les colonnes manquantes à webhooks_outgoing
ALTER TABLE `webhooks_outgoing` 
    ADD COLUMN IF NOT EXISTS `name` VARCHAR(100) NOT NULL DEFAULT 'Webhook' AFTER `id`,
    ADD COLUMN IF NOT EXISTS `success_count` INT UNSIGNED NOT NULL DEFAULT 0 AFTER `failure_count`;

-- Si ALTER avec IF NOT EXISTS ne fonctionne pas (versions MySQL < 8.0.16), utiliser:
-- ALTER TABLE `webhooks_outgoing` ADD COLUMN `name` VARCHAR(100) NOT NULL DEFAULT 'Webhook' AFTER `id`;
-- ALTER TABLE `webhooks_outgoing` ADD COLUMN `success_count` INT UNSIGNED NOT NULL DEFAULT 0 AFTER `failure_count`;

