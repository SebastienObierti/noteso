-- ============================================
-- NOTESO - Schéma MySQL 8
-- ============================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- Base de données
CREATE DATABASE IF NOT EXISTS `noteso` 
    CHARACTER SET utf8mb4 
    COLLATE utf8mb4_unicode_ci;

USE `noteso`;

-- ============================================
-- TABLE: admins (administrateurs)
-- ============================================
CREATE TABLE `admins` (
    `id` VARCHAR(50) NOT NULL,
    `email` VARCHAR(255) NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `first_name` VARCHAR(100) NOT NULL,
    `last_name` VARCHAR(100) NOT NULL,
    `role` ENUM('super_admin', 'admin', 'editor', 'viewer') NOT NULL DEFAULT 'admin',
    `permissions` JSON DEFAULT NULL COMMENT 'Array de permissions',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `last_login_at` DATETIME DEFAULT NULL,
    `last_login_ip` VARCHAR(45) DEFAULT NULL,
    `password_changed_at` DATETIME DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_admins_email` (`email`),
    KEY `idx_admins_role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLE: sessions (sessions actives)
-- ============================================
CREATE TABLE `sessions` (
    `id` VARCHAR(50) NOT NULL,
    `admin_id` VARCHAR(50) NOT NULL,
    `token` VARCHAR(64) NOT NULL,
    `ip` VARCHAR(45) NOT NULL,
    `user_agent` TEXT,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `expires_at` DATETIME NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_sessions_token` (`token`),
    KEY `idx_sessions_admin_id` (`admin_id`),
    KEY `idx_sessions_expires_at` (`expires_at`),
    CONSTRAINT `fk_sessions_admin` FOREIGN KEY (`admin_id`) 
        REFERENCES `admins` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLE: sites (sites/applications monitorés)
-- ============================================
CREATE TABLE `sites` (
    `id` VARCHAR(50) NOT NULL,
    `name` VARCHAR(100) NOT NULL,
    `url` VARCHAR(500) NOT NULL,
    `status` ENUM('online', 'offline', 'maintenance', 'error') NOT NULL DEFAULT 'online',
    `color` VARCHAR(7) DEFAULT '#3b82f6' COMMENT 'Couleur hex',
    `api_key` VARCHAR(50) NOT NULL,
    `settings` JSON DEFAULT NULL COMMENT 'currency, timezone, etc.',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_sites_api_key` (`api_key`),
    KEY `idx_sites_status` (`status`),
    KEY `idx_sites_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLE: users (utilisateurs des sites clients)
-- ============================================
CREATE TABLE `users` (
    `id` VARCHAR(50) NOT NULL,
    `site_id` VARCHAR(50) NOT NULL,
    `external_id` VARCHAR(100) DEFAULT NULL COMMENT 'ID dans le système client',
    `email` VARCHAR(255) DEFAULT NULL,
    `name` VARCHAR(200) DEFAULT NULL,
    `metadata` JSON DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_users_site_id` (`site_id`),
    KEY `idx_users_email` (`email`),
    KEY `idx_users_external_id` (`site_id`, `external_id`),
    CONSTRAINT `fk_users_site` FOREIGN KEY (`site_id`) 
        REFERENCES `sites` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLE: subscriptions (abonnements)
-- ============================================
CREATE TABLE `subscriptions` (
    `id` VARCHAR(50) NOT NULL,
    `site_id` VARCHAR(50) NOT NULL,
    `user_id` VARCHAR(50) DEFAULT NULL,
    `plan` VARCHAR(50) NOT NULL,
    `status` ENUM('active', 'cancelled', 'expired', 'trial', 'past_due') NOT NULL DEFAULT 'active',
    `amount` DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    `currency` VARCHAR(3) NOT NULL DEFAULT 'EUR',
    `interval_type` ENUM('day', 'week', 'month', 'year') NOT NULL DEFAULT 'month',
    `interval_count` TINYINT UNSIGNED NOT NULL DEFAULT 1,
    `trial_ends_at` DATETIME DEFAULT NULL,
    `current_period_start` DATETIME DEFAULT NULL,
    `current_period_end` DATETIME DEFAULT NULL,
    `cancelled_at` DATETIME DEFAULT NULL,
    `metadata` JSON DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_subscriptions_site_id` (`site_id`),
    KEY `idx_subscriptions_user_id` (`user_id`),
    KEY `idx_subscriptions_status` (`status`),
    KEY `idx_subscriptions_plan` (`plan`),
    CONSTRAINT `fk_subscriptions_site` FOREIGN KEY (`site_id`) 
        REFERENCES `sites` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT `fk_subscriptions_user` FOREIGN KEY (`user_id`) 
        REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLE: payments (paiements)
-- ============================================
CREATE TABLE `payments` (
    `id` VARCHAR(50) NOT NULL,
    `site_id` VARCHAR(50) NOT NULL,
    `user_id` VARCHAR(50) DEFAULT NULL,
    `subscription_id` VARCHAR(50) DEFAULT NULL,
    `amount` DECIMAL(10,2) NOT NULL,
    `currency` VARCHAR(3) NOT NULL DEFAULT 'EUR',
    `status` ENUM('pending', 'completed', 'failed', 'refunded', 'cancelled') NOT NULL DEFAULT 'pending',
    `payment_method` VARCHAR(50) DEFAULT NULL COMMENT 'stripe, paypal, etc.',
    `external_id` VARCHAR(100) DEFAULT NULL COMMENT 'ID chez le provider',
    `metadata` JSON DEFAULT NULL,
    `paid_at` DATETIME DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_payments_site_id` (`site_id`),
    KEY `idx_payments_user_id` (`user_id`),
    KEY `idx_payments_subscription_id` (`subscription_id`),
    KEY `idx_payments_status` (`status`),
    KEY `idx_payments_paid_at` (`paid_at`),
    CONSTRAINT `fk_payments_site` FOREIGN KEY (`site_id`) 
        REFERENCES `sites` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT `fk_payments_user` FOREIGN KEY (`user_id`) 
        REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT `fk_payments_subscription` FOREIGN KEY (`subscription_id`) 
        REFERENCES `subscriptions` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLE: activities (activités/événements)
-- ============================================
CREATE TABLE `activities` (
    `id` VARCHAR(50) NOT NULL,
    `site_id` VARCHAR(50) NOT NULL,
    `user_id` VARCHAR(50) DEFAULT NULL,
    `type` VARCHAR(50) NOT NULL COMMENT 'signup, payment, login, etc.',
    `description` TEXT,
    `metadata` JSON DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_activities_site_id` (`site_id`),
    KEY `idx_activities_user_id` (`user_id`),
    KEY `idx_activities_type` (`type`),
    KEY `idx_activities_created_at` (`created_at`),
    CONSTRAINT `fk_activities_site` FOREIGN KEY (`site_id`) 
        REFERENCES `sites` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT `fk_activities_user` FOREIGN KEY (`user_id`) 
        REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLE: notifications (notifications admin)
-- ============================================
CREATE TABLE `notifications` (
    `id` VARCHAR(50) NOT NULL,
    `admin_id` VARCHAR(50) DEFAULT NULL COMMENT 'NULL = tous les admins',
    `type` ENUM('info', 'success', 'warning', 'error') NOT NULL DEFAULT 'info',
    `title` VARCHAR(200) NOT NULL,
    `message` TEXT,
    `is_read` TINYINT(1) NOT NULL DEFAULT 0,
    `read_at` DATETIME DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_notifications_admin_id` (`admin_id`),
    KEY `idx_notifications_is_read` (`is_read`),
    KEY `idx_notifications_created_at` (`created_at`),
    CONSTRAINT `fk_notifications_admin` FOREIGN KEY (`admin_id`) 
        REFERENCES `admins` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLE: security_logs (logs de sécurité)
-- ============================================
CREATE TABLE `security_logs` (
    `id` VARCHAR(50) NOT NULL,
    `admin_id` VARCHAR(50) DEFAULT NULL,
    `type` ENUM('login_success', 'login_failed', 'logout', 'password_change', 'permission_change', 'api_access') NOT NULL,
    `details` TEXT,
    `ip` VARCHAR(45) NOT NULL,
    `user_agent` TEXT,
    `timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_security_logs_admin_id` (`admin_id`),
    KEY `idx_security_logs_type` (`type`),
    KEY `idx_security_logs_ip` (`ip`),
    KEY `idx_security_logs_timestamp` (`timestamp`),
    CONSTRAINT `fk_security_logs_admin` FOREIGN KEY (`admin_id`) 
        REFERENCES `admins` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLE: login_attempts (tentatives de connexion)
-- ============================================
CREATE TABLE `login_attempts` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `email` VARCHAR(255) NOT NULL,
    `ip` VARCHAR(45) NOT NULL,
    `success` TINYINT(1) NOT NULL DEFAULT 0,
    `user_agent` TEXT,
    `attempted_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_login_attempts_email` (`email`),
    KEY `idx_login_attempts_ip` (`ip`),
    KEY `idx_login_attempts_attempted_at` (`attempted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLE: widgets (configuration dashboard)
-- ============================================
CREATE TABLE `widgets` (
    `id` VARCHAR(50) NOT NULL,
    `admin_id` VARCHAR(50) DEFAULT NULL COMMENT 'NULL = global',
    `type` VARCHAR(50) NOT NULL COMMENT 'stats, chart, sites, activity, breakdown',
    `title` VARCHAR(100) NOT NULL,
    `position_x` TINYINT UNSIGNED NOT NULL DEFAULT 0,
    `position_y` TINYINT UNSIGNED NOT NULL DEFAULT 0,
    `width` TINYINT UNSIGNED NOT NULL DEFAULT 1,
    `height` TINYINT UNSIGNED NOT NULL DEFAULT 1,
    `is_visible` TINYINT(1) NOT NULL DEFAULT 1,
    `config` JSON DEFAULT NULL COMMENT 'Configuration spécifique au widget',
    PRIMARY KEY (`id`),
    KEY `idx_widgets_admin_id` (`admin_id`),
    KEY `idx_widgets_type` (`type`),
    CONSTRAINT `fk_widgets_admin` FOREIGN KEY (`admin_id`) 
        REFERENCES `admins` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLE: config (configuration application)
-- ============================================
CREATE TABLE `config` (
    `key` VARCHAR(100) NOT NULL,
    `value` JSON NOT NULL,
    `updated_at` DATETIME DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLE: settings (paramètres par admin)
-- ============================================
CREATE TABLE `settings` (
    `admin_id` VARCHAR(50) NOT NULL,
    `theme` ENUM('light', 'dark', 'system') NOT NULL DEFAULT 'dark',
    `language` VARCHAR(5) NOT NULL DEFAULT 'fr',
    `currency` VARCHAR(3) NOT NULL DEFAULT 'EUR',
    `timezone` VARCHAR(50) NOT NULL DEFAULT 'Europe/Paris',
    `notifications_email` TINYINT(1) NOT NULL DEFAULT 1,
    `notifications_push` TINYINT(1) NOT NULL DEFAULT 1,
    `integrations` JSON DEFAULT NULL,
    `updated_at` DATETIME DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`admin_id`),
    CONSTRAINT `fk_settings_admin` FOREIGN KEY (`admin_id`) 
        REFERENCES `admins` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLE: notification_settings (règles alertes)
-- ============================================
CREATE TABLE `notification_settings` (
    `id` VARCHAR(50) NOT NULL,
    `admin_id` VARCHAR(50) DEFAULT NULL,
    `event_type` VARCHAR(50) NOT NULL COMMENT 'new_user, payment, error, etc.',
    `channel` ENUM('email', 'push', 'webhook', 'sms') NOT NULL,
    `is_enabled` TINYINT(1) NOT NULL DEFAULT 1,
    `threshold` JSON DEFAULT NULL COMMENT 'Conditions de déclenchement',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_notification_settings_admin` (`admin_id`),
    KEY `idx_notification_settings_event` (`event_type`),
    CONSTRAINT `fk_notification_settings_admin` FOREIGN KEY (`admin_id`) 
        REFERENCES `admins` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLE: webhooks_outgoing (webhooks sortants)
-- ============================================
CREATE TABLE `webhooks_outgoing` (
    `id` VARCHAR(50) NOT NULL,
    `site_id` VARCHAR(50) DEFAULT NULL,
    `url` VARCHAR(500) NOT NULL,
    `events` JSON NOT NULL COMMENT 'Liste des événements à envoyer',
    `secret` VARCHAR(64) DEFAULT NULL,
    `is_active` TINYINT(1) NOT NULL DEFAULT 1,
    `last_triggered_at` DATETIME DEFAULT NULL,
    `last_status` SMALLINT UNSIGNED DEFAULT NULL COMMENT 'HTTP status code',
    `failure_count` INT UNSIGNED NOT NULL DEFAULT 0,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_webhooks_site_id` (`site_id`),
    KEY `idx_webhooks_is_active` (`is_active`),
    CONSTRAINT `fk_webhooks_site` FOREIGN KEY (`site_id`) 
        REFERENCES `sites` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- TABLE: monitoring (métriques de monitoring)
-- ============================================
CREATE TABLE `monitoring` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `site_id` VARCHAR(50) NOT NULL,
    `metric_type` VARCHAR(50) NOT NULL COMMENT 'uptime, response_time, errors',
    `value` DECIMAL(15,4) NOT NULL,
    `unit` VARCHAR(20) DEFAULT NULL COMMENT 'ms, %, count',
    `metadata` JSON DEFAULT NULL,
    `recorded_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_monitoring_site_id` (`site_id`),
    KEY `idx_monitoring_type` (`metric_type`),
    KEY `idx_monitoring_recorded_at` (`recorded_at`),
    KEY `idx_monitoring_site_type_date` (`site_id`, `metric_type`, `recorded_at`),
    CONSTRAINT `fk_monitoring_site` FOREIGN KEY (`site_id`) 
        REFERENCES `sites` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;

-- ============================================
-- FIN DU SCHÉMA
-- ============================================
