-- ============================================
-- PATCH v1.3 - Intégrations, Rapports PDF, Recherche
-- ============================================

-- 1. Table pour les intégrations externes
CREATE TABLE IF NOT EXISTS `integrations` (
    `id` VARCHAR(50) NOT NULL,
    `admin_id` VARCHAR(50) NOT NULL,
    `provider` VARCHAR(50) NOT NULL COMMENT 'stripe, paypal, google_analytics',
    `name` VARCHAR(100) DEFAULT NULL,
    `is_active` TINYINT(1) NOT NULL DEFAULT 1,
    `credentials` TEXT DEFAULT NULL COMMENT 'Credentials chiffrés (AES)',
    `settings` JSON DEFAULT NULL,
    `last_sync_at` DATETIME DEFAULT NULL,
    `sync_status` ENUM('idle', 'syncing', 'success', 'error') DEFAULT 'idle',
    `sync_error` TEXT DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_integrations_admin` (`admin_id`),
    KEY `idx_integrations_provider` (`provider`),
    CONSTRAINT `fk_integrations_admin` FOREIGN KEY (`admin_id`) 
        REFERENCES `admins` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Table pour les logs de synchronisation
CREATE TABLE IF NOT EXISTS `sync_logs` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `integration_id` VARCHAR(50) NOT NULL,
    `action` VARCHAR(50) NOT NULL COMMENT 'sync_payments, sync_customers, etc.',
    `status` ENUM('started', 'success', 'error') NOT NULL,
    `records_processed` INT UNSIGNED DEFAULT 0,
    `records_created` INT UNSIGNED DEFAULT 0,
    `records_updated` INT UNSIGNED DEFAULT 0,
    `error_message` TEXT DEFAULT NULL,
    `duration_ms` INT UNSIGNED DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_sync_logs_integration` (`integration_id`),
    KEY `idx_sync_logs_created` (`created_at`),
    CONSTRAINT `fk_sync_logs_integration` FOREIGN KEY (`integration_id`) 
        REFERENCES `integrations` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Table pour les rapports programmés
CREATE TABLE IF NOT EXISTS `scheduled_reports` (
    `id` VARCHAR(50) NOT NULL,
    `admin_id` VARCHAR(50) NOT NULL,
    `name` VARCHAR(100) NOT NULL,
    `report_type` VARCHAR(50) NOT NULL COMMENT 'revenue, users, payments, full',
    `frequency` ENUM('daily', 'weekly', 'monthly') NOT NULL DEFAULT 'weekly',
    `day_of_week` TINYINT UNSIGNED DEFAULT NULL COMMENT '0=Dimanche, 6=Samedi',
    `day_of_month` TINYINT UNSIGNED DEFAULT NULL COMMENT '1-28',
    `hour` TINYINT UNSIGNED NOT NULL DEFAULT 8,
    `recipients` JSON DEFAULT NULL COMMENT 'Liste emails',
    `format` ENUM('pdf', 'csv', 'excel') NOT NULL DEFAULT 'pdf',
    `include_charts` TINYINT(1) NOT NULL DEFAULT 1,
    `site_ids` JSON DEFAULT NULL COMMENT 'NULL = tous les sites',
    `is_active` TINYINT(1) NOT NULL DEFAULT 1,
    `last_sent_at` DATETIME DEFAULT NULL,
    `next_send_at` DATETIME DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_scheduled_reports_admin` (`admin_id`),
    KEY `idx_scheduled_reports_next` (`next_send_at`),
    CONSTRAINT `fk_scheduled_reports_admin` FOREIGN KEY (`admin_id`) 
        REFERENCES `admins` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Table pour les rapports générés
CREATE TABLE IF NOT EXISTS `generated_reports` (
    `id` VARCHAR(50) NOT NULL,
    `admin_id` VARCHAR(50) NOT NULL,
    `scheduled_report_id` VARCHAR(50) DEFAULT NULL,
    `name` VARCHAR(200) NOT NULL,
    `report_type` VARCHAR(50) NOT NULL,
    `period_start` DATE NOT NULL,
    `period_end` DATE NOT NULL,
    `format` VARCHAR(10) NOT NULL DEFAULT 'pdf',
    `file_path` VARCHAR(500) DEFAULT NULL,
    `file_size` INT UNSIGNED DEFAULT NULL,
    `data` JSON DEFAULT NULL COMMENT 'Données du rapport',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_generated_reports_admin` (`admin_id`),
    KEY `idx_generated_reports_created` (`created_at`),
    CONSTRAINT `fk_generated_reports_admin` FOREIGN KEY (`admin_id`) 
        REFERENCES `admins` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Table pour l'index de recherche
CREATE TABLE IF NOT EXISTS `search_index` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `entity_type` VARCHAR(50) NOT NULL COMMENT 'user, payment, site, subscription',
    `entity_id` VARCHAR(50) NOT NULL,
    `site_id` VARCHAR(50) DEFAULT NULL,
    `title` VARCHAR(255) NOT NULL,
    `content` TEXT DEFAULT NULL,
    `metadata` JSON DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_search_entity` (`entity_type`, `entity_id`),
    KEY `idx_search_site` (`site_id`),
    FULLTEXT KEY `ft_search` (`title`, `content`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Ajouter colonne external_provider aux payments
ALTER TABLE `payments`
    ADD COLUMN   `provider` VARCHAR(50) DEFAULT NULL COMMENT 'stripe, paypal, manual' AFTER `payment_method`,
    ADD COLUMN   `provider_fee` DECIMAL(10,2) DEFAULT NULL AFTER `provider`,
    ADD COLUMN   `net_amount` DECIMAL(10,2) DEFAULT NULL AFTER `provider_fee`;

-- 7. Index pour améliorer les recherches
ALTER TABLE `users` ADD FULLTEXT INDEX   `ft_users_search` (`email`, `name`);
ALTER TABLE `payments` ADD INDEX   `idx_payments_external` (`external_id`);

-- 8. Procédure pour mettre à jour l'index de recherche
DELIMITER //
CREATE PROCEDURE   `update_search_index`()
BEGIN
    -- Indexer les utilisateurs
    INSERT INTO search_index (entity_type, entity_id, site_id, title, content, metadata)
    SELECT 'user', id, site_id, 
           COALESCE(name, email), 
           CONCAT_WS(' ', email, name, external_id),
           JSON_OBJECT('email', email, 'created', created_at)
    FROM users
    ON DUPLICATE KEY UPDATE 
        title = VALUES(title), 
        content = VALUES(content),
        updated_at = NOW();
    
    -- Indexer les paiements
    INSERT INTO search_index (entity_type, entity_id, site_id, title, content, metadata)
    SELECT 'payment', id, site_id,
           CONCAT('Paiement ', amount, ' ', currency),
           CONCAT_WS(' ', external_id, payment_method, status),
           JSON_OBJECT('amount', amount, 'status', status, 'created', created_at)
    FROM payments
    ON DUPLICATE KEY UPDATE
        title = VALUES(title),
        content = VALUES(content),
        updated_at = NOW();
    
    -- Indexer les sites
    INSERT INTO search_index (entity_type, entity_id, site_id, title, content, metadata)
    SELECT 'site', id, id,
           name,
           CONCAT_WS(' ', name, url),
           JSON_OBJECT('url', url, 'status', status)
    FROM sites
    ON DUPLICATE KEY UPDATE
        title = VALUES(title),
        content = VALUES(content),
        updated_at = NOW();
END //
DELIMITER ;

-- Exécuter la procédure une première fois
CALL update_search_index();
