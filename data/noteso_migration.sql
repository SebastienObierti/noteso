-- ============================================
-- NOTESO - Migration des données JSON
-- À exécuter après noteso_schema.sql
-- ============================================

USE `noteso`;

-- ============================================
-- ADMINS
-- ============================================
INSERT INTO `admins` (`id`, `email`, `password`, `first_name`, `last_name`, `role`, `permissions`, `created_at`, `last_login_at`, `last_login_ip`, `password_changed_at`)
VALUES (
    'admin_1',
    'contact@obierti.fr',
    '$2y$12$jUQUeW5lQO/EdLsB1fIkAOcaEsfsllFdtF0uPM8e/ZKenmRbbwRYi',
    'Admin',
    'Principal',
    'super_admin',
    '["all"]',
    '2026-01-12 10:36:31',
    NULL,
    NULL,
    NULL
);

-- ============================================
-- SITES
-- ============================================
INSERT INTO `sites` (`id`, `name`, `url`, `status`, `color`, `api_key`, `settings`, `created_at`) VALUES
('site_t8732h4fee641e', 'comptael', 'https://comptael.fr', 'online', '#ec4899', 'ek_t8732hfcbbe149', '{"currency": "EUR", "timezone": "Europe/Paris"}', '2026-01-01 17:56:41'),
('site_t873s2dc8ee6fd', 'fusionel', 'https://fusionel.fr', 'online', '#a855f7', 'ek_t873s2b29b750d', '{"currency": "EUR", "timezone": "Europe/Paris"}', '2026-01-01 18:12:02'),
('site_t874jzde56096f', 'gestionnel association', 'https://gestionnel.com', 'online', '#f97316', 'ek_t874jz91b66600', '{"currency": "EUR", "timezone": "Europe/Paris"}', '2026-01-01 18:28:47'),
('site_t874n0058b4b23', 'gestionnel immo', 'httpd://gestionnel.fr', 'online', '#f97316', 'ek_t874n0f6fddf2f', '{"currency": "EUR", "timezone": "Europe/Paris"}', '2026-01-01 18:30:36'),
('site_t875nv1d114d60', 'offrel', 'https://offrel.fr', 'online', '#3b82f6', 'ek_t875nvc76d812a', '{"currency": "EUR", "timezone": "Europe/Paris"}', '2026-01-01 18:52:43'),
('site_t8awt55af747a0', 'Elnumis', 'https://elnumis.fr', 'online', '#ec4899', 'ek_t8awt55cbf34c8', '{"currency": "EUR", "timezone": "Europe/Paris"}', '2026-01-03 19:31:53'),
('site_t8lxu90b26fc56', 'coiffurEl', 'https://coiffurel.fr', 'online', '#06b6d4', 'ek_t8lxu97b24ff6e', '{"currency": "EUR", "timezone": "Europe/Paris"}', '2026-01-09 18:27:45');

-- ============================================
-- SESSIONS
-- ============================================
INSERT INTO `sessions` (`id`, `admin_id`, `token`, `ip`, `user_agent`, `created_at`, `expires_at`) VALUES
('sess_t8giut77640cc0', 'admin_1', '51bba03fe5bd17ca8a85d465ffbde71da9071e2ee08eea756d974754ab5911db', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-06 20:16:05', '2026-01-13 20:16:05'),
('sess_t8hz4f727032c0', 'admin_1', '5f34e71d50bb1a846a009f48dba695edcbe42b7c611e2b792f5c246de402e691', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-07 15:05:03', '2026-01-14 15:05:03'),
('sess_t8jtuf3edce724', 'admin_1', '37b6cb334e9933d852940126ce4a0fec79cd4c17aeb5ea41d8ba1bd758d222ab', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-08 15:06:15', '2026-01-15 15:06:15'),
('sess_t8plia63403e84', 'admin_1', 'de1c269e1b52580a747acc1feb5380678fd61fe0e59602c01bdf7a4ba573a697', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-11 17:51:46', '2026-01-18 17:51:46');

-- ============================================
-- NOTIFICATIONS
-- ============================================
INSERT INTO `notifications` (`id`, `admin_id`, `type`, `title`, `message`, `is_read`, `created_at`) VALUES
('notif_1', NULL, 'info', 'Bienvenue!', 'Votre dashboard est prêt.', 0, '2026-01-12 10:36:31'),
('notif_2', NULL, 'success', 'Nouveau record!', 'Vous avez dépassé 10 000 utilisateurs.', 0, '2026-01-12 09:36:31');

-- ============================================
-- SECURITY_LOGS
-- ============================================
INSERT INTO `security_logs` (`id`, `admin_id`, `type`, `details`, `ip`, `user_agent`, `timestamp`) VALUES
('log_t872cn4652cf8a', NULL, 'login_failed', 'Échec connexion: contact@obierti.fr', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-01 17:41:11'),
('log_t872dgfc4bf08d', NULL, 'login_failed', 'Échec connexion: contact@obierti.fr', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-01 17:41:40'),
('log_t872oq31728954', 'admin_1', 'login_success', 'Connexion réussie: contact@obierti.fr', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-01 17:48:26'),
('log_t872vh6de39872', 'admin_1', 'logout', 'Déconnexion', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-01 17:52:29'),
('log_t872w05300aeca', 'admin_1', 'login_success', 'Connexion réussie: contact@obierti.fr', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-01 17:52:48'),
('log_t8769tc7f2be10', 'admin_1', 'logout', 'Déconnexion', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-01 19:05:53'),
('log_t8769wa49d390a', NULL, 'login_failed', 'Échec connexion: contact@obierti.fr', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-01 19:05:56'),
('log_t876ah977bb2f7', 'admin_1', 'login_success', 'Connexion réussie: contact@obierti.fr', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-01 19:06:17'),
('log_t876cu9af08499', 'admin_1', 'logout', 'Déconnexion', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-01 19:07:42'),
('log_t876d89bc54a34', NULL, 'login_failed', 'Échec connexion: admin@noteso.fr', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-01 19:07:56'),
('log_t876dh9767a0ca', 'admin_1', 'login_success', 'Connexion réussie: contact@obierti.fr', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-01 19:08:05'),
('log_t8giuk1735914c', NULL, 'login_failed', 'Échec connexion: admin@noteso.fr', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-06 20:15:56'),
('log_t8giutb5821472', 'admin_1', 'login_success', 'Connexion réussie: contact@obierti.fr', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-06 20:16:05'),
('log_t8hz487d706a56', NULL, 'login_failed', 'Échec connexion: admin@noteso.fr', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-07 15:04:56'),
('log_t8hz4f4c00b018', 'admin_1', 'login_success', 'Connexion réussie: contact@obierti.fr', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-07 15:05:03'),
('log_t8jtufce5e7611', 'admin_1', 'login_success', 'Connexion réussie: contact@obierti.fr', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-08 15:06:15'),
('log_t8pli3c349ecae', NULL, 'login_failed', 'Échec connexion: admin@noteso.fr', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-11 17:51:39'),
('log_t8pliacfaab72f', 'admin_1', 'login_success', 'Connexion réussie: contact@obierti.fr', '90.14.222.141', 'Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0', '2026-01-11 17:51:46');

-- ============================================
-- WIDGETS
-- ============================================
INSERT INTO `widgets` (`id`, `admin_id`, `type`, `title`, `position_x`, `position_y`, `width`, `height`, `is_visible`) VALUES
('w1', NULL, 'stats', 'Utilisateurs', 0, 0, 1, 1, 1),
('w2', NULL, 'stats', 'Paiements', 1, 0, 1, 1, 1),
('w3', NULL, 'stats', 'Revenus', 2, 0, 1, 1, 1),
('w4', NULL, 'stats', 'Sites', 3, 0, 1, 1, 1),
('w5', NULL, 'chart', 'Revenus', 0, 1, 2, 2, 1),
('w6', NULL, 'sites', 'Sites', 0, 3, 4, 2, 1),
('w7', NULL, 'activity', 'Activité', 0, 5, 2, 2, 1),
('w8', NULL, 'breakdown', 'Répartition', 2, 5, 2, 2, 1);

-- ============================================
-- CONFIG (clé/valeur)
-- ============================================
INSERT INTO `config` (`key`, `value`) VALUES
('smtp', '{"enabled": true, "host": "mail.obierti.fr", "port": 465, "encryption": "ssl", "username": "contact@noteso.fr", "password": "Bmwmpowerm", "from_email": "contact@noteso.fr", "from_name": "Noteso"}'),
('app', '{"name": "Noteso", "url": "https://noteso.fr", "debug": true, "timezone": "Europe/Paris"}'),
('security', '{"session_duration": 604800, "max_login_attempts": 5, "lockout_duration": 900, "min_password_length": 8}');

-- ============================================
-- SETTINGS (paramètres admin par défaut)
-- ============================================
INSERT INTO `settings` (`admin_id`, `theme`, `language`, `currency`, `timezone`, `notifications_email`, `notifications_push`, `integrations`) VALUES
('admin_1', 'dark', 'fr', 'EUR', 'Europe/Paris', 1, 1, '{"stripe": {"enabled": false, "apiKey": ""}, "paypal": {"enabled": false, "clientId": ""}}');

-- ============================================
-- FIN MIGRATION
-- ============================================
