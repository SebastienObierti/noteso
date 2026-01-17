<?php
/**
 * NOTESO - Configuration MySQL 8
 */

return [
    // ============================================
    // BASE DE DONNÉES MYSQL 8
    // ============================================
    'database' => [
        'host'     => 'localhost',
        'port'     => 3306,
        'name'     => 'noteso',
        'user'     => 'seb31t',
        'password' => 'Bmwmpowerm3917=$*m',
        'charset'  => 'utf8mb4',
    ],
    
    // ============================================
    // APPLICATION
    // ============================================
    'app' => [
        'name'     => 'Noteso',
        'url'      => 'https://noteso.fr',
        'debug'    => true,  // Mettre à false en production
        'timezone' => 'Europe/Paris',
    ],
    
    // ============================================
    // SÉCURITÉ
    // ============================================
    'security' => [
        'session_duration'    => 604800,  // 7 jours
        'max_login_attempts'  => 5,
        'lockout_duration'    => 900,     // 15 minutes
        'min_password_length' => 8,
        'require_uppercase'   => true,
        'require_lowercase'   => true,
        'require_number'      => true,
        'require_special'     => false,
        'bcrypt_cost'         => 12,
    ],
    
    // ============================================
    // SMTP (Email)
    // ============================================
    'smtp' => [
        'enabled'    => true,
        'host'       => 'mail.obierti.fr',
        'port'       => 465,
        'encryption' => 'ssl',
        'username'   => 'contact@noteso.fr',
        'password'   => 'VOTRE_MOT_DE_PASSE_SMTP',
        'from_email' => 'contact@noteso.fr',
        'from_name'  => 'Noteso',
    ],
    
    // ============================================
    // ADMIN PAR DÉFAUT
    // ============================================
    'admins' => [
        [
            'email'     => 'contact@obierti.fr',
            'password'  => 'Admin123!',
            'firstName' => 'Admin',
            'lastName'  => 'Principal',
            'role'      => 'super_admin',
        ],
    ],
];
