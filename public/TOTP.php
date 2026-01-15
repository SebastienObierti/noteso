<?php
/**
 * TOTP (Time-based One-Time Password) Implementation
 * Compatible avec Google Authenticator, Authy, etc.
 */

class TOTP {
    private const DIGITS = 6;
    private const PERIOD = 30;
    private const ALGORITHM = 'sha1';
    private const SECRET_LENGTH = 16;
    
    private static $base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    
    /**
     * Génère un nouveau secret en Base32
     */
    public static function generateSecret(): string {
        $secret = '';
        $randomBytes = random_bytes(self::SECRET_LENGTH);
        
        for ($i = 0; $i < self::SECRET_LENGTH; $i++) {
            $secret .= self::$base32Chars[ord($randomBytes[$i]) % 32];
        }
        
        return $secret;
    }
    
    /**
     * Génère l'URL pour le QR code (format otpauth://)
     */
    public static function getQRCodeUrl(string $secret, string $email, string $issuer = 'Noteso'): string {
        $params = http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
            'algorithm' => strtoupper(self::ALGORITHM),
            'digits' => self::DIGITS,
            'period' => self::PERIOD
        ]);
        
        $label = rawurlencode($issuer . ':' . $email);
        return "otpauth://totp/{$label}?{$params}";
    }
    
    /**
     * Génère l'URL de l'image QR code via API Google Charts
     */
    public static function getQRCodeImageUrl(string $secret, string $email, string $issuer = 'Noteso', int $size = 200): string {
        $otpauthUrl = self::getQRCodeUrl($secret, $email, $issuer);
        return 'https://chart.googleapis.com/chart?chs=' . $size . 'x' . $size . '&cht=qr&chl=' . urlencode($otpauthUrl) . '&choe=UTF-8';
    }
    
    /**
     * Vérifie un code TOTP
     * @param string $secret Secret en Base32
     * @param string $code Code à 6 chiffres
     * @param int $window Fenêtre de tolérance (nombre de périodes avant/après)
     */
    public static function verify(string $secret, string $code, int $window = 2): bool {
        $code = preg_replace('/\s+/', '', $code); // Enlever espaces
        
        if (strlen($code) !== self::DIGITS || !ctype_digit($code)) {
            return false;
        }
        
        $currentTime = time();
        
        // Vérifier dans la fenêtre de tolérance
        for ($i = -$window; $i <= $window; $i++) {
            $timeSlice = (int)floor(($currentTime + ($i * self::PERIOD)) / self::PERIOD);
            $expectedCode = self::generateCode($secret, $timeSlice);
            
            if (hash_equals($expectedCode, $code)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Génère le code TOTP pour un timestamp donné
     */
    public static function generateCode(string $secret, ?int $timeSlice = null): string {
        if ($timeSlice === null) {
            $timeSlice = (int)floor(time() / self::PERIOD);
        }
        
        // Convertir le secret Base32 en binaire
        $secretKey = self::base32Decode($secret);
        
        // Convertir le timeSlice en bytes (8 bytes, big-endian)
        $time = pack('N', 0) . pack('N', $timeSlice);
        
        // HMAC-SHA1
        $hash = hash_hmac(self::ALGORITHM, $time, $secretKey, true);
        
        // Dynamic truncation
        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
        $binary = (
            ((ord($hash[$offset]) & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) << 8) |
            (ord($hash[$offset + 3]) & 0xFF)
        );
        
        // Générer le code à N chiffres
        $otp = $binary % pow(10, self::DIGITS);
        
        return str_pad((string)$otp, self::DIGITS, '0', STR_PAD_LEFT);
    }
    
    /**
     * Génère des codes de secours (backup codes)
     */
    public static function generateBackupCodes(int $count = 8): array {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            // Format: XXXX-XXXX
            $codes[] = strtoupper(bin2hex(random_bytes(2))) . '-' . strtoupper(bin2hex(random_bytes(2)));
        }
        return $codes;
    }
    
    /**
     * Vérifie un code de secours
     */
    public static function verifyBackupCode(string $code, array $validCodes): ?int {
        $code = strtoupper(str_replace([' ', '-'], '', $code));
        
        foreach ($validCodes as $index => $validCode) {
            if ($validCode === null) continue;
            $cleanValid = strtoupper(str_replace([' ', '-'], '', $validCode));
            if (hash_equals($cleanValid, $code)) {
                return $index;
            }
        }
        
        return null;
    }
    
    /**
     * Décode une chaîne Base32
     */
    private static function base32Decode(string $input): string {
        $input = strtoupper($input);
        $input = str_replace('=', '', $input);
        
        $buffer = 0;
        $bitsLeft = 0;
        $output = '';
        
        for ($i = 0; $i < strlen($input); $i++) {
            $char = $input[$i];
            $val = strpos(self::$base32Chars, $char);
            
            if ($val === false) {
                continue;
            }
            
            $buffer = ($buffer << 5) | $val;
            $bitsLeft += 5;
            
            if ($bitsLeft >= 8) {
                $bitsLeft -= 8;
                $output .= chr(($buffer >> $bitsLeft) & 0xFF);
            }
        }
        
        return $output;
    }
    
    /**
     * Temps restant avant le prochain code (en secondes)
     */
    public static function getRemainingTime(): int {
        return self::PERIOD - (time() % self::PERIOD);
    }
}
