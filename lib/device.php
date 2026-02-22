<?php
class Device {
    public static function gen($extra = []) {
        $parts = [
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
            implode('', $extra)
        ];
        return hash('sha256', implode('|', $parts));
    }
    
    public static function info() {
        return [
            'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'lang' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''
        ];
    }
}
?>
