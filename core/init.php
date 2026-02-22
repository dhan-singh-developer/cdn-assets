<?php
header('Content-Type: text/plain');
header('Access-Control-Allow-Origin: *');
header('Cache-Control: no-store');

session_start();
$rl = 'chk_' . md5($_SERVER['REMOTE_ADDR']);
if (isset($_SESSION[$rl]) && $_SESSION[$rl] > time()) {
    http_response_code(429);
    exit('RT');
}

require_once '../lib/hash.php';
require_once '../lib/device.php';

class Core {
    private $db = '../data/registry.json';
    private $salt = 'xK9#mP2$vL8@nQ5!wR7%';
    
    public function auth($h, $k, $d) {
        $reg = $this->load();
        
        if (!isset($reg[$k])) {
            return $this->resp(0, 'E001');
        }
        
        $item = $reg[$k];
        
        if ($item['s'] !== 1) {
            return $this->resp(0, 'E002');
        }
        
        if (strtotime($item['exp']) < time()) {
            return $this->resp(0, 'E003');
        }
        
        if (!$this->matchHost($h, $item['h'])) {
            $this->log($k, $h, $d, 'HOST_MISMATCH');
            return $this->resp(0, 'E004');
        }
        
        if ($item['dev'] && $item['dev'] !== $d) {
            $this->log($k, $h, $d, 'DEVICE_MISMATCH');
            return $this->resp(0, 'E005');
        }
        
        $reg[$k]['lc'] = date('Y-m-d H:i:s');
        $reg[$k]['cnt'] = ($item['cnt'] ?? 0) + 1;
        $this->save($reg);
        
        $payload = [
            'v' => 1,
            'u' => $item['u'],
            'f' => $item['f'],
            'exp' => $item['exp'],
            'tkn' => $this->gen($k, $h),
            'ts' => time()
        ];
        
        return $this->enc(json_encode($payload));
    }
    
    private function matchHost($p, $r) {
        $p = preg_replace('#^https?://(www\.)?#', '', $p);
        $r = preg_replace('#^https?://(www\.)?#', '', $r);
        return strtolower(trim($p, '/')) === strtolower(trim($r, '/'));
    }
    
    private function gen($k, $h) {
        return hash_hmac('sha256', $k . $h . date('Ymd'), $this->salt);
    }
    
    private function enc($str) {
        $c = "AES-256-CBC";
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($c));
        $e = openssl_encrypt($str, $c, $this->salt, 0, $iv);
        return base64_encode($e . '::' . $iv);
    }
    
    private function load() {
        return file_exists($this->db) ? json_decode(file_get_contents($this->db), true) : [];
    }
    
    private function save($data) {
        file_put_contents($this->db, json_encode($data));
    }
    
    private function log($k, $h, $d, $type) {
        $entry = json_encode([
            'k' => $k,
            'h' => $h,
            'd' => $d,
            't' => $type,
            'ip' => $_SERVER['REMOTE_ADDR'],
            'ts' => time()
        ]);
        file_put_contents('../data/alerts.log', $entry . "\n", FILE_APPEND);
    }
    
    private function resp($status, $msg) {
        return json_encode(['v' => $status, 'm' => $msg]);
    }
}

$h = $_POST['h'] ?? $_GET['h'] ?? '';
$k = $_POST['k'] ?? $_GET['k'] ?? '';
$d = $_POST['d'] ?? $_GET['d'] ?? '';

if (!$h || !$k) {
    exit(json_encode(['v' => 0, 'm' => 'E000']));
}

$core = new Core();
echo $core->auth($h, $k, $d);

$_SESSION[$rl] = time() + 30;
?>
