<?php
/*
Plugin Name: Security Calv Point (SCP)
Description: Plugin All in One untuk keamanan website anda
Version: 1.0
Author: Calv-Indo (Randhi Danar)
*/

if (!defined('ABSPATH')) exit;

class SecurityCalvPoint {
    private $options;
    private $malware_signatures = array(
    // Backdoor dan shell script terkenal
    'eval(base64_decode($_POST', 
    'eval(gzinflate(base64_decode', 
    'c99shell', 
    'r57shell', 
    'b374k', 
    'WebShell', 
    'wso(', 
    'phpspy',
    
    // Obfuscation umum
    'eval(str_rot13(', 
    'eval(urldecode(', 
    'gzinflate(base64_decode(', 
    'str_rot13(base64_decode(', 
    'urldecode(base64_decode(',
    
    // Malware JavaScript
    'document.write(base64_decode(', 
    'eval(function(p,a,c,k,e,d)',
    'atob(',
    'decodeURIComponent(',
    'String.fromCharCode(',
    
    // Ekstensi/file mencurigakan
    '.exe', 
    '.dll', 
    '.htaccess', 
    '.htpasswd', 
    '.ini', 
    '.log',
    
    // Signature tambahan untuk shell dan JS
    'shell_exec($_GET', 
    'shell_exec($_POST', 
    'eval(base64_decode($_GET', 
    'eval(base64_decode($_POST',
    'php_uname(',
    'passthru(',
    'system(',
    
    // Pola base64 panjang
    '/[a-zA-Z0-9+\/=]{100,}/'
    );

    private $excluded_file_types = array(
        'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'woff', 'woff2', 'ttf', 'eot', 'otf', 'ico'
    );

    public function __construct() {
        $this->options = get_option('scp_options', []);

        add_action('admin_menu', array($this, 'add_plugin_page'));
        add_action('admin_init', array($this, 'page_init'));
        add_action('init', array($this, 'security_features'));
        add_action('template_redirect', array($this, 'redirect_login_page'));
        add_filter('site_url', array($this, 'change_login_url'), 10, 3);
        add_action('wp_ajax_scp_malware_scan', array($this, 'malware_scanner'));
        add_action('wp_ajax_scp_delete_malware', array($this, 'delete_malware'));

        // Tambahkan rewrite rule saat plugin diaktifkan
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
    }

    public function add_plugin_page() {
        add_menu_page(
            'Security Calv Point',
            'SCP Security',
            'manage_options',
            'scp-security',
            array($this, 'admin_page_content'),
            'dashicons-shield',
            80
        );
    }

    public function admin_page_content() {
        ?>
        <div class="wrap">
            <h1>Security Calv Point</h1>
            <div class="notice notice-info">
                <p>Konfigurasi: <strong><?php echo $this->security_status(); ?></strong></p>
            </div>
            <form method="post" action="options.php">
                <?php
                settings_fields('scp_group');
                do_settings_sections('scp-security');
                submit_button('Simpan Perubahan');
                ?>
            </form>
            <div class="scan-section">
                <h2>Malware Scanner</h2>
                <div style="margin-bottom: 20px;">
                    <button id="start-scan" class="button button-primary">Mulai Scan Sekarang</button>
                    <button id="delete-malware" class="button button-danger" style="display: none; background-color: #dc3232; color: white; border-color: #dc3232; margin-left: 10px;">Hapus Malware</button>
                </div>
                <div id="scan-results" style="margin-top:20px;"></div>
            </div>
        </div>

        <script>
        jQuery(document).ready(function($) {
            $('#start-scan').click(function() {
                $('#scan-results').html('<p>Scanning...<div class="spinner is-active"></div></p>');
                $('#delete-malware').hide(); // Sembunyikan tombol hapus sebelum scan

                $.post(ajaxurl, {
                    action: 'scp_malware_scan',
                    security: '<?php echo wp_create_nonce("scp-scan-nonce"); ?>'
                }, function(response) {
                    $('#scan-results').html(response.data);

                    // Tampilkan tombol hapus jika ada malware
                    if (response.data.includes('Potensi malware ditemukan di:')) {
                        $('#delete-malware').show();
                    }
                });
            });

            $('#delete-malware').click(function() {
                if (confirm('Apakah Anda yakin ingin menghapus file yang terdeteksi sebagai malware? Pastikan Anda sudah membuat backup!')) {
                    $('#scan-results').html('<p>Menghapus malware...<div class="spinner is-active"></div></p>');

                    $.post(ajaxurl, {
                        action: 'scp_delete_malware',
                        security: '<?php echo wp_create_nonce("scp-delete-nonce"); ?>'
                    }, function(response) {
                        $('#scan-results').html(response.data);
                        $('#delete-malware').hide(); // Sembunyikan tombol setelah penghapusan
                    });
                }
            });
        });
        </script>
        <?php
    }

    public function page_init() {
        register_setting('scp_group', 'scp_options');

        add_settings_section('scp_comments', 'Pengaturan Komentar', null, 'scp-security');
        add_settings_field('disable_comments', 'Nonaktifkan Komentar', array($this, 'checkbox_callback'), 'scp-security', 'scp_comments', ['id' => 'disable_comments']);
        add_settings_field('disable_links', 'Blokir Link di Komentar', array($this, 'checkbox_callback'), 'scp-security', 'scp_comments', ['id' => 'disable_links']);

        add_settings_section('scp_security', 'Fitur Keamanan', null, 'scp-security');
        add_settings_field('disable_xmlrpc', 'Nonaktifkan XML-RPC', array($this, 'checkbox_callback'), 'scp-security', 'scp_security', ['id' => 'disable_xmlrpc']);
        add_settings_field('login_slug', 'Custom Login URL', array($this, 'text_callback'), 'scp-security', 'scp_security', ['id' => 'login_slug']);
        add_settings_field('redirect_url', 'Redirect URL', array($this, 'text_callback'), 'scp-security', 'scp_security', ['id' => 'redirect_url']);
    }

    public function checkbox_callback($args) {
        $checked = isset($this->options[$args['id']]) ? checked(1, $this->options[$args['id']], false) : '';
        echo "<input type='checkbox' id='{$args['id']}' name='scp_options[{$args['id']}]' value='1' $checked />";
    }

    public function text_callback($args) {
        $value = $this->options[$args['id']] ?? '';
        
        // Set default value untuk Custom Login URL
        if ($args['id'] === 'login_slug' && empty($value)) {
            $value = 'admin'; // Nilai default untuk Custom Login URL
        }
    
        // Set default value untuk Redirect URL
        if ($args['id'] === 'redirect_url' && empty($value)) {
            $value = '404'; // Default value untuk Redirect URL
        }
    
        echo "<input type='text' class='regular-text' name='scp_options[{$args['id']}]' value='$value' />";
    }

    public function security_features() {
        if (!empty($this->options['disable_comments'])) {
            add_filter('comments_open', '__return_false', 20, 2);
            add_filter('pings_open', '__return_false', 20, 2);
        }

        if (!empty($this->options['disable_links'])) {
            add_filter('comment_text', array($this, 'sanitize_comments'));
        }

        if (!empty($this->options['disable_xmlrpc'])) {
            add_filter('xmlrpc_enabled', '__return_false');
        }

        // Tambahkan rewrite rule untuk custom login URL
        add_action('init', array($this, 'add_rewrite_rule'));
    }

    public function add_rewrite_rule() {
        $login_slug = $this->options['login_slug'] ?? 'wp-login.php';
        add_rewrite_rule('^' . $login_slug . '/?$', 'index.php?custom_login=1', 'top');
    }

    public function sanitize_comments($comment) {
        return preg_replace('/<a[^>]*>(.*?)<\/a>/i', '', $comment);
    }

    public function change_login_url($url, $path, $scheme) {
        if ($path === 'wp-login.php' && !empty($this->options['login_slug'])) {
            return home_url($this->options['login_slug'], $scheme);
        }
        return $url;
    }

    public function redirect_login_page() {
        $login_slug = $this->options['login_slug'] ?? 'wp-login.php';
        $redirect_url = $this->options['redirect_url'] ?? '404';
        $request_uri = $_SERVER['REQUEST_URI'];

        // Redirect jika mencoba mengakses wp-login.php atau wp-admin langsung
        if ((strpos($request_uri, 'wp-login.php') !== false || strpos($request_uri, 'wp-admin') !== false) && !is_user_logged_in()) {
            if ($redirect_url === '404') {
                wp_redirect(home_url('/404'));
            } else {
                wp_redirect($redirect_url);
            }
            exit();
        }

        // Redirect ke custom login URL
        if (strpos($request_uri, $login_slug) !== false && !is_user_logged_in()) {
            require_once ABSPATH . 'wp-login.php';
            exit();
        }
    }

    private function is_trusted_file($file_path) {
    // Core WordPress files
    $core_files = [
        ABSPATH . 'wp-load.php',
        ABSPATH . 'wp-config.php',
        ABSPATH . 'wp-settings.php',
        ABSPATH . 'wp-admin/',
        ABSPATH . 'wp-includes/'
    ];

    foreach ($core_files as $core_file) {
        if (strpos($file_path, $core_file) !== false) {
            return true;
        }
    }

    // Verified plugins/themes from repository
    $verified_plugins = get_option('active_plugins');
    foreach ($verified_plugins as $plugin) {
        $plugin_dir = WP_PLUGIN_DIR . '/' . dirname($plugin);
        if (strpos($file_path, $plugin_dir) !== false) {
            return true;
        }
    }

    $theme_root = get_theme_root();
    $themes = wp_get_themes();
    foreach ($themes as $theme) {
        $theme_dir = $theme_root . '/' . $theme->get_stylesheet();
        if (strpos($file_path, $theme_dir) !== false) {
            return true;
        }
    }

    // User-defined whitelist
    $custom_whitelist = $this->options['whitelist'] ?? [];
    foreach ($custom_whitelist as $whitelisted_path) {
        if (strpos($file_path, $whitelisted_path) !== false) {
            return true;
        }
    }

    return false;
    }
    
    private function analyze_file($file_path) {
    $extension = pathinfo($file_path, PATHINFO_EXTENSION);
    if (in_array($extension, $this->excluded_file_types)) {
        return []; // Skip excluded file types
    }

    $content = @file_get_contents($file_path);
    if ($content === false) {
        return ["Gagal membaca file: " . esc_html($file_path)];
    }

    $results = [];

    // Deteksi signature malware
    foreach ($this->malware_signatures as $signature) {
        if (is_string($signature) && strpos($content, $signature) !== false) {
            $results[] = "Potensi malware ditemukan di: " . esc_html($file_path);
            break;
        } elseif (is_string($signature) && $signature[0] === '/' && preg_match($signature, $content)) {
            $results[] = "Pola mencurigakan terdeteksi di: " . esc_html($file_path);
            break;
        }
    }

    // Deteksi JS berbahaya
    if ($extension === 'js' && $this->detect_malicious_js($content)) {
        $results[] = "Kode JS berbahaya ditemukan di: " . esc_html($file_path);
    }

    // Heuristic Analysis
    if ($this->heuristic_analysis($content)) {
        $results[] = "Pola mencurigakan: " . esc_html($file_path);
    }

    return $results;
    }

    private function detect_renderer_exploit($file_path, $content) {
    // Periksa hanya file gambar
    if (in_array(pathinfo($file_path, PATHINFO_EXTENSION), ['jpg', 'jpeg', 'png', 'gif', 'webp'])) {
        // Cari tanda kode PHP atau JavaScript dalam konten file
        if (strpos($content, '<?php') !== false || strpos($content, '<script') !== false) {
            return true;
        }
    }
    return false;
    }

    private function detect_steganography($file_path, $content) {
    // Periksa hanya file gambar
    if (in_array(pathinfo($file_path, PATHINFO_EXTENSION), ['jpg', 'jpeg', 'png', 'gif', 'webp'])) {
        $hex = bin2hex($content);
        // Cari pola hex yang mencurigakan (contoh: pola panjang yang tidak biasa)
        if (preg_match('/([0-9a-f]{8})\1{3,}/', $hex)) { // Contoh: pola berulang
            return true;
        }
    }
    return false;
    }

    private function detect_phishing($file_path, $content) {
    // Periksa hanya file gambar
    if (in_array(pathinfo($file_path, PATHINFO_EXTENSION), ['jpg', 'jpeg', 'png', 'gif', 'webp'])) {
        // Gunakan OCR untuk mengekstrak teks dari gambar
        $text = shell_exec("tesseract $file_path stdout 2>/dev/null");
        if ($text) {
            // Cari URL yang mencurigakan
            if (preg_match('/https?:\/\/(?:www\.)?(?:phishing|malware|evil)\.\w+/i', $text)) {
                return true;
            }
        }
    }
    return false;
    }

    private function detect_executable_script($file_path, $content) {
    // Periksa hanya file dengan ekstensi tertentu
    if (in_array(pathinfo($file_path, PATHINFO_EXTENSION), ['php', 'js', 'html', 'htm'])) {
        // Cari kombinasi fungsi berbahaya
        $dangerous_patterns = [
            '/eval\(base64_decode\(/i',
            '/system\(\$_GET\[/i',
            '/shell_exec\(\$_POST\[/i'
        ];
        foreach ($dangerous_patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }
    }
    return false;
    }

    public function malware_scanner() {
        check_ajax_referer('scp-scan-nonce', 'security');
    
        $scan_results = [];
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(ABSPATH));
    
        foreach ($files as $file) {
            if ($file->isDir()) continue;
    
            $file_path = $file->getRealPath();
    
            // Skip file-file inti WordPress, plugin, dan tema resmi
            if ($this->is_trusted_file($file_path)) continue;
    
            $results = $this->analyze_file($file_path);
            $scan_results = array_merge($scan_results, $results);
        }
    
        if (empty($scan_results)) {
            $message = "<div class='notice notice-success'>Website Aman dari Malware!</div>";
        } else {
            $message = "<div class='notice notice-error'>" . implode('<br>', $scan_results) . "</div>";
        }
    
        wp_send_json_success($message);
    }

    public function delete_malware() {
        check_ajax_referer('scp-delete-nonce', 'security');

        $scan_results = [];
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(ABSPATH));

        foreach ($files as $file) {
            if ($file->isDir()) continue;

            $file_path = $file->getRealPath();

            // Skip file-file inti WordPress dan plugin resmi
            if ($this->is_trusted_file($file_path)) continue;

            $results = $this->analyze_file($file_path);
            if (!empty($results)) {
                // Backup file sebelum dihapus
                $backup_dir = WP_CONTENT_DIR . '/scp-backups/';
                if (!is_dir($backup_dir)) {
                    mkdir($backup_dir, 0755, true);
                }
                $backup_file = $backup_dir . basename($file_path) . '.bak';
                copy($file_path, $backup_file);

                if (@unlink($file_path)) {
                    $scan_results[] = "File berhasil dihapus: " . esc_html($file_path) . " (Backup disimpan di: " . esc_html($backup_file) . ")";
                } else {
                    $scan_results[] = "Gagal menghapus file: " . esc_html($file_path);
                }
            }
        }

        if (empty($scan_results)) {
            $message = "<div class='notice notice-success'>Tidak ada malware yang terdeteksi!</div>";
        } else {
            $message = "<div class='notice notice-success'>" . implode('<br>', $scan_results) . "</div>";
        }

        wp_send_json_success($message);
    }

    private function heuristic_analysis($content) {
    $score = 0;
    
    // Pola PHP berbahaya
    $php_patterns = [
        '/eval\s*\(\s*base64_decode\s*\(\s*["\']([a-zA-Z0-9+\/=]+)/i',
        '/system\s*\(\s*\$_(GET|POST|REQUEST)/i',
        '/shell_exec\s*\(\s*\$_(GET|POST|REQUEST)/i',
        '/\b(passthru|exec|proc_open)\s*\(/i'
    ];
    
    // Pola JavaScript berbahaya
    $js_patterns = [
        '/eval\s*\(\s*atob\s*\(\s*["\']([a-zA-Z0-9+\/=]+)/i',
        '/document\.write\s*\(\s*unescape\s*\(\s*["\']%/i',
        '/new Function\s*\(\s*["\']([a-zA-Z0-9+\/=]+)/i',
        '/XMLHttpRequest\s*\(\s*["\']POST["\']/i'
    ];
    
    // Deteksi PHP
    foreach ($php_patterns as $pattern) {
        if (preg_match($pattern, $content)) {
            $score += 50;
        }
    }
    
    // Deteksi JavaScript
    foreach ($js_patterns as $pattern) {
        if (preg_match($pattern, $content)) {
            $score += 50;
        }
    }
    
    // Deteksi string base64 panjang
    if (preg_match('/[a-zA-Z0-9+\/=]{100,}/', $content)) {
        $score += 30;
    }
    
    return $score >= 50;
    }

    private function behavioral_analysis($file_path) {
        $suspicious_actions = 0;
        
        // Baca konten untuk analisis statis
        $content = file_get_contents($file_path);
        
        // Deteksi akses database langsung
        if (preg_match('/\$wpdb->query\([^\)]*\)/', $content)) {
            $suspicious_actions++;
        }
        
        // Deteksi file system modification
        if (preg_match('/fopen\(|file_put_contents\(|chmod\(/', $content)) {
            $suspicious_actions++;
        }
        
        // Deteksi koneksi eksternal
        if (preg_match('/fsockopen\(|curl_exec\(/', $content)) {
            $suspicious_actions++;
        }
        
        return $suspicious_actions > 1;
    }
    
    private function detect_malicious_js($content) {
    $dangerous_js_patterns = [
        '/eval\s*\(.*atob\s*\(/i',
        '/document\.write\s*\(.*unescape\s*\(/i',
        '/new Function\s*\(.*decodeURIComponent\s*\(/i',
        '/XMLHttpRequest\s*\(\s*["\']POST["\']/i',
        '/\.src\s*=\s*["\']data:text\/javascript;base64/i'
    ];
    
    foreach ($dangerous_js_patterns as $pattern) {
        if (preg_match($pattern, $content)) {
            return true;
        }
    }
    return false;
    }

    private function check_file_integrity($file_path) {
    // Untuk file core WordPress
    if (strpos($file_path, ABSPATH . 'wp-admin/') !== false || 
        strpos($file_path, ABSPATH . 'wp-includes/') !== false) {
        
        $relative_path = str_replace(ABSPATH, '', $file_path);
        $api_url = 'https://api.wordpress.org/core/checksums/1.0/?version=' . get_bloginfo('version');
        
        $response = wp_remote_get($api_url);
        $checksums = json_decode(wp_remote_retrieve_body($response), true);
        
        if (isset($checksums['checksums'][$relative_path])) {
            $official_hash = $checksums['checksums'][$relative_path];
            $current_hash = md5_file($file_path);
            
            return $official_hash === $current_hash;
        }
    }

    return true; // Skip untuk file non-core
    }

    private function security_status() {
        $status = [];
        if (!empty($this->options['disable_comments'])) $status[] = 'Komentar Dinonaktifkan';
        if (!empty($this->options['disable_xmlrpc'])) $status[] = 'XML-RPC Dinonaktifkan';
        return $status ? implode(', ', $status) : 'Kemanan Website Anda';
    }

    public static function activate() {
        flush_rewrite_rules();
    }

    public static function deactivate() {
        flush_rewrite_rules();
    }
}

new SecurityCalvPoint();

register_activation_hook(__FILE__, array('SecurityCalvPoint', 'activate'));
register_deactivation_hook(__FILE__, array('SecurityCalvPoint', 'deactivate'));
?>