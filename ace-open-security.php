<?php
/**
 * Plugin Name: Ace Open Security
 * Description: Comprehensive WordPress security and site management plugin with modern SaaS-style dashboard
 * Version: 3.0
 * Author: Mohamed Houssem Eddine SAIGHI - Claude 4.5 - GLM 4.6
 * Author URI: https://mhoussemsaighi.page.gd/
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: ace-open-security
 */

if (!defined('ABSPATH')) {
    exit;
}

class AceOpenSecurity {
    private $db_version = '1.0';
    private $table_prefix;
    private $login_attempts_table;
    private $security_log_table;
    private $ip_blacklist_table;
    private $file_integrity_table;
    private $error_404_table;
    
    public function __construct() {
        global $wpdb;
        $this->table_prefix = $wpdb->prefix . 'aos_';
        $this->login_attempts_table = $this->table_prefix . 'login_attempts';
        $this->security_log_table = $this->table_prefix . 'security_log';
        $this->ip_blacklist_table = $this->table_prefix . 'ip_blacklist';
        $this->file_integrity_table = $this->table_prefix . 'file_integrity';
        $this->error_404_table = $this->table_prefix . '404_log';
        
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
        
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('init', array($this, 'init_security_features'));
        add_action('wp_login_failed', array($this, 'log_failed_login'));
        add_action('template_redirect', array($this, 'track_404_errors'));
        add_action('aos_daily_tasks', array($this, 'run_daily_tasks'));
        add_filter('login_url', array($this, 'custom_login_url'), 10, 3);
        add_action('login_head', array($this, 'add_math_captcha'));
        add_filter('authenticate', array($this, 'verify_math_captcha'), 30, 3);
        add_action('wp_loaded', array($this, 'check_custom_login_url'));
    }
    
    public function activate() {
        $this->create_tables();
        $this->set_default_options();
        $this->schedule_cron_jobs();
        $this->scan_core_files();
        flush_rewrite_rules();
    }
    
    public function deactivate() {
        wp_clear_scheduled_hook('aos_daily_tasks');
        flush_rewrite_rules();
    }
    
    private function create_tables() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        
        $sql = "CREATE TABLE IF NOT EXISTS {$this->login_attempts_table} (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(100) NOT NULL,
            username varchar(255) NOT NULL,
            attempt_time datetime NOT NULL,
            success tinyint(1) DEFAULT 0,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY attempt_time (attempt_time)
        ) $charset_collate;";
        dbDelta($sql);
        
        $sql = "CREATE TABLE IF NOT EXISTS {$this->security_log_table} (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            event_type varchar(100) NOT NULL,
            description text NOT NULL,
            ip_address varchar(100),
            user_id bigint(20),
            severity varchar(20) DEFAULT 'info',
            created_at datetime NOT NULL,
            PRIMARY KEY (id),
            KEY event_type (event_type),
            KEY created_at (created_at)
        ) $charset_collate;";
        dbDelta($sql);
        
        $sql = "CREATE TABLE IF NOT EXISTS {$this->ip_blacklist_table} (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(100) NOT NULL,
            reason text,
            blocked_at datetime NOT NULL,
            expires_at datetime,
            PRIMARY KEY (id),
            UNIQUE KEY ip_address (ip_address)
        ) $charset_collate;";
        dbDelta($sql);
        
        $sql = "CREATE TABLE IF NOT EXISTS {$this->file_integrity_table} (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            file_path text NOT NULL,
            file_hash varchar(64) NOT NULL,
            last_checked datetime NOT NULL,
            PRIMARY KEY (id)
        ) $charset_collate;";
        dbDelta($sql);
        
        $sql = "CREATE TABLE IF NOT EXISTS {$this->error_404_table} (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(100) NOT NULL,
            requested_url text NOT NULL,
            user_agent text,
            referer text,
            created_at datetime NOT NULL,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY created_at (created_at)
        ) $charset_collate;";
        dbDelta($sql);
    }
    
    private function set_default_options() {
        $defaults = array(
            'aos_login_attempts' => 5,
            'aos_lockout_duration' => 30,
            'aos_enable_math_captcha' => 1,
            'aos_custom_login_url' => '',
            'aos_disable_user_enum' => 1,
            'aos_session_timeout' => 30,
            'aos_enable_rate_limit' => 1,
            'aos_rate_limit_requests' => 100,
            'aos_rate_limit_period' => 60,
            'aos_block_xmlrpc' => 1,
            'aos_block_trace' => 1,
            'aos_disable_file_editor' => 1,
            'aos_enable_hotlink_protection' => 1,
            'aos_auto_optimize_db' => 1,
            'aos_disable_rss' => 0,
            'aos_lockdown_rest_api' => 1,
            'aos_disable_right_click' => 0,
            'aos_enable_iframe_protection' => 1,
            'aos_404_threshold' => 20,
            'aos_404_block_duration' => 60,
            'aos_enable_security_headers' => 1,
            'aos_hide_wp_version' => 1,
            'aos_theme' => 'light'
        );
        
        foreach ($defaults as $key => $value) {
            if (get_option($key) === false) {
                add_option($key, $value);
            }
        }
    }
    
    private function schedule_cron_jobs() {
        if (!wp_next_scheduled('aos_daily_tasks')) {
            wp_schedule_event(time(), 'daily', 'aos_daily_tasks');
        }
    }
    
    public function run_daily_tasks() {
        if (get_option('aos_auto_optimize_db')) {
            $this->optimize_database();
        }
        $this->scan_core_files();
        $this->cleanup_old_logs();
    }
    
    private function optimize_database() {
        global $wpdb;
        $tables = $wpdb->get_results('SHOW TABLES', ARRAY_N);
        foreach ($tables as $table) {
            $wpdb->query("OPTIMIZE TABLE {$table[0]}");
        }
        $this->log_security_event('database_optimization', 'Database optimized successfully', 'info');
    }
    
    private function cleanup_old_logs() {
        global $wpdb;
        $date_limit = date('Y-m-d H:i:s', strtotime('-30 days'));
        $wpdb->query($wpdb->prepare("DELETE FROM {$this->login_attempts_table} WHERE attempt_time < %s", $date_limit));
        $wpdb->query($wpdb->prepare("DELETE FROM {$this->security_log_table} WHERE created_at < %s", $date_limit));
        $wpdb->query($wpdb->prepare("DELETE FROM {$this->error_404_table} WHERE created_at < %s", $date_limit));
    }
    
    public function add_admin_menu() {
        add_menu_page(
            __('Ace Open Security', 'ace-open-security'),
            __('Security', 'ace-open-security'),
            'manage_options',
            'ace-open-security',
            array($this, 'render_dashboard'),
            'dashicons-shield',
            3
        );
        
        add_submenu_page(
            'ace-open-security',
            __('Dashboard', 'ace-open-security'),
            __('Dashboard', 'ace-open-security'),
            'manage_options',
            'ace-open-security',
            array($this, 'render_dashboard')
        );
        
        add_submenu_page(
            'ace-open-security',
            __('Settings', 'ace-open-security'),
            __('Settings', 'ace-open-security'),
            'manage_options',
            'ace-open-security-settings',
            array($this, 'render_settings')
        );
        
        add_submenu_page(
            'ace-open-security',
            __('Firewall', 'ace-open-security'),
            __('Firewall', 'ace-open-security'),
            'manage_options',
            'ace-open-security-firewall',
            array($this, 'render_firewall')
        );
        
        add_submenu_page(
            'ace-open-security',
            __('IP Management', 'ace-open-security'),
            __('IP Management', 'ace-open-security'),
            'manage_options',
            'ace-open-security-ips',
            array($this, 'render_ip_management')
        );
        
        add_submenu_page(
            'ace-open-security',
            __('Security Logs', 'ace-open-security'),
            __('Security Logs', 'ace-open-security'),
            'manage_options',
            'ace-open-security-logs',
            array($this, 'render_logs')
        );
        
        add_submenu_page(
            'ace-open-security',
            __('File Security', 'ace-open-security'),
            __('File Security', 'ace-open-security'),
            'manage_options',
            'ace-open-security-files',
            array($this, 'render_file_security')
        );
    }
    
    public function register_settings() {
        register_setting('aos_settings', 'aos_login_attempts');
        register_setting('aos_settings', 'aos_lockout_duration');
        register_setting('aos_settings', 'aos_enable_math_captcha');
        register_setting('aos_settings', 'aos_custom_login_url');
        register_setting('aos_settings', 'aos_disable_user_enum');
        register_setting('aos_settings', 'aos_session_timeout');
        register_setting('aos_settings', 'aos_enable_rate_limit');
        register_setting('aos_settings', 'aos_rate_limit_requests');
        register_setting('aos_settings', 'aos_rate_limit_period');
        register_setting('aos_settings', 'aos_block_xmlrpc');
        register_setting('aos_settings', 'aos_block_trace');
        register_setting('aos_settings', 'aos_disable_file_editor');
        register_setting('aos_settings', 'aos_enable_hotlink_protection');
        register_setting('aos_settings', 'aos_auto_optimize_db');
        register_setting('aos_settings', 'aos_disable_rss');
        register_setting('aos_settings', 'aos_lockdown_rest_api');
        register_setting('aos_settings', 'aos_disable_right_click');
        register_setting('aos_settings', 'aos_enable_iframe_protection');
        register_setting('aos_settings', 'aos_404_threshold');
        register_setting('aos_settings', 'aos_404_block_duration');
        register_setting('aos_settings', 'aos_enable_security_headers');
        register_setting('aos_settings', 'aos_hide_wp_version');
        register_setting('aos_settings', 'aos_theme');
    }
    
    public function init_security_features() {
        $this->check_ip_blacklist();
        $this->implement_waf();
        $this->disable_user_enumeration();
        $this->block_xmlrpc();
        $this->disable_file_editor();
        $this->protect_against_hotlinking();
        $this->disable_rss_feeds();
        $this->lockdown_rest_api();
        $this->implement_security_headers();
        $this->hide_wp_version();
        $this->check_session_timeout();
    }
    
    private function check_ip_blacklist() {
        global $wpdb;
        $ip = $this->get_client_ip();
        $blocked = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$this->ip_blacklist_table} WHERE ip_address = %s AND (expires_at IS NULL OR expires_at > NOW())",
            $ip
        ));
        
        if ($blocked) {
            wp_die(__('Your IP address has been blocked due to suspicious activity.', 'ace-open-security'), 403);
        }
    }
    
    private function implement_waf() {
        if (!get_option('aos_enable_rate_limit')) {
            return;
        }
        
        $ip = $this->get_client_ip();
        $rate_limit = get_option('aos_rate_limit_requests', 100);
        $period = get_option('aos_rate_limit_period', 60);
        
        $transient_key = 'aos_rate_' . md5($ip);
        $requests = get_transient($transient_key);
        
        if ($requests === false) {
            set_transient($transient_key, 1, $period);
        } else {
            if ($requests >= $rate_limit) {
                $this->log_security_event('rate_limit_exceeded', "Rate limit exceeded for IP: $ip", 'warning');
                wp_die(__('Too many requests. Please try again later.', 'ace-open-security'), 429);
            }
            set_transient($transient_key, $requests + 1, $period);
        }
        
        if (get_option('aos_block_trace')) {
            $method = $_SERVER['REQUEST_METHOD'];
            if (in_array($method, array('TRACE', 'TRACK', 'DELETE'))) {
                $this->log_security_event('suspicious_method', "Blocked $method request from IP: $ip", 'warning');
                wp_die(__('Method not allowed.', 'ace-open-security'), 405);
            }
        }
    }
    
    private function disable_user_enumeration() {
        if (!get_option('aos_disable_user_enum')) {
            return;
        }
        
        if (is_admin()) {
            return;
        }
        
        if (isset($_GET['author']) && !is_user_logged_in()) {
            wp_redirect(home_url());
            exit;
        }
        
        add_filter('rest_endpoints', function($endpoints) {
            if (isset($endpoints['/wp/v2/users'])) {
                unset($endpoints['/wp/v2/users']);
            }
            if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
                unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
            }
            return $endpoints;
        });
    }
    
    private function block_xmlrpc() {
        if (get_option('aos_block_xmlrpc')) {
            add_filter('xmlrpc_enabled', '__return_false');
        }
    }
    
    private function disable_file_editor() {
        if (get_option('aos_disable_file_editor')) {
            if (!defined('DISALLOW_FILE_EDIT')) {
                define('DISALLOW_FILE_EDIT', true);
            }
        }
    }
    
    private function protect_against_hotlinking() {
        if (!get_option('aos_enable_hotlink_protection')) {
            return;
        }
        
        add_action('template_redirect', function() {
            $referer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
            $site_url = site_url();
            
            if (!empty($referer) && strpos($referer, $site_url) === false) {
                $request_uri = $_SERVER['REQUEST_URI'];
                if (preg_match('/\.(jpg|jpeg|png|gif|webp)$/i', $request_uri)) {
                    wp_die(__('Hotlinking is not allowed.', 'ace-open-security'), 403);
                }
            }
        });
    }
    
    private function disable_rss_feeds() {
        if (get_option('aos_disable_rss')) {
            add_action('do_feed', array($this, 'disable_feed'), 1);
            add_action('do_feed_rdf', array($this, 'disable_feed'), 1);
            add_action('do_feed_rss', array($this, 'disable_feed'), 1);
            add_action('do_feed_rss2', array($this, 'disable_feed'), 1);
            add_action('do_feed_atom', array($this, 'disable_feed'), 1);
        }
    }
    
    public function disable_feed() {
        wp_die(__('RSS feeds are disabled on this site.', 'ace-open-security'));
    }
    
    private function lockdown_rest_api() {
        if (!get_option('aos_lockdown_rest_api')) {
            return;
        }
        
        add_filter('rest_authentication_errors', function($result) {
            if (!is_user_logged_in()) {
                return new WP_Error('rest_disabled', __('REST API is disabled for non-authenticated users.', 'ace-open-security'), array('status' => 401));
            }
            return $result;
        });
    }
    
    private function implement_security_headers() {
        if (!get_option('aos_enable_security_headers')) {
            return;
        }
        
        add_action('send_headers', function() {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
            header('X-Frame-Options: SAMEORIGIN');
            header('X-Content-Type-Options: nosniff');
            header('X-XSS-Protection: 1; mode=block');
            header('Referrer-Policy: strict-origin-when-cross-origin');
            header("Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval' https:; img-src 'self' data: https:; font-src 'self' data: https:;");
        });
        
        if (get_option('aos_enable_iframe_protection')) {
            remove_action('wp_head', 'wp_oembed_add_discovery_links');
            remove_action('wp_head', 'wp_oembed_add_host_js');
        }
    }
    
    private function hide_wp_version() {
        if (get_option('aos_hide_wp_version')) {
            remove_action('wp_head', 'wp_generator');
            add_filter('the_generator', '__return_empty_string');
        }
    }
    
    private function check_session_timeout() {
        if (!is_user_logged_in()) {
            return;
        }
        
        // Skip timeout check on login page and AJAX requests
        if (defined('DOING_AJAX') && DOING_AJAX) {
            return;
        }
        
        if (isset($GLOBALS['pagenow']) && $GLOBALS['pagenow'] === 'wp-login.php') {
            return;
        }
        
        $timeout = get_option('aos_session_timeout', 30) * 60;
        $last_activity = get_user_meta(get_current_user_id(), 'aos_last_activity', true);
        
        // If no last activity is set, initialize it instead of logging out
        if (!$last_activity) {
            update_user_meta(get_current_user_id(), 'aos_last_activity', time());
            return;
        }
        
        if ((time() - $last_activity) > $timeout) {
            // Clear the last activity before logout to prevent loops
            delete_user_meta(get_current_user_id(), 'aos_last_activity');
            wp_logout();
            wp_redirect(wp_login_url() . '?session_expired=1');
            exit;
        }
        
        update_user_meta(get_current_user_id(), 'aos_last_activity', time());
    }
    
    public function log_failed_login($username) {
        global $wpdb;
        $ip = $this->get_client_ip();
        
        $wpdb->insert($this->login_attempts_table, array(
            'ip_address' => $ip,
            'username' => sanitize_text_field($username),
            'attempt_time' => current_time('mysql'),
            'success' => 0
        ));
        
        $max_attempts = get_option('aos_login_attempts', 5);
        $lockout_duration = get_option('aos_lockout_duration', 30);
        $time_limit = date('Y-m-d H:i:s', strtotime("-{$lockout_duration} minutes"));
        
        $attempts = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->login_attempts_table} WHERE ip_address = %s AND attempt_time > %s AND success = 0",
            $ip, $time_limit
        ));
        
        if ($attempts >= $max_attempts) {
            $expires_at = date('Y-m-d H:i:s', strtotime("+{$lockout_duration} minutes"));
            $wpdb->replace($this->ip_blacklist_table, array(
                'ip_address' => $ip,
                'reason' => 'Too many failed login attempts',
                'blocked_at' => current_time('mysql'),
                'expires_at' => $expires_at
            ));
            $this->log_security_event('ip_blocked', "IP $ip blocked due to multiple failed login attempts", 'warning');
        }
    }
    
    public function track_404_errors() {
        if (!is_404()) {
            return;
        }
        
        global $wpdb;
        $ip = $this->get_client_ip();
        
        $wpdb->insert($this->error_404_table, array(
            'ip_address' => $ip,
            'requested_url' => esc_url_raw($_SERVER['REQUEST_URI']),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? substr(sanitize_text_field($_SERVER['HTTP_USER_AGENT']), 0, 255) : '',
            'referer' => isset($_SERVER['HTTP_REFERER']) ? esc_url_raw($_SERVER['HTTP_REFERER']) : '',
            'created_at' => current_time('mysql')
        ));
        
        $threshold = get_option('aos_404_threshold', 20);
        $block_duration = get_option('aos_404_block_duration', 60);
        $time_limit = date('Y-m-d H:i:s', strtotime("-{$block_duration} minutes"));
        
        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->error_404_table} WHERE ip_address = %s AND created_at > %s",
            $ip, $time_limit
        ));
        
        if ($count >= $threshold) {
            $expires_at = date('Y-m-d H:i:s', strtotime("+{$block_duration} minutes"));
            $wpdb->replace($this->ip_blacklist_table, array(
                'ip_address' => $ip,
                'reason' => 'Excessive 404 errors',
                'blocked_at' => current_time('mysql'),
                'expires_at' => $expires_at
            ));
            $this->log_security_event('ip_blocked', "IP $ip blocked due to excessive 404 errors", 'warning');
        }
    }
    
    public function custom_login_url($login_url, $redirect, $force_reauth) {
        $custom_url = get_option('aos_custom_login_url');
        if (!empty($custom_url)) {
            $login_url = home_url('/' . $custom_url);
            if (!empty($redirect)) {
                $login_url = add_query_arg('redirect_to', urlencode($redirect), $login_url);
            }
        }
        return $login_url;
    }
    
    public function check_custom_login_url() {
        $custom_url = get_option('aos_custom_login_url');
        if (empty($custom_url)) {
            return;
        }
        
        // Parse the request URI to get just the path
        $request_uri = trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');
        $custom_path = trim($custom_url, '/');
        
        // If accessing custom login URL, load wp-login.php
        if ($request_uri === $custom_path) {
            require_once(ABSPATH . 'wp-login.php');
            exit;
        }
        
        // Block direct access to wp-login.php (except logout and some essential actions)
        if (isset($GLOBALS['pagenow']) && in_array($GLOBALS['pagenow'], array('wp-login.php'))) {
            $allowed_actions = array('logout', 'lostpassword', 'resetpass', 'rp', 'register');
            if (!isset($_GET['action']) || !in_array($_GET['action'], $allowed_actions)) {
                wp_redirect(home_url());
                exit;
            }
        }
    }
    
    public function add_math_captcha() {
        if (!get_option('aos_enable_math_captcha')) {
            return;
        }
        
        $num1 = rand(1, 10);
        $num2 = rand(1, 10);
        $answer = $num1 + $num2;
        
        setcookie('aos_captcha_answer', $answer, time() + 300, COOKIEPATH, COOKIE_DOMAIN);
        
        echo '<style>
            .aos-captcha-field { margin-bottom: 16px; }
            .aos-captcha-field label { display: block; margin-bottom: 4px; font-weight: 600; }
            .aos-captcha-field input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        </style>';
        
        echo '<div class="aos-captcha-field">';
        echo '<label for="aos_captcha">' . sprintf(__('Security Question: What is %d + %d?', 'ace-open-security'), $num1, $num2) . '</label>';
        echo '<input type="text" name="aos_captcha" id="aos_captcha" required />';
        echo '</div>';
    }
    
    public function verify_math_captcha($user, $username, $password) {
        if (!get_option('aos_enable_math_captcha')) {
            return $user;
        }
        
        if (isset($_POST['aos_captcha']) && isset($_COOKIE['aos_captcha_answer'])) {
            $user_answer = intval($_POST['aos_captcha']);
            $correct_answer = intval($_COOKIE['aos_captcha_answer']);
            
            if ($user_answer !== $correct_answer) {
                return new WP_Error('captcha_failed', __('Incorrect answer to security question.', 'ace-open-security'));
            }
        }
        
        return $user;
    }
    
    private function scan_core_files() {
        $core_files = array(
            ABSPATH . 'wp-config.php',
            ABSPATH . 'wp-settings.php',
            ABSPATH . 'wp-load.php',
            ABSPATH . 'index.php'
        );
        
        global $wpdb;
        
        foreach ($core_files as $file) {
            if (file_exists($file)) {
                $hash = hash_file('sha256', $file);
                $existing = $wpdb->get_var($wpdb->prepare(
                    "SELECT file_hash FROM {$this->file_integrity_table} WHERE file_path = %s",
                    $file
                ));
                
                if ($existing && $existing !== $hash) {
                    $this->log_security_event('file_modified', "Core file modified: $file", 'critical');
                }
                
                $wpdb->replace($this->file_integrity_table, array(
                    'file_path' => $file,
                    'file_hash' => $hash,
                    'last_checked' => current_time('mysql')
                ));
            }
        }
    }
    
    private function log_security_event($event_type, $description, $severity = 'info') {
        global $wpdb;
        $wpdb->insert($this->security_log_table, array(
            'event_type' => sanitize_text_field($event_type),
            'description' => sanitize_text_field($description),
            'ip_address' => $this->get_client_ip(),
            'user_id' => get_current_user_id(),
            'severity' => sanitize_text_field($severity),
            'created_at' => current_time('mysql')
        ));
    }
    
    private function get_client_ip() {
        $ip_keys = array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR');
        
        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                        return $ip;
                    }
                }
            }
        }
        
        return '0.0.0.0';
    }
    
    private function calculate_security_score() {
        $score = 0;
        $max_score = 100;
        
        if (get_option('aos_login_attempts') <= 5) $score += 10;
        if (get_option('aos_enable_math_captcha')) $score += 10;
        if (!empty(get_option('aos_custom_login_url'))) $score += 8;
        if (get_option('aos_disable_user_enum')) $score += 7;
        if (get_option('aos_session_timeout') <= 30) $score += 5;
        if (get_option('aos_enable_rate_limit')) $score += 10;
        if (get_option('aos_block_xmlrpc')) $score += 8;
        if (get_option('aos_block_trace')) $score += 5;
        if (get_option('aos_disable_file_editor')) $score += 10;
        if (get_option('aos_enable_hotlink_protection')) $score += 5;
        if (get_option('aos_auto_optimize_db')) $score += 5;
        if (get_option('aos_lockdown_rest_api')) $score += 7;
        if (get_option('aos_enable_security_headers')) $score += 10;
        
        return min($score, $max_score);
    }
    
    private function get_recent_events($limit = 10) {
        global $wpdb;
        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$this->security_log_table} ORDER BY created_at DESC LIMIT %d",
            $limit
        ));
    }
    
    public function render_dashboard() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        if (isset($_POST['aos_toggle_theme']) && check_admin_referer('aos_toggle_theme')) {
            $current_theme = get_option('aos_theme', 'light');
            $new_theme = $current_theme === 'light' ? 'dark' : 'light';
            update_option('aos_theme', $new_theme);
        }
        
        $theme = get_option('aos_theme', 'light');
        $security_score = $this->calculate_security_score();
        $recent_events = $this->get_recent_events(10);
        
        global $wpdb;
        $total_blocked_ips = $wpdb->get_var("SELECT COUNT(*) FROM {$this->ip_blacklist_table}");
        $failed_logins_today = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->login_attempts_table} WHERE success = 0 AND attempt_time > %s",
            date('Y-m-d 00:00:00')
        ));
        $total_404_today = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->error_404_table} WHERE created_at > %s",
            date('Y-m-d 00:00:00')
        ));
        
        ?>
        <div class="wrap aos-dashboard" data-theme="<?php echo esc_attr($theme); ?>">
            <?php $this->render_styles(); ?>
            
            <div class="aos-header">
                <div class="aos-header-content">
                    <div>
                        <h1><?php _e('Security Dashboard', 'ace-open-security'); ?></h1>
                        <p class="aos-subtitle"><?php _e('Monitor and manage your site security', 'ace-open-security'); ?></p>
                    </div>
                    <form method="post" style="margin: 0;">
                        <?php wp_nonce_field('aos_toggle_theme'); ?>
                        <button type="submit" name="aos_toggle_theme" class="aos-theme-toggle" title="<?php _e('Toggle theme', 'ace-open-security'); ?>">
                            <span class="aos-icon"><?php echo $theme === 'light' ? '🌙' : '☀️'; ?></span>
                        </button>
                    </form>
                </div>
            </div>
            
            <div class="aos-stats-grid">
                <div class="aos-stat-card">
                    <div class="aos-stat-icon" style="background: var(--color-bg-1);">🛡️</div>
                    <div class="aos-stat-content">
                        <div class="aos-stat-label"><?php _e('Security Score', 'ace-open-security'); ?></div>
                        <div class="aos-stat-value"><?php echo esc_html($security_score); ?>/100</div>
                    </div>
                    <div class="aos-progress-ring">
                        <svg width="80" height="80">
                            <circle cx="40" cy="40" r="36" fill="none" stroke="var(--color-border)" stroke-width="6"/>
                            <circle cx="40" cy="40" r="36" fill="none" stroke="var(--color-primary)" stroke-width="6"
                                stroke-dasharray="<?php echo 2 * pi() * 36; ?>"
                                stroke-dashoffset="<?php echo 2 * pi() * 36 * (1 - $security_score / 100); ?>"
                                transform="rotate(-90 40 40)" stroke-linecap="round"/>
                        </svg>
                    </div>
                </div>
                
                <div class="aos-stat-card">
                    <div class="aos-stat-icon" style="background: var(--color-bg-4);">🚫</div>
                    <div class="aos-stat-content">
                        <div class="aos-stat-label"><?php _e('Blocked IPs', 'ace-open-security'); ?></div>
                        <div class="aos-stat-value"><?php echo esc_html($total_blocked_ips); ?></div>
                    </div>
                </div>
                
                <div class="aos-stat-card">
                    <div class="aos-stat-icon" style="background: var(--color-bg-2);">🔒</div>
                    <div class="aos-stat-content">
                        <div class="aos-stat-label"><?php _e('Failed Logins Today', 'ace-open-security'); ?></div>
                        <div class="aos-stat-value"><?php echo esc_html($failed_logins_today); ?></div>
                    </div>
                </div>
                
                <div class="aos-stat-card">
                    <div class="aos-stat-icon" style="background: var(--color-bg-5);">❌</div>
                    <div class="aos-stat-content">
                        <div class="aos-stat-label"><?php _e('404 Errors Today', 'ace-open-security'); ?></div>
                        <div class="aos-stat-value"><?php echo esc_html($total_404_today); ?></div>
                    </div>
                </div>
            </div>
            
            <div class="aos-grid">
                <div class="aos-card aos-card-large">
                    <div class="aos-card-header">
                        <h2><?php _e('Recent Security Events', 'ace-open-security'); ?></h2>
                        <span class="aos-badge aos-badge-info"><?php echo count($recent_events); ?> <?php _e('events', 'ace-open-security'); ?></span>
                    </div>
                    <div class="aos-card-body">
                        <?php if (empty($recent_events)): ?>
                            <p class="aos-empty-state"><?php _e('No security events recorded yet.', 'ace-open-security'); ?></p>
                        <?php else: ?>
                            <div class="aos-table-container">
                                <table class="aos-table">
                                    <thead>
                                        <tr>
                                            <th><?php _e('Time', 'ace-open-security'); ?></th>
                                            <th><?php _e('Event', 'ace-open-security'); ?></th>
                                            <th><?php _e('Description', 'ace-open-security'); ?></th>
                                            <th><?php _e('IP Address', 'ace-open-security'); ?></th>
                                            <th><?php _e('Severity', 'ace-open-security'); ?></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($recent_events as $event): ?>
                                            <tr>
                                                <td><?php echo esc_html(date('M j, H:i', strtotime($event->created_at))); ?></td>
                                                <td><code><?php echo esc_html($event->event_type); ?></code></td>
                                                <td><?php echo esc_html($event->description); ?></td>
                                                <td><code><?php echo esc_html($event->ip_address); ?></code></td>
                                                <td>
                                                    <?php
                                                    $badge_class = 'aos-badge-info';
                                                    if ($event->severity === 'warning') $badge_class = 'aos-badge-warning';
                                                    if ($event->severity === 'critical') $badge_class = 'aos-badge-error';
                                                    if ($event->severity === 'info') $badge_class = 'aos-badge-success';
                                                    ?>
                                                    <span class="aos-badge <?php echo $badge_class; ?>"><?php echo esc_html($event->severity); ?></span>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div class="aos-card">
                    <div class="aos-card-header">
                        <h2><?php _e('Security Recommendations', 'ace-open-security'); ?></h2>
                    </div>
                    <div class="aos-card-body">
                        <div class="aos-recommendations">
                            <?php if ($security_score >= 90): ?>
                                <div class="aos-recommendation aos-recommendation-success">
                                    <span class="aos-rec-icon">✅</span>
                                    <div>
                                        <strong><?php _e('Excellent Security', 'ace-open-security'); ?></strong>
                                        <p><?php _e('Your site has strong security measures in place.', 'ace-open-security'); ?></p>
                                    </div>
                                </div>
                            <?php endif; ?>
                            
                            <?php if (empty(get_option('aos_custom_login_url'))): ?>
                                <div class="aos-recommendation aos-recommendation-warning">
                                    <span class="aos-rec-icon">⚠️</span>
                                    <div>
                                        <strong><?php _e('Set Custom Login URL', 'ace-open-security'); ?></strong>
                                        <p><?php _e('Hide your login page from bots by using a custom URL.', 'ace-open-security'); ?></p>
                                    </div>
                                </div>
                            <?php endif; ?>
                            
                            <?php if (!get_option('aos_enable_math_captcha')): ?>
                                <div class="aos-recommendation aos-recommendation-warning">
                                    <span class="aos-rec-icon">🔢</span>
                                    <div>
                                        <strong><?php _e('Enable Math CAPTCHA', 'ace-open-security'); ?></strong>
                                        <p><?php _e('Add an extra layer of bot protection to your login form.', 'ace-open-security'); ?></p>
                                    </div>
                                </div>
                            <?php endif; ?>
                            
                            <?php if (!get_option('aos_enable_security_headers')): ?>
                                <div class="aos-recommendation aos-recommendation-error">
                                    <span class="aos-rec-icon">🛡️</span>
                                    <div>
                                        <strong><?php _e('Enable Security Headers', 'ace-open-security'); ?></strong>
                                        <p><?php _e('Protect against common web vulnerabilities with HTTP security headers.', 'ace-open-security'); ?></p>
                                    </div>
                                </div>
                            <?php endif; ?>
                            
                            <?php if (get_option('aos_login_attempts') > 5): ?>
                                <div class="aos-recommendation aos-recommendation-warning">
                                    <span class="aos-rec-icon">🔐</span>
                                    <div>
                                        <strong><?php _e('Reduce Login Attempts', 'ace-open-security'); ?></strong>
                                        <p><?php _e('Lower the maximum login attempts to 5 or less for better security.', 'ace-open-security'); ?></p>
                                    </div>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }
    
    public function render_settings() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        if (isset($_POST['aos_save_settings']) && check_admin_referer('aos_settings_nonce')) {
            $fields = array(
                'aos_login_attempts', 'aos_lockout_duration', 'aos_enable_math_captcha',
                'aos_custom_login_url', 'aos_disable_user_enum', 'aos_session_timeout',
                'aos_enable_rate_limit', 'aos_rate_limit_requests', 'aos_rate_limit_period',
                'aos_block_xmlrpc', 'aos_block_trace', 'aos_disable_file_editor',
                'aos_enable_hotlink_protection', 'aos_auto_optimize_db', 'aos_disable_rss',
                'aos_lockdown_rest_api', 'aos_disable_right_click', 'aos_enable_iframe_protection',
                'aos_404_threshold', 'aos_404_block_duration', 'aos_enable_security_headers',
                'aos_hide_wp_version'
            );
            
            foreach ($fields as $field) {
                if (isset($_POST[$field])) {
                    $value = $_POST[$field];
                    if ($field === 'aos_custom_login_url') {
                        $value = sanitize_text_field($value);
                    } else {
                        $value = intval($value);
                    }
                    update_option($field, $value);
                } else {
                    update_option($field, 0);
                }
            }
            
            echo '<div class="aos-notice aos-notice-success">' . __('Settings saved successfully!', 'ace-open-security') . '</div>';
        }
        
        $theme = get_option('aos_theme', 'light');
        ?>
        <div class="wrap aos-dashboard" data-theme="<?php echo esc_attr($theme); ?>">
            <?php $this->render_styles(); ?>
            
            <div class="aos-header">
                <div class="aos-header-content">
                    <div>
                        <h1><?php _e('Security Settings', 'ace-open-security'); ?></h1>
                        <p class="aos-subtitle"><?php _e('Configure security features for your site', 'ace-open-security'); ?></p>
                    </div>
                </div>
            </div>
            
            <form method="post" action="">
                <?php wp_nonce_field('aos_settings_nonce'); ?>
                
                <div class="aos-tabs">
                    <div class="aos-tab-nav">
                        <button type="button" class="aos-tab-button active" data-tab="login"><?php _e('Login Security', 'ace-open-security'); ?></button>
                        <button type="button" class="aos-tab-button" data-tab="firewall"><?php _e('Firewall', 'ace-open-security'); ?></button>
                        <button type="button" class="aos-tab-button" data-tab="files"><?php _e('File Security', 'ace-open-security'); ?></button>
                        <button type="button" class="aos-tab-button" data-tab="content"><?php _e('Content Protection', 'ace-open-security'); ?></button>
                        <button type="button" class="aos-tab-button" data-tab="advanced"><?php _e('Advanced', 'ace-open-security'); ?></button>
                    </div>
                    
                    <div class="aos-tab-content active" data-tab="login">
                        <div class="aos-card">
                            <div class="aos-card-header">
                                <h2><?php _e('Login Protection', 'ace-open-security'); ?></h2>
                            </div>
                            <div class="aos-card-body">
                                <div class="aos-form-group">
                                    <label for="aos_login_attempts"><?php _e('Maximum Login Attempts', 'ace-open-security'); ?></label>
                                    <input type="number" name="aos_login_attempts" id="aos_login_attempts" value="<?php echo esc_attr(get_option('aos_login_attempts', 5)); ?>" min="1" max="20" />
                                    <p class="aos-help-text"><?php _e('Number of failed login attempts before blocking IP', 'ace-open-security'); ?></p>
                                </div>
                                
                                <div class="aos-form-group">
                                    <label for="aos_lockout_duration"><?php _e('Lockout Duration (minutes)', 'ace-open-security'); ?></label>
                                    <input type="number" name="aos_lockout_duration" id="aos_lockout_duration" value="<?php echo esc_attr(get_option('aos_lockout_duration', 30)); ?>" min="5" max="1440" />
                                    <p class="aos-help-text"><?php _e('How long to block an IP after exceeding login attempts', 'ace-open-security'); ?></p>
                                </div>
                                
                                <div class="aos-form-group">
                                    <label class="aos-toggle">
										<input type="checkbox" name="aos_enable_math_captcha" value="1" <?php checked(get_option('aos_enable_math_captcha'), 1); ?> />
										<span class="aos-toggle-label"><?php _e('Enable Math CAPTCHA', 'ace-open-security'); ?></span>
									</label>
                                    <p class="aos-help-text"><?php _e('Add a simple math challenge to the login form', 'ace-open-security'); ?></p>
                                </div>
                                
                                <div class="aos-form-group">
                                    <label for="aos_custom_login_url"><?php _e('Custom Login URL', 'ace-open-security'); ?></label>
                                    <input type="text" name="aos_custom_login_url" id="aos_custom_login_url" value="<?php echo esc_attr(get_option('aos_custom_login_url', '')); ?>" placeholder="my-secret-login" />
                                    <p class="aos-help-text"><?php _e('Change your login URL from /wp-login.php to something custom (e.g., my-secret-login)', 'ace-open-security'); ?></p>
                                </div>
                                
                                <div class="aos-form-group">
                                    <label class="aos-toggle">
                                        <input type="checkbox" name="aos_disable_user_enum" value="1" <?php checked(get_option('aos_disable_user_enum'), 1); ?> />
                                        <span class="aos-toggle-label"><?php _e('Prevent User Enumeration', 'ace-open-security'); ?></span>
                                    </label>
                                    <p class="aos-help-text"><?php _e('Block attempts to discover usernames', 'ace-open-security'); ?></p>
                                </div>
                                
                                <div class="aos-form-group">
                                    <label for="aos_session_timeout"><?php _e('Session Timeout (minutes)', 'ace-open-security'); ?></label>
                                    <input type="number" name="aos_session_timeout" id="aos_session_timeout" value="<?php echo esc_attr(get_option('aos_session_timeout', 30)); ?>" min="5" max="1440" />
                                    <p class="aos-help-text"><?php _e('Auto-logout users after period of inactivity', 'ace-open-security'); ?></p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="aos-tab-content" data-tab="firewall">
                        <div class="aos-card">
                            <div class="aos-card-header">
                                <h2><?php _e('Web Application Firewall', 'ace-open-security'); ?></h2>
                            </div>
                            <div class="aos-card-body">
                                <div class="aos-form-group">
                                    <label class="aos-toggle">
                                        <input type="checkbox" name="aos_enable_rate_limit" value="1" <?php checked(get_option('aos_enable_rate_limit'), 1); ?> />
                                        <span class="aos-toggle-label"><?php _e('Enable Rate Limiting', 'ace-open-security'); ?></span>
                                    </label>
                                    <p class="aos-help-text"><?php _e('Limit requests per IP to prevent abuse', 'ace-open-security'); ?></p>
                                </div>
                                
                                <div class="aos-form-group">
                                    <label for="aos_rate_limit_requests"><?php _e('Max Requests', 'ace-open-security'); ?></label>
                                    <input type="number" name="aos_rate_limit_requests" id="aos_rate_limit_requests" value="<?php echo esc_attr(get_option('aos_rate_limit_requests', 100)); ?>" min="10" max="1000" />
                                    <p class="aos-help-text"><?php _e('Maximum requests allowed per period', 'ace-open-security'); ?></p>
                                </div>
                                
                                <div class="aos-form-group">
                                    <label for="aos_rate_limit_period"><?php _e('Period (seconds)', 'ace-open-security'); ?></label>
                                    <input type="number" name="aos_rate_limit_period" id="aos_rate_limit_period" value="<?php echo esc_attr(get_option('aos_rate_limit_period', 60)); ?>" min="10" max="3600" />
                                    <p class="aos-help-text"><?php _e('Time window for rate limiting', 'ace-open-security'); ?></p>
                                </div>
                                
                                <div class="aos-form-group">
                                    <label class="aos-toggle">
                                        <input type="checkbox" name="aos_block_xmlrpc" value="1" <?php checked(get_option('aos_block_xmlrpc'), 1); ?> />
                                        <span class="aos-toggle-label"><?php _e('Block XML-RPC', 'ace-open-security'); ?></span>
                                    </label>
                                    <p class="aos-help-text"><?php _e('Disable XML-RPC to prevent brute force attacks', 'ace-open-security'); ?></p>
                                </div>
                                
                                <div class="aos-form-group">
                                    <label class="aos-toggle">
                                        <input type="checkbox" name="aos_block_trace" value="1" <?php checked(get_option('aos_block_trace'), 1); ?> />
                                        <span class="aos-toggle-label"><?php _e('Block Suspicious HTTP Methods', 'ace-open-security'); ?></span>
                                    </label>
                                    <p class="aos-help-text"><?php _e('Block TRACE, TRACK, and DELETE methods', 'ace-open-security'); ?></p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="aos-tab-content" data-tab="files">
                        <div class="aos-card">
                            <div class="aos-card-header">
                                <h2><?php _e('File Security', 'ace-open-security'); ?></h2>
                            </div>
                            <div class="aos-card-body">
                                <div class="aos-form-group">
                                    <label class="aos-toggle">
                                        <input type="checkbox" name="aos_disable_file_editor" value="1" <?php checked(get_option('aos_disable_file_editor'), 1); ?> />
                                        <span class="aos-toggle-label"><?php _e('Disable Theme/Plugin Editor', 'ace-open-security'); ?></span>
                                    </label>
                                    <p class="aos-help-text"><?php _e('Prevent editing files from WordPress admin', 'ace-open-security'); ?></p>
                                </div>
                                
                                <div class="aos-form-group">
                                    <label class="aos-toggle">
                                        <input type="checkbox" name="aos_enable_hotlink_protection" value="1" <?php checked(get_option('aos_enable_hotlink_protection'), 1); ?> />
                                        <span class="aos-toggle-label"><?php _e('Enable Hotlink Protection', 'ace-open-security'); ?></span>
                                    </label>
                                    <p class="aos-help-text"><?php _e('Prevent other sites from embedding your images', 'ace-open-security'); ?></p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="aos-tab-content" data-tab="content">
                        <div class="aos-card">
                            <div class="aos-card-header">
                                <h2><?php _e('Content Protection', 'ace-open-security'); ?></h2>
                            </div>
                            <div class="aos-card-body">
                                <div class="aos-form-group">
                                    <label class="aos-toggle">
                                        <input type="checkbox" name="aos_disable_rss" value="1" <?php checked(get_option('aos_disable_rss'), 1); ?> />
                                        <span class="aos-toggle-label"><?php _e('Disable RSS Feeds', 'ace-open-security'); ?></span>
                                    </label>
                                    <p class="aos-help-text"><?php _e('Completely disable RSS/Atom feeds', 'ace-open-security'); ?></p>
                                </div>
                                
                                <div class="aos-form-group">
                                    <label class="aos-toggle">
                                        <input type="checkbox" name="aos_lockdown_rest_api" value="1" <?php checked(get_option('aos_lockdown_rest_api'), 1); ?> />
                                        <span class="aos-toggle-label"><?php _e('Lockdown REST API', 'ace-open-security'); ?></span>
                                    </label>
                                    <p class="aos-help-text"><?php _e('Require authentication for REST API access', 'ace-open-security'); ?></p>
                                </div>
                                
                                <div class="aos-form-group">
                                    <label class="aos-toggle">
                                        <input type="checkbox" name="aos_disable_right_click" value="1" <?php checked(get_option('aos_disable_right_click'), 1); ?> />
                                        <span class="aos-toggle-label"><?php _e('Disable Right-Click', 'ace-open-security'); ?></span>
                                    </label>
                                    <p class="aos-help-text"><?php _e('Prevent right-click context menu (basic protection)', 'ace-open-security'); ?></p>
                                </div>
                                
                                <div class="aos-form-group">
                                    <label class="aos-toggle">
                                        <input type="checkbox" name="aos_enable_iframe_protection" value="1" <?php checked(get_option('aos_enable_iframe_protection'), 1); ?> />
                                        <span class="aos-toggle-label"><?php _e('Enable Iframe Protection', 'ace-open-security'); ?></span>
                                    </label>
                                    <p class="aos-help-text"><?php _e('Prevent your site from being embedded in iframes', 'ace-open-security'); ?></p>
                                </div>
                                
                                <div class="aos-form-group">
                                    <label for="aos_404_threshold"><?php _e('404 Error Threshold', 'ace-open-security'); ?></label>
                                    <input type="number" name="aos_404_threshold" id="aos_404_threshold" value="<?php echo esc_attr(get_option('aos_404_threshold', 20)); ?>" min="5" max="100" />
                                    <p class="aos-help-text"><?php _e('Number of 404 errors before blocking IP', 'ace-open-security'); ?></p>
                                </div>
                                
                                <div class="aos-form-group">
                                    <label for="aos_404_block_duration"><?php _e('404 Block Duration (minutes)', 'ace-open-security'); ?></label>
                                    <input type="number" name="aos_404_block_duration" id="aos_404_block_duration" value="<?php echo esc_attr(get_option('aos_404_block_duration', 60)); ?>" min="10" max="1440" />
                                    <p class="aos-help-text"><?php _e('How long to block IPs with excessive 404 errors', 'ace-open-security'); ?></p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="aos-tab-content" data-tab="advanced">
                        <div class="aos-card">
                            <div class="aos-card-header">
                                <h2><?php _e('Advanced Settings', 'ace-open-security'); ?></h2>
                            </div>
                            <div class="aos-card-body">
                                <div class="aos-form-group">
                                    <label class="aos-toggle">
                                        <input type="checkbox" name="aos_enable_security_headers" value="1" <?php checked(get_option('aos_enable_security_headers'), 1); ?> />
                                        <span class="aos-toggle-label"><?php _e('Enable Security Headers', 'ace-open-security'); ?></span>
                                    </label>
                                    <p class="aos-help-text"><?php _e('Add HSTS, X-Frame-Options, CSP, and other security headers', 'ace-open-security'); ?></p>
                                </div>
                                
                                <div class="aos-form-group">
                                    <label class="aos-toggle">
                                        <input type="checkbox" name="aos_hide_wp_version" value="1" <?php checked(get_option('aos_hide_wp_version'), 1); ?> />
                                        <span class="aos-toggle-label"><?php _e('Hide WordPress Version', 'ace-open-security'); ?></span>
                                    </label>
                                    <p class="aos-help-text"><?php _e('Remove WordPress version from HTML source', 'ace-open-security'); ?></p>
                                </div>
                                
                                <div class="aos-form-group">
                                    <label class="aos-toggle">
                                        <input type="checkbox" name="aos_auto_optimize_db" value="1" <?php checked(get_option('aos_auto_optimize_db'), 1); ?> />
                                        <span class="aos-toggle-label"><?php _e('Auto-Optimize Database', 'ace-open-security'); ?></span>
                                    </label>
                                    <p class="aos-help-text"><?php _e('Automatically optimize database tables daily', 'ace-open-security'); ?></p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="aos-card aos-submit-card">
                    <button type="submit" name="aos_save_settings" class="aos-btn aos-btn-primary">
                        <?php _e('Save All Settings', 'ace-open-security'); ?>
                    </button>
                </div>
            </form>
        </div>
        
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                const tabButtons = document.querySelectorAll('.aos-tab-button');
                const tabContents = document.querySelectorAll('.aos-tab-content');
                
                tabButtons.forEach(button => {
                    button.addEventListener('click', function() {
                        const targetTab = this.dataset.tab;
                        
                        tabButtons.forEach(btn => btn.classList.remove('active'));
                        tabContents.forEach(content => content.classList.remove('active'));
                        
                        this.classList.add('active');
                        document.querySelector(`.aos-tab-content[data-tab="${targetTab}"]`).classList.add('active');
                    });
                });
            });
        </script>
        <?php
    }
    
    public function render_firewall() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        $theme = get_option('aos_theme', 'light');
        global $wpdb;
        
        $rate_limit_enabled = get_option('aos_enable_rate_limit');
        $xmlrpc_blocked = get_option('aos_block_xmlrpc');
        $methods_blocked = get_option('aos_block_trace');
        
        $blocked_today = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->security_log_table} WHERE event_type = %s AND created_at > %s",
            'rate_limit_exceeded',
            date('Y-m-d 00:00:00')
        ));
        
        ?>
        <div class="wrap aos-dashboard" data-theme="<?php echo esc_attr($theme); ?>">
            <?php $this->render_styles(); ?>
            
            <div class="aos-header">
                <div class="aos-header-content">
                    <div>
                        <h1><?php _e('Web Application Firewall', 'ace-open-security'); ?></h1>
                        <p class="aos-subtitle"><?php _e('Monitor and manage firewall protection', 'ace-open-security'); ?></p>
                    </div>
                </div>
            </div>
            
            <div class="aos-stats-grid">
                <div class="aos-stat-card">
                    <div class="aos-stat-icon" style="background: var(--color-bg-1);">🛡️</div>
                    <div class="aos-stat-content">
                        <div class="aos-stat-label"><?php _e('Rate Limiting', 'ace-open-security'); ?></div>
                        <div class="aos-stat-value"><?php echo $rate_limit_enabled ? __('Active', 'ace-open-security') : __('Inactive', 'ace-open-security'); ?></div>
                    </div>
                </div>
                
                <div class="aos-stat-card">
                    <div class="aos-stat-icon" style="background: var(--color-bg-4);">🚫</div>
                    <div class="aos-stat-content">
                        <div class="aos-stat-label"><?php _e('Blocked Today', 'ace-open-security'); ?></div>
                        <div class="aos-stat-value"><?php echo esc_html($blocked_today); ?></div>
                    </div>
                </div>
                
                <div class="aos-stat-card">
                    <div class="aos-stat-icon" style="background: var(--color-bg-2);">📡</div>
                    <div class="aos-stat-content">
                        <div class="aos-stat-label"><?php _e('XML-RPC', 'ace-open-security'); ?></div>
                        <div class="aos-stat-value"><?php echo $xmlrpc_blocked ? __('Blocked', 'ace-open-security') : __('Allowed', 'ace-open-security'); ?></div>
                    </div>
                </div>
                
                <div class="aos-stat-card">
                    <div class="aos-stat-icon" style="background: var(--color-bg-5);">🔒</div>
                    <div class="aos-stat-content">
                        <div class="aos-stat-label"><?php _e('HTTP Methods', 'ace-open-security'); ?></div>
                        <div class="aos-stat-value"><?php echo $methods_blocked ? __('Protected', 'ace-open-security') : __('Open', 'ace-open-security'); ?></div>
                    </div>
                </div>
            </div>
            
            <div class="aos-card">
                <div class="aos-card-header">
                    <h2><?php _e('Firewall Configuration', 'ace-open-security'); ?></h2>
                </div>
                <div class="aos-card-body">
                    <p><?php _e('Configure your firewall settings in the', 'ace-open-security'); ?> <a href="<?php echo admin_url('admin.php?page=ace-open-security-settings'); ?>"><?php _e('Settings page', 'ace-open-security'); ?></a>.</p>
                    
                    <div class="aos-firewall-status">
                        <div class="aos-status-item">
                            <span class="aos-status-label"><?php _e('Rate Limiting:', 'ace-open-security'); ?></span>
                            <span class="aos-badge <?php echo $rate_limit_enabled ? 'aos-badge-success' : 'aos-badge-error'; ?>">
                                <?php echo $rate_limit_enabled ? __('Enabled', 'ace-open-security') : __('Disabled', 'ace-open-security'); ?>
                            </span>
                        </div>
                        
                        <div class="aos-status-item">
                            <span class="aos-status-label"><?php _e('XML-RPC Protection:', 'ace-open-security'); ?></span>
                            <span class="aos-badge <?php echo $xmlrpc_blocked ? 'aos-badge-success' : 'aos-badge-error'; ?>">
                                <?php echo $xmlrpc_blocked ? __('Enabled', 'ace-open-security') : __('Disabled', 'ace-open-security'); ?>
                            </span>
                        </div>
                        
                        <div class="aos-status-item">
                            <span class="aos-status-label"><?php _e('HTTP Method Protection:', 'ace-open-security'); ?></span>
                            <span class="aos-badge <?php echo $methods_blocked ? 'aos-badge-success' : 'aos-badge-error'; ?>">
                                <?php echo $methods_blocked ? __('Enabled', 'ace-open-security') : __('Disabled', 'ace-open-security'); ?>
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }
    
    public function render_ip_management() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        global $wpdb;
        
        if (isset($_POST['aos_unblock_ip']) && check_admin_referer('aos_unblock_ip')) {
            $ip = sanitize_text_field($_POST['ip_address']);
            $wpdb->delete($this->ip_blacklist_table, array('ip_address' => $ip));
            echo '<div class="aos-notice aos-notice-success">' . sprintf(__('IP %s has been unblocked.', 'ace-open-security'), esc_html($ip)) . '</div>';
        }
        
        if (isset($_POST['aos_block_ip']) && check_admin_referer('aos_block_ip')) {
            $ip = sanitize_text_field($_POST['new_ip_address']);
            $reason = sanitize_text_field($_POST['block_reason']);
            
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $wpdb->replace($this->ip_blacklist_table, array(
                    'ip_address' => $ip,
                    'reason' => $reason,
                    'blocked_at' => current_time('mysql')
                ));
                echo '<div class="aos-notice aos-notice-success">' . sprintf(__('IP %s has been blocked.', 'ace-open-security'), esc_html($ip)) . '</div>';
            } else {
                echo '<div class="aos-notice aos-notice-error">' . __('Invalid IP address.', 'ace-open-security') . '</div>';
            }
        }
        
        $theme = get_option('aos_theme', 'light');
        $blocked_ips = $wpdb->get_results("SELECT * FROM {$this->ip_blacklist_table} ORDER BY blocked_at DESC");
        
        ?>
        <div class="wrap aos-dashboard" data-theme="<?php echo esc_attr($theme); ?>">
            <?php $this->render_styles(); ?>
            
            <div class="aos-header">
                <div class="aos-header-content">
                    <div>
                        <h1><?php _e('IP Management', 'ace-open-security'); ?></h1>
                        <p class="aos-subtitle"><?php _e('Manage blocked IP addresses', 'ace-open-security'); ?></p>
                    </div>
                </div>
            </div>
            
            <div class="aos-card">
                <div class="aos-card-header">
                    <h2><?php _e('Block New IP Address', 'ace-open-security'); ?></h2>
                </div>
                <div class="aos-card-body">
                    <form method="post" action="">
                        <?php wp_nonce_field('aos_block_ip'); ?>
                        <div class="aos-form-row">
                            <div class="aos-form-group">
                                <label for="new_ip_address"><?php _e('IP Address', 'ace-open-security'); ?></label>
                                <input type="text" name="new_ip_address" id="new_ip_address" placeholder="192.168.1.1" required />
                            </div>
                            <div class="aos-form-group">
                                <label for="block_reason"><?php _e('Reason', 'ace-open-security'); ?></label>
                                <input type="text" name="block_reason" id="block_reason" placeholder="Manual block" required />
                            </div>
                            <div class="aos-form-group">
                                <label>&nbsp;</label>
                                <button type="submit" name="aos_block_ip" class="aos-btn aos-btn-primary"><?php _e('Block IP', 'ace-open-security'); ?></button>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
            
            <div class="aos-card">
                <div class="aos-card-header">
                    <h2><?php _e('Blocked IP Addresses', 'ace-open-security'); ?></h2>
                    <span class="aos-badge aos-badge-info"><?php echo count($blocked_ips); ?> <?php _e('blocked', 'ace-open-security'); ?></span>
                </div>
                <div class="aos-card-body">
                    <?php if (empty($blocked_ips)): ?>
                        <p class="aos-empty-state"><?php _e('No IP addresses are currently blocked.', 'ace-open-security'); ?></p>
                    <?php else: ?>
                        <div class="aos-table-container">
                            <table class="aos-table">
                                <thead>
                                    <tr>
                                        <th><?php _e('IP Address', 'ace-open-security'); ?></th>
                                        <th><?php _e('Reason', 'ace-open-security'); ?></th>
                                        <th><?php _e('Blocked At', 'ace-open-security'); ?></th>
                                        <th><?php _e('Expires At', 'ace-open-security'); ?></th>
                                        <th><?php _e('Action', 'ace-open-security'); ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($blocked_ips as $ip): ?>
                                        <tr>
                                            <td><code><?php echo esc_html($ip->ip_address); ?></code></td>
                                            <td><?php echo esc_html($ip->reason); ?></td>
                                            <td><?php echo esc_html(date('M j, Y H:i', strtotime($ip->blocked_at))); ?></td>
                                            <td><?php echo $ip->expires_at ? esc_html(date('M j, Y H:i', strtotime($ip->expires_at))) : __('Permanent', 'ace-open-security'); ?></td>
                                            <td>
                                                <form method="post" action="" style="display:inline;">
                                                    <?php wp_nonce_field('aos_unblock_ip'); ?>
                                                    <input type="hidden" name="ip_address" value="<?php echo esc_attr($ip->ip_address); ?>" />
                                                    <button type="submit" name="aos_unblock_ip" class="aos-btn aos-btn-small aos-btn-danger"><?php _e('Unblock', 'ace-open-security'); ?></button>
                                                </form>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        <?php
    }
    
    public function render_logs() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        global $wpdb;
        
        if (isset($_GET['export']) && check_admin_referer('aos_export_logs', 'nonce')) {
            $logs = $wpdb->get_results("SELECT * FROM {$this->security_log_table} ORDER BY created_at DESC");
            
            header('Content-Type: text/csv');
            header('Content-Disposition: attachment; filename="security-logs-' . date('Y-m-d') . '.csv"');
            
            $output = fopen('php://output', 'w');
            fputcsv($output, array('Time', 'Event Type', 'Description', 'IP Address', 'User ID', 'Severity'));
            
            foreach ($logs as $log) {
                fputcsv($output, array(
                    $log->created_at,
                    $log->event_type,
                    $log->description,
                    $log->ip_address,
                    $log->user_id,
                    $log->severity
                ));
            }
            
            fclose($output);
            exit;
        }
        
        $theme = get_option('aos_theme', 'light');
        $per_page = 50;
        $page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
        $offset = ($page - 1) * $per_page;
        
        $total = $wpdb->get_var("SELECT COUNT(*) FROM {$this->security_log_table}");
        $logs = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$this->security_log_table} ORDER BY created_at DESC LIMIT %d OFFSET %d",
            $per_page, $offset
        ));
        
        $total_pages = ceil($total / $per_page);
        
        ?>
        <div class="wrap aos-dashboard" data-theme="<?php echo esc_attr($theme); ?>">
            <?php $this->render_styles(); ?>
            
            <div class="aos-header">
                <div class="aos-header-content">
                    <div>
                        <h1><?php _e('Security Logs', 'ace-open-security'); ?></h1>
                        <p class="aos-subtitle"><?php _e('View all security events', 'ace-open-security'); ?></p>
                    </div>
                    <a href="<?php echo wp_nonce_url(add_query_arg('export', 'csv'), 'aos_export_logs', 'nonce'); ?>" class="aos-btn aos-btn-primary">
                        <?php _e('Export to CSV', 'ace-open-security'); ?>
                    </a>
                </div>
            </div>
            
            <div class="aos-card">
                <div class="aos-card-header">
                    <h2><?php _e('Recent Events', 'ace-open-security'); ?></h2>
                    <span class="aos-badge aos-badge-info"><?php echo esc_html($total); ?> <?php _e('total', 'ace-open-security'); ?></span>
                </div>
                <div class="aos-card-body">
                    <?php if (empty($logs)): ?>
                        <p class="aos-empty-state"><?php _e('No security events recorded yet.', 'ace-open-security'); ?></p>
                    <?php else: ?>
                        <div class="aos-table-container">
                            <table class="aos-table">
                                <thead>
                                    <tr>
                                        <th><?php _e('Time', 'ace-open-security'); ?></th>
                                        <th><?php _e('Event', 'ace-open-security'); ?></th>
                                        <th><?php _e('Description', 'ace-open-security'); ?></th>
                                        <th><?php _e('IP Address', 'ace-open-security'); ?></th>
                                        <th><?php _e('Severity', 'ace-open-security'); ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($logs as $log): ?>
                                        <tr>
                                            <td><?php echo esc_html(date('M j, Y H:i:s', strtotime($log->created_at))); ?></td>
                                            <td><code><?php echo esc_html($log->event_type); ?></code></td>
                                            <td><?php echo esc_html($log->description); ?></td>
                                            <td><code><?php echo esc_html($log->ip_address); ?></code></td>
                                            <td>
                                                <?php
                                                $badge_class = 'aos-badge-info';
                                                if ($log->severity === 'warning') $badge_class = 'aos-badge-warning';
                                                if ($log->severity === 'critical') $badge_class = 'aos-badge-error';
                                                if ($log->severity === 'info') $badge_class = 'aos-badge-success';
                                                ?>
                                                <span class="aos-badge <?php echo $badge_class; ?>"><?php echo esc_html($log->severity); ?></span>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                        
                        <?php if ($total_pages > 1): ?>
                            <div class="aos-pagination">
                                <?php
                                $base_url = remove_query_arg('paged');
                                for ($i = 1; $i <= $total_pages; $i++) {
                                    $class = $i === $page ? 'active' : '';
                                    $url = add_query_arg('paged', $i, $base_url);
                                    echo '<a href="' . esc_url($url) . '" class="aos-page-link ' . $class . '">' . $i . '</a>';
                                }
                                ?>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        <?php
    }
    
    public function render_file_security() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        global $wpdb;
        
        if (isset($_POST['aos_scan_files']) && check_admin_referer('aos_scan_files')) {
            $this->scan_core_files();
            echo '<div class="aos-notice aos-notice-success">' . __('File integrity scan completed.', 'ace-open-security') . '</div>';
        }
        
        $theme = get_option('aos_theme', 'light');
        $files = $wpdb->get_results("SELECT * FROM {$this->file_integrity_table} ORDER BY last_checked DESC");
        
        ?>
        <div class="wrap aos-dashboard" data-theme="<?php echo esc_attr($theme); ?>">
            <?php $this->render_styles(); ?>
            
            <div class="aos-header">
                <div class="aos-header-content">
                    <div>
                        <h1><?php _e('File Security', 'ace-open-security'); ?></h1>
                        <p class="aos-subtitle"><?php _e('Monitor file integrity', 'ace-open-security'); ?></p>
                    </div>
                    <form method="post" action="" style="margin: 0;">
                        <?php wp_nonce_field('aos_scan_files'); ?>
                        <button type="submit" name="aos_scan_files" class="aos-btn aos-btn-primary">
                            <?php _e('Scan Files Now', 'ace-open-security'); ?>
                        </button>
                    </form>
                </div>
            </div>
            
            <div class="aos-card">
                <div class="aos-card-header">
                    <h2><?php _e('Core File Integrity', 'ace-open-security'); ?></h2>
                    <span class="aos-badge aos-badge-info"><?php echo count($files); ?> <?php _e('files monitored', 'ace-open-security'); ?></span>
                </div>
                <div class="aos-card-body">
                    <?php if (empty($files)): ?>
                        <p class="aos-empty-state"><?php _e('No files have been scanned yet. Click "Scan Files Now" to start monitoring.', 'ace-open-security'); ?></p>
                    <?php else: ?>
                        <div class="aos-table-container">
                            <table class="aos-table">
                                <thead>
                                    <tr>
                                        <th><?php _e('File Path', 'ace-open-security'); ?></th>
                                        <th><?php _e('Hash', 'ace-open-security'); ?></th>
                                        <th><?php _e('Last Checked', 'ace-open-security'); ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($files as $file): ?>
                                        <tr>
                                            <td><code><?php echo esc_html($file->file_path); ?></code></td>
                                            <td><code class="aos-hash"><?php echo esc_html(substr($file->file_hash, 0, 16)); ?>...</code></td>
                                            <td><?php echo esc_html(date('M j, Y H:i', strtotime($file->last_checked))); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        <?php
    }
    
    private function render_styles() {
        ?>
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        
        :root {
            /* Modern Color Palette */
            --color-white: #ffffff;
            --color-gray-50: #f9fafb;
            --color-gray-100: #f3f4f6;
            --color-gray-200: #e5e7eb;
            --color-gray-300: #d1d5db;
            --color-gray-400: #9ca3af;
            --color-gray-500: #6b7280;
            --color-gray-600: #4b5563;
            --color-gray-700: #374151;
            --color-gray-800: #1f2937;
            --color-gray-900: #111827;
            
            /* Accent Colors */
            --color-blue-50: #eff6ff;
            --color-blue-100: #dbeafe;
            --color-blue-200: #bfdbfe;
            --color-blue-300: #93c5fd;
            --color-blue-400: #60a5fa;
            --color-blue-500: #3b82f6;
            --color-blue-600: #2563eb;
            --color-blue-700: #1d4ed8;
            --color-blue-800: #1e40af;
            --color-blue-900: #1e3a8a;
            
            --color-green-50: #f0fdf4;
            --color-green-100: #dcfce7;
            --color-green-200: #bbf7d0;
            --color-green-300: #86efac;
            --color-green-400: #4ade80;
            --color-green-500: #22c55e;
            --color-green-600: #16a34a;
            --color-green-700: #15803d;
            --color-green-800: #166534;
            --color-green-900: #14532d;
            
            --color-red-50: #fef2f2;
            --color-red-100: #fee2e2;
            --color-red-200: #fecaca;
            --color-red-300: #fca5a5;
            --color-red-400: #f87171;
            --color-red-500: #ef4444;
            --color-red-600: #dc2626;
            --color-red-700: #b91c1c;
            --color-red-800: #991b1b;
            --color-red-900: #7f1d1d;
            
            --color-yellow-50: #fefce8;
            --color-yellow-100: #fef3c7;
            --color-yellow-200: #fde68a;
            --color-yellow-300: #fcd34d;
            --color-yellow-400: #fbbf24;
            --color-yellow-500: #eab308;
            --color-yellow-600: #ca8a04;
            --color-yellow-700: #a16207;
            --color-yellow-800: #854d0e;
            --color-yellow-900: #713f12;
            
            --color-purple-50: #faf5ff;
            --color-purple-100: #f3e8ff;
            --color-purple-200: #e9d5ff;
            --color-purple-300: #d8b4fe;
            --color-purple-400: #c084fc;
            --color-purple-500: #a855f7;
            --color-purple-600: #9333ea;
            --color-purple-700: #7c3aed;
            --color-purple-800: #6b21a8;
            --color-purple-900: #581c87;
            
            /* Typography */
            --font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            
            /* Light Theme */
            --bg-primary: var(--color-white);
            --bg-secondary: var(--color-gray-50);
            --bg-tertiary: var(--color-gray-100);
            --text-primary: var(--color-gray-900);
            --text-secondary: var(--color-gray-600);
            --text-tertiary: var(--color-gray-500);
            --border-primary: var(--color-gray-200);
            --border-secondary: var(--color-gray-300);
            --surface-primary: var(--color-white);
            --surface-secondary: var(--color-gray-50);
            --surface-tertiary: var(--color-gray-100);
            --accent-primary: var(--color-blue-600);
            --accent-hover: var(--color-blue-700);
            --accent-active: var(--color-blue-800);
            
            /* Semantic Colors */
            --color-success: var(--color-green-600);
            --color-success-bg: var(--color-green-50);
            --color-success-border: var(--color-green-200);
            --color-error: var(--color-red-600);
            --color-error-bg: var(--color-red-50);
            --color-error-border: var(--color-red-200);
            --color-warning: var(--color-yellow-600);
            --color-warning-bg: var(--color-yellow-50);
            --color-warning-border: var(--color-yellow-200);
            --color-info: var(--color-blue-600);
            --color-info-bg: var(--color-blue-50);
            --color-info-border: var(--color-blue-200);
            
            /* Background Colors for Stats */
            --color-bg-1: var(--color-blue-50);
            --color-bg-2: var(--color-green-50);
            --color-bg-3: var(--color-yellow-50);
            --color-bg-4: var(--color-red-50);
            --color-bg-5: var(--color-purple-50);
            
            /* Shadows */
            --shadow-xs: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-sm: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
            --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);
            --shadow-2xl: 0 25px 50px -12px rgb(0 0 0 / 0.25);
            
            /* Layout Variables */
            --border-radius-sm: 6px;
            --border-radius: 8px;
            --border-radius-lg: 12px;
            --border-radius-xl: 16px;
            --spacing-xs: 4px;
            --spacing-sm: 8px;
            --spacing: 16px;
            --spacing-lg: 24px;
            --spacing-xl: 32px;
            --spacing-2xl: 48px;
            
            /* Transitions */
            --transition-fast: 150ms ease;
            --transition: 200ms ease;
            --transition-slow: 300ms ease;
        }
        
        [data-theme="dark"] {
            /* Dark Theme Colors */
            --bg-primary: var(--color-gray-900);
            --bg-secondary: var(--color-gray-800);
            --bg-tertiary: var(--color-gray-700);
            --text-primary: var(--color-gray-100);
            --text-secondary: var(--color-gray-400);
            --text-tertiary: var(--color-gray-500);
            --border-primary: var(--color-gray-700);
            --border-secondary: var(--color-gray-600);
            --surface-primary: var(--color-gray-800);
            --surface-secondary: var(--color-gray-700);
            --surface-tertiary: var(--color-gray-600);
            --accent-primary: var(--color-blue-500);
            --accent-hover: var(--color-blue-400);
            --accent-active: var(--color-blue-300);
            
            /* Darker shadows */
            --shadow-xs: 0 1px 2px 0 rgb(0 0 0 / 0.3);
            --shadow-sm: 0 1px 3px 0 rgb(0 0 0 / 0.4), 0 1px 2px -1px rgb(0 0 0 / 0.4);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.4), 0 2px 4px -2px rgb(0 0 0 / 0.4);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.4), 0 4px 6px -4px rgb(0 0 0 / 0.4);
            --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.4), 0 8px 10px -6px rgb(0 0 0 / 0.4);
            --shadow-2xl: 0 25px 50px -12px rgb(0 0 0 / 0.5);
            
            /* Darker background colors for stats */
            --color-bg-1: var(--color-blue-900);
            --color-bg-2: var(--color-green-900);
            --color-bg-3: var(--color-yellow-900);
            --color-bg-4: var(--color-red-900);
            --color-bg-5: var(--color-purple-900);
        }
        
        /* Base Reset & Setup */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        .aos-dashboard {
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            font-family: var(--font-family);
            font-weight: 400;
            line-height: 1.6;
            position: relative;
            overflow-x: hidden;
        }
        
        /* Header */
        .aos-header {
            background: var(--surface-primary);
            border-bottom: 1px solid var(--border-primary);
            padding: var(--spacing-xl) var(--spacing-2xl);
            margin-bottom: var(--spacing-xl);
            position: sticky;
            top: 0;
            z-index: 100;
            backdrop-filter: blur(10px);
            background: rgba(var(--surface-primary), 0.95);
        }
        
        .aos-header-content {
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: var(--spacing);
        }
        
        .aos-header h1 {
            font-size: clamp(28px, 4vw, 36px);
            font-weight: 700;
            font-family: var(--font-family);
            color: var(--text-primary);
            letter-spacing: -0.025em;
            margin-bottom: var(--spacing-xs);
        }
        
        .aos-subtitle {
            color: var(--text-secondary);
            font-size: 15px;
            font-family: var(--font-family);
            font-weight: 400;
        }
        
        .aos-theme-toggle {
            background: var(--surface-secondary);
            border: 1px solid var(--border-primary);
            padding: var(--spacing-sm) var(--spacing);
            border-radius: var(--border-radius-lg);
            cursor: pointer;
            transition: all var(--transition);
            font-family: var(--font-family);
            font-weight: 500;
            min-width: 60px;
            box-shadow: var(--shadow-sm);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .aos-theme-toggle:hover {
            background: var(--accent-primary);
            color: var(--color-white);
            border-color: var(--accent-primary);
            box-shadow: var(--shadow-md);
            transform: translateY(-2px);
        }
        
        .aos-theme-toggle:active {
            transform: translateY(0);
            box-shadow: var(--shadow-sm);
        }
        
        .aos-icon {
            font-size: 20px;
            display: block;
        }
        
        /* Stats Grid */
        .aos-stats-grid {
            max-width: 1400px;
            margin: 0 auto var(--spacing-xl);
            padding: 0 var(--spacing-xl);
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: var(--spacing);
        }
        
        .aos-stat-card {
            background: var(--surface-primary);
            border: 1px solid var(--border-primary);
            border-radius: var(--border-radius-lg);
            padding: var(--spacing-lg);
            display: flex;
            align-items: center;
            gap: var(--spacing);
            position: relative;
            transition: all var(--transition);
            box-shadow: var(--shadow-sm);
            overflow: hidden;
        }
        
        .aos-stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--accent-primary), var(--color-purple-500));
            opacity: 0;
            transition: opacity var(--transition);
        }
        
        .aos-stat-card:hover {
            box-shadow: var(--shadow-lg);
            transform: translateY(-4px);
            border-color: var(--accent-primary);
        }
        
        .aos-stat-card:hover::before {
            opacity: 1;
        }
        
        .aos-stat-icon {
            width: 56px;
            height: 56px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            font-weight: 400;
            flex-shrink: 0;
            border-radius: var(--border-radius-lg);
            box-shadow: var(--shadow-sm);
        }
        
        .aos-stat-content {
            flex: 1;
        }
        
        .aos-stat-label {
            font-size: 14px;
            color: var(--text-secondary);
            margin-bottom: var(--spacing-xs);
            font-family: var(--font-family);
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .aos-stat-value {
            font-size: 32px;
            font-weight: 700;
            font-family: var(--font-family);
            color: var(--text-primary);
            line-height: 1;
        }
        
        .aos-progress-ring {
            position: absolute;
            right: var(--spacing);
            top: 50%;
            transform: translateY(-50%);
        }
        
        .aos-progress-ring circle:last-child {
            stroke: var(--accent-primary) !important;
            stroke-width: 4 !important;
            transition: stroke-dashoffset 0.5s ease;
        }
        
        /* Grid Layout */
        .aos-grid {
            max-width: 1400px;
            margin: 0 auto var(--spacing-xl);
            padding: 0 var(--spacing-xl);
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: var(--spacing);
        }
        
        /* Cards */
        .aos-card {
            background: var(--surface-primary);
            border: 1px solid var(--border-primary);
            border-radius: var(--border-radius-lg);
            position: relative;
            box-shadow: var(--shadow-sm);
            transition: all var(--transition);
            overflow: hidden;
        }
        
        .aos-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--accent-primary), var(--color-purple-500));
            opacity: 0;
            transition: opacity var(--transition);
        }
        
        .aos-card:hover {
            box-shadow: var(--shadow-lg);
            transform: translateY(-2px);
        }
        
        .aos-card:hover::before {
            opacity: 1;
        }
        
        .aos-card-large {
            grid-column: span 2;
        }
        
        .aos-card-header {
            padding: var(--spacing-lg);
            border-bottom: 1px solid var(--border-primary);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--surface-secondary);
        }
        
        .aos-card-header h2 {
            font-size: 18px;
            font-weight: 600;
            font-family: var(--font-family);
            color: var(--text-primary);
            letter-spacing: -0.025em;
        }
        
        .aos-card-body {
            padding: var(--spacing-lg);
        }
        
        /* Badges */
        .aos-badge {
            display: inline-flex;
            align-items: center;
            padding: var(--spacing-xs) var(--spacing-sm);
            font-size: 12px;
            font-weight: 600;
            font-family: var(--font-family);
            border-radius: var(--border-radius-sm);
            border: 1px solid transparent;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .aos-badge-success {
            background: var(--color-success-bg);
            color: var(--color-success);
            border-color: var(--color-success-border);
        }
        
        .aos-badge-error {
            background: var(--color-error-bg);
            color: var(--color-error);
            border-color: var(--color-error-border);
        }
        
        .aos-badge-warning {
            background: var(--color-warning-bg);
            color: var(--color-warning);
            border-color: var(--color-warning-border);
        }
        
        .aos-badge-info {
            background: var(--color-info-bg);
            color: var(--color-info);
            border-color: var(--color-info-border);
        }
        
        /* Tables */
        .aos-table-container {
            overflow-x: auto;
            border: 1px solid var(--border-primary);
            border-radius: var(--border-radius);
            box-shadow: var(--shadow-xs);
        }
        
        .aos-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            font-family: var(--font-family);
            font-size: 14px;
        }
        
        .aos-table th {
            text-align: left;
            padding: var(--spacing) var(--spacing-lg);
            font-weight: 600;
            color: var(--text-primary);
            background: var(--surface-secondary);
            border-bottom: 1px solid var(--border-primary);
            border-right: 1px solid var(--border-primary);
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .aos-table th:last-child {
            border-right: none;
        }
        
        .aos-table th:first-child {
            border-top-left-radius: var(--border-radius);
        }
        
        .aos-table th:last-child {
            border-top-right-radius: var(--border-radius);
        }
        
        .aos-table td {
            padding: var(--spacing) var(--spacing-lg);
            color: var(--text-primary);
            border-bottom: 1px solid var(--border-primary);
            border-right: 1px solid var(--border-primary);
            background: var(--surface-primary);
            transition: background-color var(--transition);
        }
        
        .aos-table td:last-child {
            border-right: none;
        }
        
        .aos-table tbody tr:hover td {
            background: var(--surface-secondary);
        }
        
        .aos-table tbody tr:last-child td:first-child {
            border-bottom-left-radius: var(--border-radius);
        }
        
        .aos-table tbody tr:last-child td:last-child {
            border-bottom-right-radius: var(--border-radius);
        }
        
        .aos-table code {
            background: var(--surface-tertiary);
            padding: 2px var(--spacing-xs);
            font-weight: 500;
            color: var(--accent-primary);
            border-radius: var(--border-radius-sm);
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            font-size: 12px;
        }
        
        .aos-hash {
            font-size: 11px !important;
        }
        
        /* Empty State */
        .aos-empty-state {
            text-align: center;
            padding: var(--spacing-2xl);
            color: var(--text-secondary);
            font-size: 15px;
        }
        
        /* Recommendations */
        .aos-recommendations {
            display: flex;
            flex-direction: column;
            gap: var(--spacing);
        }
        
        .aos-recommendation {
            display: flex;
            gap: var(--spacing);
            padding: var(--spacing);
            border-radius: var(--border-radius);
            border-left: 4px solid;
            transition: all var(--transition);
        }
        
        .aos-recommendation:hover {
            transform: translateX(4px);
        }
        
        .aos-recommendation-success {
            background: var(--color-success-bg);
            border-color: var(--color-success);
        }
        
        .aos-recommendation-warning {
            background: var(--color-warning-bg);
            border-color: var(--color-warning);
        }
        
        .aos-recommendation-error {
            background: var(--color-error-bg);
            border-color: var(--color-error);
        }
        
        .aos-rec-icon {
            font-size: 20px;
            flex-shrink: 0;
        }
        
        .aos-recommendation strong {
            display: block;
            margin-bottom: var(--spacing-xs);
            color: var(--text-primary);
            font-weight: 600;
        }
        
        .aos-recommendation p {
            margin: 0;
            font-size: 14px;
            color: var(--text-secondary);
            line-height: 1.5;
        }
        
        /* Buttons */
        .aos-btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: var(--spacing-sm) var(--spacing);
            font-size: 14px;
            font-weight: 500;
            font-family: var(--font-family);
            cursor: pointer;
            border: 1px solid var(--border-primary);
            background: var(--surface-primary);
            color: var(--text-primary);
            transition: all var(--transition);
            text-decoration: none;
            position: relative;
            box-shadow: var(--shadow-sm);
            border-radius: var(--border-radius);
            white-space: nowrap;
        }
        
        .aos-btn:hover {
            box-shadow: var(--shadow-md);
            transform: translateY(-2px);
            border-color: var(--accent-primary);
        }
        
        .aos-btn:active {
            transform: translateY(0);
            box-shadow: var(--shadow-sm);
        }
        
        .aos-btn-primary {
            background: var(--accent-primary);
            color: var(--color-white);
            border-color: var(--accent-primary);
        }
        
        .aos-btn-primary:hover {
            background: var(--accent-hover);
            border-color: var(--accent-hover);
        }
        
        .aos-btn-small {
            padding: var(--spacing-xs) var(--spacing-sm);
            font-size: 12px;
        }
        
        .aos-btn-danger {
            background: var(--color-error);
            color: var(--color-white);
            border-color: var(--color-error);
        }
        
        .aos-btn-danger:hover {
            background: var(--color-red-700);
            border-color: var(--color-red-700);
        }
        
        /* Tabs */
        .aos-tabs {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 var(--spacing-xl);
        }
        
        .aos-tab-nav {
            display: flex;
            gap: var(--spacing-xs);
            margin-bottom: var(--spacing);
            border-bottom: 1px solid var(--border-primary);
            overflow-x: auto;
        }
        
        .aos-tab-button {
            padding: var(--spacing) var(--spacing-lg);
            background: transparent;
            border: none;
            border-bottom: 2px solid transparent;
            color: var(--text-secondary);
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all var(--transition);
            font-family: var(--font-family);
            white-space: nowrap;
            position: relative;
        }
        
        .aos-tab-button:hover {
            color: var(--text-primary);
            background: var(--surface-secondary);
        }
        
        .aos-tab-button.active {
            color: var(--accent-primary);
            border-bottom-color: var(--accent-primary);
            background: var(--surface-secondary);
        }
        
        .aos-tab-content {
            display: none;
        }
        
        .aos-tab-content.active {
            display: block;
        }
        
        /* Form Elements */
        .aos-form-group {
            margin-bottom: var(--spacing-lg);
        }
        
        .aos-form-group label {
            display: block;
            margin-bottom: var(--spacing-xs);
            font-size: 14px;
            font-weight: 500;
            color: var(--text-primary);
            font-family: var(--font-family);
        }
        
        .aos-form-group input[type="text"],
        .aos-form-group input[type="number"] {
            width: 100%;
            padding: var(--spacing-sm) var(--spacing);
            border: 1px solid var(--border-primary);
            border-radius: var(--border-radius);
            background: var(--surface-primary);
            color: var(--text-primary);
            font-size: 14px;
            font-family: var(--font-family);
            transition: all var(--transition);
        }
        
        .aos-form-group input:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }
        
        .aos-help-text {
            margin: var(--spacing-xs) 0 0 0;
            font-size: 13px;
            color: var(--text-secondary);
            line-height: 1.4;
        }
        
        /* Checkbox Styles */
		.aos-toggle {
			display: flex;
			align-items: center;
			cursor: pointer;
			position: relative;
			padding: var(--spacing);
			border-radius: var(--border-radius);
			transition: all var(--transition);
			width: 100%;
		}

		.aos-toggle:hover {
			background: var(--surface-secondary);
		}

		.aos-toggle input[type="checkbox"] {
			width: 20px;
			height: 20px;
			margin: 0;
			margin-right: var(--spacing);
			cursor: pointer;
			accent-color: var(--accent-primary);
		}

		.aos-toggle-label {
			font-size: 14px;
			font-weight: 500;
			font-family: var(--font-family);
			color: var(--text-primary);
			line-height: 1.5;
			transition: color var(--transition);
			flex: 1;
		}

		.aos-toggle:hover .aos-toggle-label {
			color: var(--accent-primary);
		}
				
		/* Custom Checkbox Styling (Optional) */
		.aos-toggle input[type="checkbox"] {
			appearance: none;
			width: 20px;
			height: 20px;
			border: 2px solid var(--border-primary);
			border-radius: var(--border-radius-sm);
			background: var(--surface-primary);
			position: relative;
			cursor: pointer;
			transition: all var(--transition);
			margin-right: var(--spacing);
		}

		.aos-toggle input[type="checkbox"]:checked {
			background: var(--accent-primary);
			border-color: var(--accent-primary);
		}

		.aos-toggle input[type="checkbox"]:checked::after {
			content: '✓';
			position: absolute;
			top: 50%;
			left: 50%;
			transform: translate(-50%, -50%);
			color: var(--color-white);
			font-size: 14px;
			font-weight: bold;
		}	
        /* Form Row */
        .aos-form-row {
            display: grid;
            grid-template-columns: 1fr 1fr auto;
            gap: var(--spacing);
            align-items: end;
        }
        
        /* Submit Card */
        .aos-submit-card {
            margin-top: var(--spacing);
            padding: var(--spacing-lg);
            text-align: right;
            background: var(--surface-secondary);
            border-top: 1px solid var(--border-primary);
        }
        
        /* Notices */
        .aos-notice {
            max-width: 1400px;
            margin: var(--spacing) auto;
            padding: var(--spacing) var(--spacing-lg);
            border-radius: var(--border-radius);
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: var(--spacing-sm);
        }
        
        .aos-notice-success {
            background: var(--color-success-bg);
            color: var(--color-success);
            border-left: 4px solid var(--color-success);
        }
        
        .aos-notice-error {
            background: var(--color-error-bg);
            color: var(--color-error);
            border-left: 4px solid var(--color-error);
        }
        
        /* Pagination */
        .aos-pagination {
            display: flex;
            justify-content: center;
            gap: var(--spacing-xs);
            margin-top: var(--spacing);
        }
        
        .aos-page-link {
            padding: var(--spacing-sm) var(--spacing);
            border: 1px solid var(--border-primary);
            border-radius: var(--border-radius-sm);
            text-decoration: none;
            color: var(--text-primary);
            font-size: 14px;
            font-weight: 500;
            transition: all var(--transition);
        }
        
        .aos-page-link:hover {
            background: var(--surface-secondary);
            border-color: var(--accent-primary);
        }
        
        .aos-page-link.active {
            background: var(--accent-primary);
            color: var(--color-white);
            border-color: var(--accent-primary);
        }
        
        /* Firewall Status */
        .aos-firewall-status {
            display: flex;
            flex-direction: column;
            gap: var(--spacing);
            margin-top: var(--spacing);
        }
        
        .aos-status-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: var(--spacing);
            background: var(--surface-secondary);
            border-radius: var(--border-radius);
            transition: all var(--transition);
        }
        
        .aos-status-item:hover {
            background: var(--surface-tertiary);
        }
        
        .aos-status-label {
            font-weight: 500;
            color: var(--text-primary);
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--surface-secondary);
            border-radius: var(--border-radius);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--border-secondary);
            border-radius: var(--border-radius);
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--text-tertiary);
        }
        
        ::-webkit-scrollbar-corner {
            background: var(--surface-secondary);
        }
        
        /* Responsive Design */
        @media (max-width: 1024px) {
            .aos-grid {
                grid-template-columns: 1fr;
                gap: var(--spacing);
            }
            
            .aos-card-large {
                grid-column: span 1;
            }
        }
        
        @media (max-width: 768px) {
            .aos-stats-grid {
                grid-template-columns: 1fr;
                gap: var(--spacing-sm);
            }
            
            .aos-header {
                padding: var(--spacing) var(--spacing);
            }
            
            .aos-header-content {
                flex-direction: column;
                align-items: flex-start;
                gap: var(--spacing);
            }
            
            .aos-header h1 {
                font-size: 24px;
            }
            
            .aos-stat-card {
                flex-direction: column;
                text-align: center;
            }
            
            .aos-form-row {
                grid-template-columns: 1fr;
                gap: var(--spacing);
            }
            
            .aos-tab-nav {
                gap: 0;
            }
            
            .aos-tab-button {
                flex: 1;
                min-width: 0;
            }
        }
        
        /* Animations */
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .aos-card {
            animation: fadeIn 0.3s ease;
        }
        
        .aos-stat-card {
            animation: fadeIn 0.3s ease;
        }
        
        .aos-stat-card:nth-child(1) { animation-delay: 0.1s; }
        .aos-stat-card:nth-child(2) { animation-delay: 0.2s; }
        .aos-stat-card:nth-child(3) { animation-delay: 0.3s; }
        .aos-stat-card:nth-child(4) { animation-delay: 0.4s; }
        </style>
        <?php
    }
}

new AceOpenSecurity();