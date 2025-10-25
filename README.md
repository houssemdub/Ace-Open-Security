# 🛡️ Ace Open Security

<div align="center">

![Version](https://img.shields.io/badge/version-3.0-blue.svg)
![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-green.svg)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-purple.svg)
![License](https://img.shields.io/badge/license-GPL%20v2-red.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

**A comprehensive WordPress security plugin with a modern, minimal GitHub-inspired dashboard**

[Features](#-features) • [Installation](#-installation) • [Screenshots](#-screenshots) • [Configuration](#%EF%B8%8F-configuration) • [Contributing](#-contributing)

</div>

---

## 🌟 Overview

Ace Open Security is a powerful, all-in-one WordPress security plugin designed to protect your website from threats while providing an intuitive, clean interface inspired by GitHub's design principles. Built with modern security best practices, it offers enterprise-grade protection without the complexity.

## ✨ Features

### 🔐 Login Protection
- **Brute-Force Prevention** - Configurable login attempts with automatic IP blocking
- **Math CAPTCHA** - Simple bot protection without external dependencies
- **Custom Login URL** - Hide your wp-login.php from automated attacks
- **User Enumeration Blocking** - Prevent username discovery attacks
- **Session Timeout** - Automatic logout after inactivity

### 🔥 Web Application Firewall (WAF)
- **Rate Limiting** - Per-IP request throttling to prevent DDoS attacks
- **HTTP Method Filtering** - Block suspicious methods (TRACE, TRACK, DELETE)
- **XML-RPC Protection** - Disable or limit XML-RPC access
- **Real-time Threat Detection** - Monitor and block malicious activity

### 📁 File Security
- **File Integrity Monitoring** - Track changes to core WordPress files
- **Hotlink Protection** - Prevent bandwidth theft from external sites
- **Theme/Plugin Editor Disabling** - Prevent unauthorized code modifications

### 🗄️ Database Security
- **Auto-Optimization** - Daily automated database maintenance
- **SQL Injection Protection** - Built-in input sanitization
- **Secure Queries** - Prepared statements for all database operations

### 🌐 Content Protection
- **RSS Feed Control** - Option to disable RSS feeds
- **REST API Lockdown** - Require authentication for API access
- **Right-Click Protection** - Optional content copying prevention
- **Iframe Protection** - Prevent clickjacking attacks

### 📊 404 Monitoring
- **Error Tracking** - Log all 404 requests with details
- **Auto-Blocking** - Automatically block IPs after threshold
- **Pattern Detection** - Identify scanning attempts

### 🔒 Security Headers
- **HSTS** - HTTP Strict Transport Security
- **X-Frame-Options** - Clickjacking protection
- **X-Content-Type-Options** - MIME sniffing prevention
- **XSS Protection** - Cross-site scripting defense
- **Content Security Policy** - Advanced content restrictions
- **Referrer Policy** - Control referrer information leakage

### 📈 Security Dashboard
- **Real-Time Security Score** - 0-100 rating based on active features
- **Recent Events Log** - Comprehensive security event tracking
- **Actionable Recommendations** - Smart suggestions to improve security
- **Statistics Overview** - Blocked IPs, failed logins, 404 errors
- **Dark/Light Theme** - Modern, clean GitHub-inspired interface

## 📥 Installation

### Method 1: WordPress Admin (Recommended)

1. Download the latest release from [GitHub Releases](https://github.com/houssemdub/Ace-Open-Security/releases)
2. Go to **WordPress Admin** → **Plugins** → **Add New** → **Upload Plugin**
3. Choose the downloaded ZIP file and click **Install Now**
4. Click **Activate Plugin**

### Method 2: Manual Installation

1. Download the plugin files
2. Upload the `ace-open-security` folder to `/wp-content/plugins/`
3. Activate the plugin through the **Plugins** menu in WordPress

### Method 3: Git Clone

```bash
cd /path/to/wordpress/wp-content/plugins/
git clone https://github.com/houssemdub/Ace-Open-Security.git ace-open-security
```

Then activate through WordPress admin.

## 🚀 Quick Start

1. **Activate the Plugin** - Navigate to Plugins and activate Ace Open Security
2. **Access Dashboard** - Go to **Security** in your WordPress admin menu
3. **Review Settings** - Click **Settings** and configure based on your needs
4. **Monitor Security** - Check your security score and follow recommendations

## 🖼️ Screenshots

### Security Dashboard
Beautiful, clean dashboard with real-time statistics and security score visualization.

### Settings Panel
Intuitive tabbed interface for configuring all security features with helpful descriptions.

### IP Management
Manage blocked IPs, add manual blocks, and view expiration times.

### Security Logs
Detailed event logs with CSV export functionality for audit trails.

## ⚙️ Configuration

### Login Security Settings

```
Maximum Login Attempts: 5 (recommended)
Lockout Duration: 30 minutes
Math CAPTCHA: Enabled
Custom Login URL: your-secret-login (optional but recommended)
Session Timeout: 30 minutes
```

### Firewall Settings

```
Rate Limiting: Enabled
Max Requests: 100 requests per 60 seconds
Block XML-RPC: Enabled
Block Suspicious Methods: Enabled
```

### File Security

```
Disable Theme/Plugin Editor: Enabled
Hotlink Protection: Enabled
File Integrity Monitoring: Automatic daily scans
```

### Content Protection

```
Disable RSS Feeds: Optional (affects legitimate readers)
REST API Lockdown: Enabled
Iframe Protection: Enabled
404 Threshold: 20 errors before auto-block
```

### Advanced Settings

```
Security Headers: Enabled
Hide WordPress Version: Enabled
Auto-Optimize Database: Enabled
```

## 🎨 User Interface

Ace Open Security features a modern, minimal UI inspired by GitHub's design system:

- **Clean Typography** - System fonts for optimal readability
- **GitHub-Style Cards** - Familiar, comfortable design patterns
- **Color-Coded Badges** - Quick visual status identification
- **Responsive Layout** - Works perfectly on all screen sizes
- **Dark/Light Theme** - Toggle between themes with one click

## 📋 Requirements

- **WordPress**: 5.0 or higher
- **PHP**: 7.4 or higher
- **MySQL**: 5.6 or higher / MariaDB 10.0 or higher
- **Server**: Apache or Nginx

## 🔧 Technical Details

### Database Tables Created

- `wp_aos_login_attempts` - Tracks login attempts
- `wp_aos_security_log` - Security event logging
- `wp_aos_ip_blacklist` - Blocked IP addresses
- `wp_aos_file_integrity` - File hash monitoring
- `wp_aos_404_log` - 404 error tracking

### Cron Jobs

- **Daily Tasks** - Database optimization and file integrity scans
- Runs automatically every 24 hours
- Manual triggers available in admin panel

### Security Best Practices

All code follows WordPress coding standards:
- Input sanitization with `sanitize_text_field()`, `esc_url_raw()`
- Output escaping with `esc_html()`, `esc_attr()`
- Nonce verification for all forms
- Prepared SQL statements via `$wpdb->prepare()`
- Capability checks with `current_user_can()`

## 🛠️ Development

### File Structure

```
ace-open-security/
├── ace-open-security.php    # Main plugin file (single-file architecture)
└── README.md                 # This file
```

### Single-File Architecture

This plugin uses a single-file architecture for:
- **Easy installation** - One file to manage
- **No external dependencies** - All code self-contained
- **Performance** - Minimal overhead
- **Simplicity** - Easy to audit and maintain

## 🐛 Known Issues & Limitations

- Custom login URL requires permalink structure (not default `?p=123`)
- Session timeout may conflict with other authentication plugins
- Right-click protection can affect legitimate users
- Rate limiting uses WordPress transients (consider Redis for high-traffic sites)

## 🔄 Changelog

### Version 3.0 (Current)
- ✨ New GitHub-inspired minimal UI
- 🎨 Dark/light theme toggle
- 📊 Enhanced security dashboard with circular progress indicator
- 🔧 Improved firewall configuration page
- 🐛 Fixed session timeout redirect loop
- 🚀 Performance optimizations

### Version 2.0
- Added file integrity monitoring
- Implemented 404 tracking and auto-blocking
- Enhanced security headers
- Added CSV export for logs

### Version 1.0
- Initial release
- Core security features
- Basic dashboard

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the Repository**
2. **Create a Feature Branch** (`git checkout -b feature/AmazingFeature`)
3. **Commit Your Changes** (`git commit -m 'Add some AmazingFeature'`)
4. **Push to the Branch** (`git push origin feature/AmazingFeature`)
5. **Open a Pull Request**

### Contribution Guidelines

- Follow WordPress coding standards
- Test on multiple PHP versions (7.4, 8.0, 8.1, 8.2)
- Test on multiple WordPress versions (5.0+)
- Include comments for complex logic
- Update README.md if adding new features

## 📝 License

This project is licensed under the **GPL v2 or later** - see the [LICENSE](LICENSE) file for details.

```
Copyright (C) 2025 Mohamed Houssem Eddine SAIGHI

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
```

## 👨‍💻 Author

**Mohamed Houssem Eddine SAIGHI**

- Website: [mhoussemsaighi.page.gd](https://mhoussemsaighi.page.gd/)
- GitHub: [@houssemdub](https://github.com/houssemdub)

## 🙏 Acknowledgments

- Built with assistance from **Claude 3.5 Sonnet** and **GLM 4.6**
- UI inspired by GitHub's Primer design system
- Thanks to the WordPress community for security best practices

## 📞 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/houssemdub/Ace-Open-Security/issues)
- 💬 **Questions**: [GitHub Discussions](https://github.com/houssemdub/Ace-Open-Security/discussions)
- 📧 **Email**: Create an issue for support requests

## ⚠️ Disclaimer

While this plugin implements many security best practices, **no plugin can guarantee 100% security**. Always:

- Keep WordPress, themes, and plugins updated
- Use strong passwords and 2FA
- Regular backups are essential
- Monitor your site regularly
- Use HTTPS/SSL certificates
- Keep PHP and server software updated

## 🌟 Star This Repository

If you find this plugin useful, please consider giving it a star ⭐ on GitHub!

---

<div align="center">

**Made with ❤️ for the WordPress Community**

[Report Bug](https://github.com/houssemdub/Ace-Open-Security/issues) · [Request Feature](https://github.com/houssemdub/Ace-Open-Security/issues) · [View Demo](#)

</div>
