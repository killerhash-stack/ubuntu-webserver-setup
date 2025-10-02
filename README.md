Ubuntu Web Server Setup Script
A comprehensive, automated setup script for deploying production-ready web servers on Ubuntu (20.04, 22.04, 24.04+).

🚀 Features
Core Services
Nginx - High-performance web server with optimized configuration

PHP-FPM - Latest PHP with essential extensions

MariaDB/MySQL - Secure database server with user isolation

Redis - In-memory caching with ACL security

SSL/TLS - Automated Let's Encrypt certificate setup

Security & Hardening
SSH Hardening - Key-only authentication, root login disabled

UFW Firewall - Configured with essential ports only

Fail2Ban - Protection against brute force attacks

Automatic Security Updates - Unattended security patches

rkhunter - Rootkit detection and system integrity monitoring

Management & Monitoring
Cockpit - Web-based server management with plugins

Netdata - Real-time performance monitoring

File Browser - Standalone web file manager

Health Endpoint - JSON API for service status monitoring

Backup System - Automated encrypted backups with retention

Performance Optimizations
OS-level kernel optimizations

Nginx worker and connection tuning

PHP-FPM process management

MySQL/MariaDB buffer pool configuration

Redis memory and persistence settings

📋 Prerequisites
Ubuntu 20.04, 22.04, or 24.04 (recommended)

Minimum 10GB free disk space

Root/sudo access

Internet connectivity

🛠️ Installation
Quick Start
bash
# Download and run the setup script
wget https://raw.githubusercontent.com/kevinbdx35/setup-webserver/main/setup-webserver.sh
sudo bash setup-webserver.sh
Step-by-Step
Download the script

bash
wget https://raw.githubusercontent.com/kevinbdx35/setup-webserver/main/setup-webserver.sh
Make it executable

bash
chmod +x setup-webserver.sh
Run the setup

bash
sudo ./setup-webserver.sh
Follow the interactive prompts to configure:

Deploy user account

Domain name and SSL

Software components

Backup settings

Performance optimizations

🎯 Interactive Configuration
The script will guide you through:

User Setup
Create secure deploy user with sudo privileges

Set up SSH key authentication

Configure password for web console access

Domain & SSL
Primary domain name configuration

Additional domains (subdomains)

Let's Encrypt SSL certificate automation

Email for certificate

killerhash-stack/ubuntu-webserver-setup/main/setup-webserver.sh is my gethub info can you fill this in in the correct places
Ubuntu Web Server Setup Script
A comprehensive, automated setup script for deploying production-ready web servers on Ubuntu (20.04, 22.04, 24.04+).

🚀 Features
Core Services
Nginx - High-performance web server with optimized configuration

PHP-FPM - Latest PHP with essential extensions

MariaDB/MySQL - Secure database server with user isolation

Redis - In-memory caching with ACL security

SSL/TLS - Automated Let's Encrypt certificate setup

Security & Hardening
SSH Hardening - Key-only authentication, root login disabled

UFW Firewall - Configured with essential ports only

Fail2Ban - Protection against brute force attacks

Automatic Security Updates - Unattended security patches

rkhunter - Rootkit detection and system integrity monitoring

Management & Monitoring
Cockpit - Web-based server management with plugins

Netdata - Real-time performance monitoring

File Browser - Standalone web file manager

Health Endpoint - JSON API for service status monitoring

Backup System - Automated encrypted backups with retention

Performance Optimizations
OS-level kernel optimizations

Nginx worker and connection tuning

PHP-FPM process management

MySQL/MariaDB buffer pool configuration

Redis memory and persistence settings

📋 Prerequisites
Ubuntu 20.04, 22.04, or 24.04 (recommended)

Minimum 10GB free disk space

Root/sudo access

Internet connectivity

🛠️ Installation
Quick Start
bash
# Download and run the setup script
wget https://raw.githubusercontent.com/killerhash-stack/ubuntu-webserver-setup/main/setup-webserver.sh
sudo bash setup-webserver.sh
Step-by-Step
Download the script

bash
wget https://raw.githubusercontent.com/killerhash-stack/ubuntu-webserver-setup/main/setup-webserver.sh
Make it executable

bash
chmod +x setup-webserver.sh
Run the setup

bash
sudo ./setup-webserver.sh
Follow the interactive prompts to configure:

Deploy user account

Domain name and SSL

Software components

Backup settings

Performance optimizations

🎯 Interactive Configuration
The script will guide you through:

User Setup
Create secure deploy user with sudo privileges

Set up SSH key authentication

Configure password for web console access

Domain & SSL
Primary domain name configuration

Additional domains (subdomains)

Let's Encrypt SSL certificate automation

Email for certificate notifications

Software Selection
PHP & MySQL - For dynamic websites and applications

Redis - For caching and session storage

Cockpit Plugins - Enhanced web management interface

Adminer - Web-based database administration

Security Tools - Lynis, ClamAV, AIDE

Monitoring - Performance and advanced monitoring tools

Backup Configuration
Local backup encryption

Remote backup to NAS/cloud storage

Rclone cloud storage setup

Automated retention policies

🔧 Access Information
After setup, you'll have access to:

Web Interfaces
Cockpit: https://your-server-ip:9090 - Full server management

Netdata: http://your-server-ip:19999 - Real-time monitoring

File Browser: http://your-server-ip:8080 - File management

Health Endpoint: http://your-server-ip/health.php - Service status API

Adminer: http://your-server-ip/db-admin.php - Database management

SSH Access
bash
ssh deploy@your-server-ip
Important Files
Setup Log: /root/webserver-setup.log

Web Root: /var/www/html/

Nginx Config: /etc/nginx/nginx.conf

Backup Directory: /var/backups/website/

🛡️ Security Features
SSH Hardened: Key-based authentication only, root login disabled

Firewall: UFW configured with minimal open ports

Fail2Ban: Automatic IP blocking for failed login attempts

SSL/TLS: Automated Let's Encrypt certificates with auto-renewal

Service Isolation: Separate users and permissions for each service

Backup Encryption: Optional GPG encryption for backups

📊 Monitoring & Health
Health Endpoint
Access http://your-server-ip/health.php for:

Service status overview

Resource usage (CPU, memory, disk)

SSL certificate expiry

Performance metrics

Performance Monitoring
Real-time metrics via Netdata

PHP OPcache status dashboard

GoAccess web log analysis

Custom health checks

🔄 Backup System
Automated Backups
Daily: 7 days retention

Weekly: 4 weeks retention

Monthly: 3 months retention

Encryption: Optional GPG encryption

Remote: SSH-based remote backup support

Cloud: Rclone integration for cloud storage

Manual Backup
bash
sudo /usr/local/bin/backup-website.sh
🚨 Emergency Access
If locked out of SSH:

bash
sudo /usr/local/bin/emergency-access.sh
⚠️ Use with caution - temporarily enables password authentication for 10 minutes.

🛠️ Maintenance Commands
Service Management
bash
# Restart services
sudo systemctl restart nginx
sudo systemctl restart php-fpm
sudo systemctl restart mariadb

# Check status
sudo systemctl status nginx
sudo journalctl -u nginx -f
Monitoring
bash
# Check server health
curl http://localhost/health.php

# View logs
sudo tail -f /var/log/nginx/error.log
sudo tail -f /var/log/website-backup.log
Backup Management
bash
# Run manual backup
sudo /usr/local/bin/backup-website.sh

# Check backup status
sudo ls -la /var/backups/website/
🔧 Customization
Nginx Configuration
Edit /etc/nginx/nginx.conf for:

Worker processes and connections

Gzip compression settings

Client timeouts and buffers

PHP Configuration
Edit /etc/php/8.3/fpm/php.ini for:

Memory limits and execution time

File upload sizes

Error reporting and logging

Database Configuration
Edit /etc/mysql/mariadb.conf.d/99-performance.cnf for:

Buffer pool sizes

Connection limits

Query optimization

🐛 Troubleshooting
Common Issues
Nginx fails to start

Check port 80 availability: sudo netstat -tulpn | grep :80

Test configuration: sudo nginx -t

View error logs: sudo tail -f /var/log/nginx/error.log

SSL certificate issues

Verify DNS records point to server IP

Check Let's Encrypt logs: sudo journalctl -u certbot

Renew manually: sudo certbot renew

Service connectivity

Use health endpoint: curl http://localhost/health.php

Check firewall: sudo ufw status

Log Files
Setup Log: /root/webserver-setup.log

Nginx: /var/log/nginx/error.log

PHP-FPM: /var/log/php8.3-fpm.log

MariaDB: /var/log/mysql/error.log

Backups: /var/log/website-backup.log

📝 License
MIT License - feel free to use and modify for your projects.

🤝 Contributing
Contributions welcome! Please feel free to submit pull requests or open issues for:

Bug fixes

New features

Documentation improvements

Security enhancements

⚠️ Disclaimer
This script is designed for:

Development environments

Personal projects

Educational purposes

For production use:

Review all security settings

Test thoroughly in staging

Monitor resource usage

Implement additional security measures as needed

Need help? Check the setup log at /root/webserver-setup.log
