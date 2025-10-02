Ubuntu Web Server Setup Script
A comprehensive Bash script to set up a production-ready web server on Ubuntu with Nginx, PHP, MySQL, SSL, and security configurations.

Features
Web Server: Nginx installation and configuration

PHP Support: Multiple PHP versions with FPM

Database: MySQL/MariaDB installation and secure setup

SSL Certificate: Automated Let's Encrypt SSL setup

Security: Firewall configuration and security hardening

Optimization: Performance tuning and caching setup

Quick Start
Direct Download and Execution
bash
# Download the script directly from GitHub
wget https://raw.githubusercontent.com/killerhash-stack/ubuntu-webserver-setup/refs/heads/main/setup-webserver.sh

# Make it executable
chmod +x setup-webserver.sh

# Run the script
sudo ./setup-webserver.sh
Manual Download
If you prefer to review the script first:

bash
# Download and examine
wget https://raw.githubusercontent.com/killerhash-stack/ubuntu-webserver-setup/refs/heads/main/setup-webserver.sh
chmod +x setup-webserver.sh

# Review the script
nano setup-webserver.sh

# Execute after review
sudo ./setup-webserver.sh
What the Script Installs
Nginx - High-performance web server

PHP (8.1, 8.2, 8.3) with common extensions

MySQL or MariaDB database server

Certbot for SSL certificates

UFW firewall

Fail2Ban for intrusion prevention

Various utilities (curl, git, unzip, etc.)

Configuration
The script will prompt you for:

Domain name

Database credentials

PHP version selection

SSL certificate setup

Manual Setup (Alternative)
If you prefer to set up manually, you can examine the script at:
https://raw.githubusercontent.com/killerhash-stack/ubuntu-webserver-setup/refs/heads/main/setup-webserver.sh

Security Features
UFW firewall configuration

SSH security enhancements

Fail2Ban setup

Secure MySQL installation

Nginx security headers

Automated security updates

Post-Installation
After running the script:

Upload your website files to /var/www/html/

Configure your domain DNS to point to your server

Set up database and users as needed

Monitor logs in /var/log/

Troubleshooting
Check the following logs if you encounter issues:

Nginx: /var/log/nginx/error.log

PHP-FPM: /var/log/php8.x-fpm.log

MySQL: /var/log/mysql/error.log

License
MIT License

Contributing
Feel free to submit issues and enhancement requests!
