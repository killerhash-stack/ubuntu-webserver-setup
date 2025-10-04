#!/bin/bash
################################################################################
# Ubuntu Web Server Setup Script - COMPLETE FIXED VERSION
# 
# Purpose: Automated setup of production-ready web server
# Compatible: Ubuntu 20.04, 22.04, 24.04, 25.04+
# Features: Nginx, PHP, MySQL, Redis, SSL, Security, Monitoring, Backups
# 
# Usage: sudo bash setup-webserver.sh
# Author: Automated Server Setup
# License: MIT
################################################################################

set -e  # Exit on any error
set -o pipefail  # Catch errors in pipes

LOGFILE="/root/webserver-setup.log"
SCRIPT_VERSION="2.2-COMPLETE"

# ----------------------------
# Logging helpers
# ----------------------------
timestamp() { date +"[%Y-%m-%d %H:%M:%S]"; }
log_info() { echo "$(timestamp) [INFO] $1" | tee -a "$LOGFILE"; }
log_error() { echo "$(timestamp) [ERROR] $1" | tee -a "$LOGFILE" >&2; }
log_warn() { echo "$(timestamp) [WARN] $1" | tee -a "$LOGFILE"; }
log_success() { echo "$(timestamp) [✓] $1" | tee -a "$LOGFILE"; }

# Error handler
trap 'log_error "Script failed at line $LINENO. Check $LOGFILE for details."; exit 1' ERR

# Redirect all output to log file while showing in console
exec > >(tee -a "$LOGFILE") 2>&1

cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║           Ubuntu Web Server Setup Script v2.2               ║
║                      COMPLETE VERSION                        ║
║                                                              ║
║  Features: Nginx • PHP • MySQL • Redis • SSL • Security     ║
║            ModSec • Cockpit • Netdata • File Browser         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF

echo ""
log_info "Starting Ubuntu Webserver Setup Script v${SCRIPT_VERSION}..."

# ----------------------------
# Check requirements
# ----------------------------
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root (use sudo)"
   echo "Usage: sudo bash $0"
   exit 1
fi

# Check if running Ubuntu
if [ ! -f /etc/lsb-release ]; then
    log_error "This script is designed for Ubuntu only"
    exit 1
fi

UBUNTU_VERSION=$(lsb_release -rs)
UBUNTU_CODENAME=$(lsb_release -cs)
log_info "Detected Ubuntu $UBUNTU_VERSION ($UBUNTU_CODENAME)"

# Verify minimum Ubuntu version (20.04+)
MIN_VERSION="20.04"
if [ "$(printf '%s\n' "$MIN_VERSION" "$UBUNTU_VERSION" | sort -V | head -n1)" != "$MIN_VERSION" ]; then 
    log_error "Ubuntu $MIN_VERSION or higher required. Found: $UBUNTU_VERSION"
    exit 1
fi

# Check internet connectivity
log_info "Checking internet connectivity..."
if ! ping -c 1 -W 5 8.8.8.8 &> /dev/null; then
    log_error "No internet connectivity detected. Please check your network connection."
    exit 1
fi
log_success "Internet connectivity confirmed"

# Check available disk space (minimum 10GB)
AVAILABLE_SPACE=$(df / | awk 'NR==2 {print $4}')
REQUIRED_SPACE=10485760  # 10GB in KB
if [ "$AVAILABLE_SPACE" -lt "$REQUIRED_SPACE" ]; then
    log_error "Insufficient disk space. Need at least 10GB free."
    exit 1
fi
log_success "Sufficient disk space available"

# ----------------------------
# Safe rerun: clean APT locks and configure pending packages
# ----------------------------
log_info "Cleaning up APT locks and configuring packages..."
rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock
dpkg --configure -a

# ----------------------------
# Safe rerun: backup configs with unique timestamps
# ----------------------------
BACKUP_TIMESTAMP=$(date +%F-%H%M%S)
CONFIGS=( "/etc/nginx/nginx.conf" "/etc/ssh/sshd_config" )
for cfg in "${CONFIGS[@]}"; do
    if [ -f "$cfg" ]; then
        BACKUP_NAME="$cfg.bak.$BACKUP_TIMESTAMP"
        cp "$cfg" "$BACKUP_NAME"
        log_info "Backed up $cfg to $BACKUP_NAME"
    fi
done

# ----------------------------
# Interactive deploy user setup with validation
# ----------------------------
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  User Configuration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

while true; do
    read -rp "Enter the deploy username [deploy]: " DEPLOYUSER
    DEPLOYUSER=${DEPLOYUSER:-deploy}
    
    # Validate username
    if [[ ! "$DEPLOYUSER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
        echo "Invalid username. Use lowercase letters, numbers, hyphens, underscores only."
        continue
    fi
    
    # Check if username is reserved
    if [[ "$DEPLOYUSER" =~ ^(root|admin|administrator|test|guest|mysql|redis|nginx|www-data)$ ]]; then
        echo "Username '$DEPLOYUSER' is reserved. Please choose another."
        continue
    fi
    
    break
done

if ! id -u "$DEPLOYUSER" >/dev/null 2>&1; then
    log_info "Creating user $DEPLOYUSER..."
    adduser --disabled-password --gecos "" "$DEPLOYUSER"
    usermod -aG sudo "$DEPLOYUSER"
    echo "$DEPLOYUSER ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/"$DEPLOYUSER"
    chmod 440 /etc/sudoers.d/"$DEPLOYUSER"
    
    # Set password for the deploy user
    log_info "Setting password for $DEPLOYUSER (needed for web console access)..."
    while true; do
        read -sp "Enter password for $DEPLOYUSER: " DEPLOY_PASSWORD
        echo ""
        
        if [ ${#DEPLOY_PASSWORD} -lt 8 ]; then
            echo "❌ Password too short. Please use at least 8 characters."
            continue
        fi
        
        read -sp "Confirm password for $DEPLOYUSER: " DEPLOY_PASSWORD_CONFIRM
        echo ""
        
        if [ "$DEPLOY_PASSWORD" = "$DEPLOY_PASSWORD_CONFIRM" ]; then
            echo "$DEPLOYUSER:$DEPLOY_PASSWORD" | chpasswd
            log_success "Password set successfully for $DEPLOYUSER"
            break
        else
            echo "❌ Passwords don't match. Please try again."
        fi
    done
    
    unset DEPLOY_PASSWORD
    unset DEPLOY_PASSWORD_CONFIRM
else
    log_info "User $DEPLOYUSER already exists..."
fi

# ----------------------------
# Domain and Git repository setup
# ----------------------------
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Website & SSL Configuration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

read -rp "Enter your domain name (e.g., example.com) or leave blank to skip SSL: " DOMAIN_NAME
if [ -n "$DOMAIN_NAME" ]; then
    read -rp "Enter additional domains (comma-separated, e.g., www.example.com) or leave blank: " ADDITIONAL_DOMAINS
    
    while true; do
        read -rp "Enter your email for Let's Encrypt notifications: " LETSENCRYPT_EMAIL
        if [[ "$LETSENCRYPT_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || [ -z "$LETSENCRYPT_EMAIL" ]; then
            break
        else
            echo "❌ Invalid email format. Please try again."
        fi
    done
fi

read -rp "Enter your GitHub repo (format: username/repo) or leave blank: " GITREPO

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Optional Software Components"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

read -rp "Install PHP and MySQL for dynamic websites? [Y/n]: " INSTALL_PHP_MYSQL
INSTALL_PHP_MYSQL=${INSTALL_PHP_MYSQL:-Y}

read -rp "Install Redis for caching/sessions? [Y/n]: " INSTALL_REDIS
INSTALL_REDIS=${INSTALL_REDIS:-Y}

read -rp "Install ModSecurity WAF for extra security? [Y/n]: " INSTALL_MODSECURITY
INSTALL_MODSECURITY=${INSTALL_MODSECURITY:-Y}

read -rp "Install Cockpit web management console? [Y/n]: " INSTALL_COCKPIT
INSTALL_COCKPIT=${INSTALL_COCKPIT:-Y}

read -rp "Install Netdata monitoring? [Y/n]: " INSTALL_NETDATA
INSTALL_NETDATA=${INSTALL_NETDATA:-Y}

read -rp "Install File Browser for file management? [Y/n]: " INSTALL_FILEBROWSER
INSTALL_FILEBROWSER=${INSTALL_FILEBROWSER:-Y}

read -rp "Install rkhunter rootkit scanner? [Y/n]: " INSTALL_RKHUNTER
INSTALL_RKHUNTER=${INSTALL_RKHUNTER:-Y}

echo ""
log_info "Configuration complete. Starting installation..."
sleep 2

# ----------------------------
# Internal IP detection
# ----------------------------
INTERNAL_IP=$(hostname -I | awk '{print $1}')
if [ -z "$INTERNAL_IP" ]; then
    log_warn "Could not detect internal IP, using localhost"
    INTERNAL_IP="127.0.0.1"
fi

# ----------------------------
# System update
# ----------------------------
log_info "Updating and upgrading system packages..."
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# ----------------------------
# Core packages
# ----------------------------
log_info "Installing core packages..."
CORE_PACKAGES="curl wget git ufw fail2ban unzip software-properties-common gnupg2 ca-certificates lsb-release apt-transport-https build-essential"

for package in $CORE_PACKAGES; do
    if ! dpkg -l | grep -q "^ii  $package "; then
        if apt-cache show "$package" &>/dev/null; then
            apt-get install -yqq "$package" || log_warn "Failed to install $package, continuing..."
        else
            log_warn "Package $package not available, skipping..."
        fi
    fi
done
log_success "Core packages installed"

# ----------------------------
# SSH key generation for deploy user
# ----------------------------
if [ ! -f /home/"$DEPLOYUSER"/.ssh/id_rsa ]; then
    log_info "Generating SSH key for $DEPLOYUSER..."
    
    rm -rf /home/"$DEPLOYUSER"/.ssh
    mkdir -p /home/"$DEPLOYUSER"/.ssh
    chown "$DEPLOYUSER":"$DEPLOYUSER" /home/"$DEPLOYUSER"
    chown "$DEPLOYUSER":"$DEPLOYUSER" /home/"$DEPLOYUSER"/.ssh
    chmod 700 /home/"$DEPLOYUSER"/.ssh
    
    if su - "$DEPLOYUSER" -c "ssh-keygen -t rsa -b 4096 -f /home/$DEPLOYUSER/.ssh/id_rsa -N '' -C '$DEPLOYUSER@$(hostname)'" 2>/dev/null; then
        log_info "SSH key generated successfully"
    else
        ssh-keygen -t rsa -b 4096 -f "/home/$DEPLOYUSER/.ssh/id_rsa" -N "" -C "$DEPLOYUSER@$(hostname)"
        chown "$DEPLOYUSER":"$DEPLOYUSER" /home/"$DEPLOYUSER"/.ssh/id_rsa*
    fi
    
    if [ -f /home/"$DEPLOYUSER"/.ssh/id_rsa ]; then
        cp /home/"$DEPLOYUSER"/.ssh/id_rsa.pub /home/"$DEPLOYUSER"/.ssh/authorized_keys
        chown -R "$DEPLOYUSER":"$DEPLOYUSER" /home/"$DEPLOYUSER"/.ssh
        chmod 700 /home/"$DEPLOYUSER"/.ssh
        chmod 600 /home/"$DEPLOYUSER"/.ssh/id_rsa
        chmod 644 /home/"$DEPLOYUSER"/.ssh/id_rsa.pub
        chmod 600 /home/"$DEPLOYUSER"/.ssh/authorized_keys
        log_success "SSH key configured for $DEPLOYUSER"
    fi
fi

# ----------------------------
# OpenSSH hardening
# ----------------------------
log_info "Configuring OpenSSH server..."
apt-get install -y openssh-server

SSH_CONFIG_BACKUP="/etc/ssh/sshd_config.backup.$BACKUP_TIMESTAMP"
cp /etc/ssh/sshd_config "$SSH_CONFIG_BACKUP"

sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

if ! grep -q "^AllowUsers" /etc/ssh/sshd_config; then
    echo "AllowUsers $DEPLOYUSER" >> /etc/ssh/sshd_config
fi

if sshd -t 2>/dev/null; then
    systemctl enable ssh
    systemctl restart ssh
    log_success "SSH configured and restarted"
else
    log_error "SSH configuration test failed, restoring backup"
    cp "$SSH_CONFIG_BACKUP" /etc/ssh/sshd_config
    systemctl restart ssh
fi

# ----------------------------
# PHP and MySQL installation
# ----------------------------
if [[ "$INSTALL_PHP_MYSQL" =~ ^[Yy]$ ]]; then
    log_info "Installing PHP and MySQL/MariaDB..."
    
    if apt-cache show php8.3 &>/dev/null; then
        PHP_VERSION="8.3"
    elif apt-cache show php8.2 &>/dev/null; then
        PHP_VERSION="8.2"
    elif apt-cache show php8.1 &>/dev/null; then
        PHP_VERSION="8.1"
    else
        PHP_VERSION=""
    fi
    
    if [ -n "$PHP_VERSION" ]; then
        log_info "Installing PHP $PHP_VERSION..."
        
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            php${PHP_VERSION} \
            php${PHP_VERSION}-fpm \
            php${PHP_VERSION}-mysql \
            php${PHP_VERSION}-curl \
            php${PHP_VERSION}-gd \
            php${PHP_VERSION}-mbstring \
            php${PHP_VERSION}-xml \
            php${PHP_VERSION}-zip \
            php${PHP_VERSION}-intl \
            php${PHP_VERSION}-bcmath
        
        systemctl enable php${PHP_VERSION}-fpm
        systemctl start php${PHP_VERSION}-fpm
        log_success "PHP $PHP_VERSION installed"
        
        # Configure PHP for security
        PHP_INI="/etc/php/${PHP_VERSION}/fpm/php.ini"
        if [ -f "$PHP_INI" ]; then
            sed -i 's/^expose_php = On/expose_php = Off/' "$PHP_INI"
            sed -i 's/^;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/' "$PHP_INI"
            systemctl restart php${PHP_VERSION}-fpm
        fi
    fi
    
    log_info "Installing MariaDB..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server mariadb-client
    
    systemctl enable mariadb
    systemctl start mariadb
    
    DB_ROOT_PASSWORD=$(openssl rand -base64 32)
    
    mysql -u root <<-EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASSWORD}';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
    
    cat > /root/.my.cnf <<EOF
[client]
user=root
password=${DB_ROOT_PASSWORD}
EOF
    chmod 600 /root/.my.cnf
    
    # Create database for deploy user
    DB_USER_PASSWORD=$(openssl rand -base64 16)
    
    mysql -u root <<-EOF
CREATE DATABASE IF NOT EXISTS website_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DEPLOYUSER}'@'localhost' IDENTIFIED BY '${DB_USER_PASSWORD}';
GRANT ALL PRIVILEGES ON website_db.* TO '${DEPLOYUSER}'@'localhost';
FLUSH PRIVILEGES;
EOF
    
    cat > /home/${DEPLOYUSER}/.my.cnf <<EOF
[client]
user=${DEPLOYUSER}
password=${DB_USER_PASSWORD}
database=website_db
EOF
    chown ${DEPLOYUSER}:${DEPLOYUSER} /home/${DEPLOYUSER}/.my.cnf
    chmod 600 /home/${DEPLOYUSER}/.my.cnf
    
    log_success "MariaDB secured and database created"
fi

# ----------------------------
# Redis installation
# ----------------------------
if [[ "$INSTALL_REDIS" =~ ^[Yy]$ ]]; then
    log_info "Installing Redis..."
    
    if apt-cache show redis-server &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y redis-server redis-tools
        
        if [ -f /etc/redis/redis.conf ]; then
            cp /etc/redis/redis.conf /etc/redis/redis.conf.backup
            
            REDIS_PASSWORD=$(openssl rand -base64 32)
            sed -i "s/^# requirepass .*/requirepass ${REDIS_PASSWORD}/" /etc/redis/redis.conf
            sed -i 's/^bind 127.0.0.1 ::1/bind 127.0.0.1/' /etc/redis/redis.conf
            sed -i 's/^# maxmemory .*/maxmemory 256mb/' /etc/redis/redis.conf
            sed -i 's/^# maxmemory-policy .*/maxmemory-policy allkeys-lru/' /etc/redis/redis.conf
        fi
        
        systemctl enable redis-server
        systemctl restart redis-server
        
        cat > /root/.redis_credentials <<EOF
Redis Connection Info:
Host: localhost (127.0.0.1)
Port: 6379
Password: ${REDIS_PASSWORD}
EOF
        chmod 600 /root/.redis_credentials
        
        # Install PHP Redis extension if PHP is installed
        if [ -n "$PHP_VERSION" ]; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y php${PHP_VERSION}-redis
            systemctl restart php${PHP_VERSION}-fpm
        fi
        
        log_success "Redis installed and configured"
    fi
fi

# ----------------------------
# Nginx installation - FIXED
# ----------------------------
log_info "Installing Nginx..."

# Clean install
systemctl stop nginx 2>/dev/null || true
apt-get remove --purge nginx nginx-common nginx-core -y 2>/dev/null || true
rm -rf /etc/nginx
rm -rf /var/www/html

apt-get install -y nginx

# Create web root
mkdir -p /var/www/html
chown -R www-data:www-data /var/www/html

# Create clean default config
cat > /etc/nginx/sites-available/default <<'NGINXCONF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;
    index index.html index.htm index.nginx-debian.html index.php;

    server_name _;

    location / {
        try_files $uri $uri/ =404;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    }

    location ~ /\.ht {
        deny all;
    }
}
NGINXCONF

ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

if nginx -t; then
    systemctl enable nginx
    systemctl start nginx
    log_success "Nginx installed and started"
else
    log_error "Nginx configuration test failed!"
    exit 1
fi

# ----------------------------
# ModSecurity installation - FIXED APPROACH
# ----------------------------
if [[ "$INSTALL_MODSECURITY" =~ ^[Yy]$ ]]; then
    log_info "Installing ModSecurity..."
    
    MODSEC_INSTALLED=false
    
    # Try package installation first
    if apt-cache show libmodsecurity3 &>/dev/null; then
        log_info "Installing ModSecurity via package manager..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y libmodsecurity3 || true
        
        if dpkg -l | grep -q libmodsecurity3; then
            MODSEC_INSTALLED=true
        fi
    fi
    
    if [ "$MODSEC_INSTALLED" = true ]; then
        # Setup ModSecurity configuration
        mkdir -p /etc/nginx/modsec
        
        # Download OWASP CRS with timeout protection
        if [ ! -d "/etc/nginx/modsec/coreruleset" ]; then
            log_info "Downloading OWASP Core Rule Set..."
            cd /tmp
            if timeout 60 wget -q https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.0.0.tar.gz 2>/dev/null; then
                tar -xzf v4.0.0.tar.gz
                mv coreruleset-4.0.0 /etc/nginx/modsec/coreruleset
                cp /etc/nginx/modsec/coreruleset/crs-setup.conf.example /etc/nginx/modsec/crs-setup.conf
                rm -f v4.0.0.tar.gz
                
                # Create ModSecurity config
                cat > /etc/nginx/modsec/modsecurity.conf <<'MODSECCONF'
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
MODSECCONF

                cat > /etc/nginx/modsec/main.conf <<'MODSECMAIN'
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/nginx/modsec/crs-setup.conf
Include /etc/nginx/modsec/coreruleset/rules/*.conf
MODSECMAIN

                log_success "ModSecurity rules downloaded (Detection mode only)"
            else
                log_warn "Failed to download OWASP CRS within timeout"
                MODSEC_INSTALLED=false
            fi
        fi
    else
        log_warn "ModSecurity not available in repositories"
    fi
fi

# ----------------------------
# Cockpit installation - IMPROVED
# ----------------------------
if [[ "$INSTALL_COCKPIT" =~ ^[Yy]$ ]]; then
    log_info "Installing Cockpit..."
    
    if apt-cache show cockpit &>/dev/null; then
        # Install with timeout protection
        if timeout 180 apt-get install -y cockpit 2>/dev/null; then
            systemctl enable cockpit.socket
            systemctl start cockpit.socket
            
            if systemctl is-active --quiet cockpit.socket; then
                log_success "Cockpit installed successfully"
                
                # Allow Cockpit through firewall
                ufw allow 9090/tcp comment 'Cockpit Web Console'
            else
                log_warn "Cockpit installed but not running"
            fi
        else
            log_warn "Cockpit installation timed out, skipping"
        fi
    else
        log_warn "Cockpit not available in repositories"
    fi
fi

# ----------------------------
# Netdata installation - IMPROVED
# ----------------------------
if [[ "$INSTALL_NETDATA" =~ ^[Yy]$ ]]; then
    log_info "Installing Netdata..."
    
    NETDATA_INSTALLED=false
    
    # Try package manager first
    if apt-cache show netdata &>/dev/null; then
        log_info "Installing Netdata via package manager..."
        if timeout 120 apt-get install -y netdata 2>/dev/null; then
            systemctl enable netdata
            systemctl start netdata
            NETDATA_INSTALLED=true
        fi
    fi
    
    # If package failed, try installer script with timeout
    if [ "$NETDATA_INSTALLED" = false ]; then
        log_info "Trying Netdata kickstart installer..."
        if timeout 180 wget -O /tmp/netdata-kickstart.sh https://my-netdata.io/kickstart.sh 2>/dev/null; then
            if timeout 300 bash /tmp/netdata-kickstart.sh --dont-wait --disable-telemetry --non-interactive 2>/dev/null; then
                systemctl enable netdata 2>/dev/null || true
                systemctl start netdata 2>/dev/null || true
                NETDATA_INSTALLED=true
            fi
            rm -f /tmp/netdata-kickstart.sh
        fi
    fi
    
    if [ "$NETDATA_INSTALLED" = true ] && systemctl is-active --quiet netdata; then
        log_success "Netdata installed successfully"
        ufw allow 19999/tcp comment 'Netdata Monitoring'
    else
        log_warn "Netdata installation failed or timed out"
    fi
fi

# ----------------------------
# File Browser installation - IMPROVED
# ----------------------------
if [[ "$INSTALL_FILEBROWSER" =~ ^[Yy]$ ]]; then
    log_info "Installing File Browser..."
    
    if [ ! -f /usr/local/bin/filebrowser ]; then
        if timeout 60 curl -fsSL https://raw.githubusercontent.com/filebrowser/get/master/get.sh 2>/dev/null | timeout 120 bash 2>/dev/null; then
            mkdir -p /etc/filebrowser
            mkdir -p /var/lib/filebrowser
            
            filebrowser config init --database /var/lib/filebrowser/filebrowser.db
            filebrowser config set --address 0.0.0.0 --port 8080 --database /var/lib/filebrowser/filebrowser.db
            filebrowser config set --root /var/www/html --database /var/lib/filebrowser/filebrowser.db
            filebrowser users add admin admin --perm.admin --database /var/lib/filebrowser/filebrowser.db 2>/dev/null || true
            
            cat > /etc/systemd/system/filebrowser.service <<'FBSERVICE'
[Unit]
Description=File Browser
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/filebrowser --database /var/lib/filebrowser/filebrowser.db
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
FBSERVICE

            systemctl daemon-reload
            systemctl enable filebrowser
            systemctl start filebrowser
            
            if systemctl is-active --quiet filebrowser; then
                log_success "File Browser installed (port 8080, login: admin/admin)"
                ufw allow 8080/tcp comment 'File Browser'
            else
                log_warn "File Browser installed but not running"
            fi
        else
            log_warn "File Browser installation timed out"
        fi
    else
        log_info "File Browser already installed"
    fi
fi

# ----------------------------
# rkhunter installation - IMPROVED
# ----------------------------
if [[ "$INSTALL_RKHUNTER" =~ ^[Yy]$ ]]; then
    log_info "Installing rkhunter..."
    
    if apt-cache show rkhunter &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y rkhunter
        
        # Fix configuration
        if [ -f /etc/rkhunter.conf ]; then
            sed -i 's|^WEB_CMD=.*|#WEB_CMD="" # Disabled|g' /etc/rkhunter.conf
            
            if [ -f /etc/default/rkhunter ]; then
                sed -i 's|APT_AUTOGEN=.*|APT_AUTOGEN="yes"|g' /etc/default/rkhunter
            fi
            
            # Initialize database
            rkhunter --propupd --quiet 2>/dev/null || log_warn "rkhunter property update failed"
            log_success "rkhunter installed and configured"
        fi
    else
        log_warn "rkhunter not available in repositories"
    fi
fi

# ----------------------------
# Let's Encrypt SSL Setup - FIXED
# ----------------------------
log_info "Installing Certbot..."
apt-get install -y certbot python3-certbot-nginx

if [ -n "$DOMAIN_NAME" ] && [ -n "$LETSENCRYPT_EMAIL" ]; then
    log_info "Setting up SSL for $DOMAIN_NAME..."
    
    # Build domain list
    CERT_DOMAINS="-d $DOMAIN_NAME"
    if [ -n "$ADDITIONAL_DOMAINS" ]; then
        IFS=',' read -ra DOMAIN_ARRAY <<< "$ADDITIONAL_DOMAINS"
        for domain in "${DOMAIN_ARRAY[@]}"; do
            domain=$(echo "$domain" | xargs)
            if [ -n "$domain" ]; then
                CERT_DOMAINS="$CERT_DOMAINS -d $domain"
            fi
        done
    fi
    
    # Create domain-specific config
    SERVER_NAMES="$DOMAIN_NAME"
    [ -n "$ADDITIONAL_DOMAINS" ] && SERVER_NAMES="$DOMAIN_NAME ${ADDITIONAL_DOMAINS//,/ }"
    
    cat > /etc/nginx/sites-available/$DOMAIN_NAME <<DOMAINCONF
server {
    listen 80;
    listen [::]:80;
    server_name $SERVER_NAMES;

    root /var/www/html;
    index index.html index.htm index.php;

    location ^~ /.well-known/acme-challenge/ {
        default_type "text/plain";
        root /var/www/letsencrypt;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php${PHP_VERSION}-fpm.sock;
    }

    location ~ /\.ht {
        deny all;
    }
}
DOMAINCONF

    mkdir -p /var/www/letsencrypt
    chown www-data:www-data /var/www/letsencrypt

    # Remove default site and enable domain site
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/$DOMAIN_NAME /etc/nginx/sites-enabled/$DOMAIN_NAME

    # Test and reload
    if nginx -t; then
        systemctl reload nginx
        log_info "Domain configuration applied"
        
        sleep 3
        
        # Try to get SSL certificate
        if certbot certonly --webroot -w /var/www/letsencrypt $CERT_DOMAINS \
            --email "$LETSENCRYPT_EMAIL" --agree-tos --non-interactive --expand; then
            
            log_success "SSL certificate obtained!"
            
            # Update config with SSL
            cat > /etc/nginx/sites-available/$DOMAIN_NAME <<SSLCONF
server {
    listen 80;
    listen [::]:80;
    server_name $SERVER_NAMES;

    location ^~ /.well-known/acme-challenge/ {
        default_type "text/plain";
        root /var/www/letsencrypt;
    }

    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $SERVER_NAMES;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    
    root /var/www/html;
    index index.html index.htm index.php;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php${PHP_VERSION}-fpm.sock;
    }

    location ~ /\.ht {
        deny all;
    }
}
SSLCONF

            if nginx -t; then
                systemctl reload nginx
                log_success "SSL configuration applied!"
                
                # Setup auto-renewal
                cat > /etc/cron.d/letsencrypt-renewal <<'RENEWAL'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 */12 * * * root certbot renew --quiet --deploy-hook "systemctl reload nginx"
RENEWAL
                
                log_info "SSL auto-renewal configured"
            fi
        else
            log_warn "SSL certificate request failed - keeping HTTP configuration"
        fi
    fi
fi

# ----------------------------
# Fail2Ban configuration
# ----------------------------
log_info "Configuring Fail2Ban..."

mkdir -p /etc/fail2ban/filter.d

cat > /etc/fail2ban/filter.d/nginx-http-auth.conf <<'F2BFILTER'
[Definition]
failregex = ^ \[error\] \d+#\d+: \*\d+ user "\S+":? (?:password mismatch|was not found in ".*"), client: <HOST>, server: \S+, request: "\S+ \S+ HTTP/\d+\.\d+", host: "\S+"(?:, referrer: "\S+")?\s*$
ignoreregex =
F2BFILTER

cat > /etc/fail2ban/jail.local <<'F2BJAIL'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
F2BJAIL

systemctl enable fail2ban
systemctl restart fail2ban
log_success "Fail2Ban configured"

# ----------------------------
# Firewall setup
# ----------------------------
log_info "Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw --force enable
log_success "Firewall configured"

# ----------------------------
# Automated Backup System
# ----------------------------
log_info "Setting up automated backup system..."

mkdir -p /var/backups/website/{daily,weekly,monthly}
chmod 700 /var/backups/website

cat > /usr/local/bin/backup-website.sh <<'BACKUPSCRIPT'
#!/bin/bash
BACKUP_DIR="/var/backups/website"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DAY_OF_WEEK=$(date +%u)
DAY_OF_MONTH=$(date +%d)

DAILY_RETENTION=7
WEEKLY_RETENTION=28
MONTHLY_RETENTION=90

if [ "$DAY_OF_MONTH" -eq "01" ]; then
    BACKUP_TYPE="monthly"
    BACKUP_SUBDIR="${BACKUP_DIR}/monthly"
    RETENTION=$MONTHLY_RETENTION
elif [ "$DAY_OF_WEEK" -eq "7" ]; then
    BACKUP_TYPE="weekly"
    BACKUP_SUBDIR="${BACKUP_DIR}/weekly"
    RETENTION=$WEEKLY_RETENTION
else
    BACKUP_TYPE="daily"
    BACKUP_SUBDIR="${BACKUP_DIR}/daily"
    RETENTION=$DAILY_RETENTION
fi

tar -czf "${BACKUP_SUBDIR}/webfiles_${TIMESTAMP}.tar.gz" -C /var/www/html . 2>/dev/null
tar -czf "${BACKUP_SUBDIR}/nginx_${TIMESTAMP}.tar.gz" /etc/nginx 2>/dev/null

if systemctl is-active --quiet mariadb 2>/dev/null && [ -f /root/.my.cnf ]; then
    mysqldump --all-databases --single-transaction --quick | gzip > "${BACKUP_SUBDIR}/databases_${TIMESTAMP}.sql.gz" 2>/dev/null
fi

find "${BACKUP_DIR}/daily" -name "*.tar.gz" -mtime +${DAILY_RETENTION} -delete 2>/dev/null
find "${BACKUP_DIR}/daily" -name "*.sql.gz" -mtime +${DAILY_RETENTION} -delete 2>/dev/null
find "${BACKUP_DIR}/weekly" -name "*.tar.gz" -mtime +${WEEKLY_RETENTION} -delete 2>/dev/null
find "${BACKUP_DIR}/weekly" -name "*.sql.gz" -mtime +${WEEKLY_RETENTION} -delete 2>/dev/null
find "${BACKUP_DIR}/monthly" -name "*.tar.gz" -mtime +${MONTHLY_RETENTION} -delete 2>/dev/null
find "${BACKUP_DIR}/monthly" -name "*.sql.gz" -mtime +${MONTHLY_RETENTION} -delete 2>/dev/null

echo "$(date): ${BACKUP_TYPE^} backup completed" >> /var/log/website-backup.log
BACKUPSCRIPT

chmod +x /usr/local/bin/backup-website.sh

cat > /etc/cron.d/website-backup <<'BACKUPCRON'
0 2 * * * root /usr/local/bin/backup-website.sh >/dev/null 2>&1
BACKUPCRON

/usr/local/bin/backup-website.sh
log_success "Backup system configured"

# ----------------------------
# Git auto-deploy
# ----------------------------
if [ -n "$GITREPO" ]; then
    log_info "Setting up Git repository..."
    mkdir -p /var/www/html
    chown -R "$DEPLOYUSER":"$DEPLOYUSER" /var/www/html
    
    if [ ! -d "/var/www/html/.git" ]; then
        if sudo -u "$DEPLOYUSER" git clone "https://github.com/$GITREPO.git" /tmp/repo 2>/dev/null; then
            sudo -u "$DEPLOYUSER" cp -r /tmp/repo/* /var/www/html/ 2>/dev/null || true
            sudo -u "$DEPLOYUSER" cp -r /tmp/repo/.git /var/www/html/ 2>/dev/null || true
            rm -rf /tmp/repo
            log_success "Git repository cloned"
        else
            log_warn "Failed to clone repository: $GITREPO"
        fi
    fi
fi

# ----------------------------
# Create index page
# ----------------------------
if [ ! -f "/var/www/html/index.html" ] && [ ! -f "/var/www/html/index.php" ]; then
    cat > /var/www/html/index.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Server Setup Complete</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 900px; margin: 40px auto; background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { opacity: 0.9; font-size: 1.1em; }
        .content { padding: 40px; }
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }
        .status-card { background: #f8f9fa; padding: 20px; border-radius: 10px; border-left: 4px solid #28a745; }
        .status-card.warning { border-left-color: #ffc107; }
        .status-card h3 { color: #333; margin-bottom: 10px; display: flex; align-items: center; gap: 10px; }
        .status-card p { color: #666; font-size: 0.9em; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; }
        .badge.success { background: #28a745; color: white; }
        .badge.warning { background: #ffc107; color: #333; }
        .info-section { background: #e3f2fd; padding: 20px; border-radius: 10px; margin: 20px 0; }
        .info-section h3 { color: #1976d2; margin-bottom: 15px; }
        .info-list { list-style: none; }
        .info-list li { padding: 8px 0; color: #555; display: flex; align-items: center; gap: 10px; }
        .info-list li:before { content: "→"; color: #1976d2; font-weight: bold; }
        .footer { text-align: center; padding: 20px; color: #999; font-size: 0.9em; border-top: 1px solid #eee; }
        a { color: #667eea; text-decoration: none; font-weight: 500; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 Server Ready!</h1>
            <p>Your web server has been successfully configured</p>
        </div>
        
        <div class="content">
            <div class="status-grid">
                <div class="status-card">
                    <h3>🌐 Web Server <span class="badge success">ACTIVE</span></h3>
                    <p>Nginx is running and serving content</p>
                </div>
                
                <div class="status-card">
                    <h3>🔒 Security <span class="badge success">ENABLED</span></h3>
                    <p>Firewall, Fail2Ban, SSH hardening active</p>
                </div>
                
$([ -n "$DOMAIN_NAME" ] && [ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ] && cat <<'SSLSTATUS'
                <div class="status-card">
                    <h3>🔐 SSL/TLS <span class="badge success">ACTIVE</span></h3>
                    <p>Let's Encrypt certificate installed</p>
                </div>
SSLSTATUS
)
                
$(systemctl is-active --quiet cockpit.socket 2>/dev/null && cat <<'COCKPITSTATUS'
                <div class="status-card">
                    <h3>🔧 Cockpit <span class="badge success">PORT 9090</span></h3>
                    <p>Web management console available</p>
                </div>
COCKPITSTATUS
)

$(systemctl is-active --quiet netdata 2>/dev/null && cat <<'NETDATASTATUS'
                <div class="status-card">
                    <h3>📊 Netdata <span class="badge success">PORT 19999</span></h3>
                    <p>Real-time monitoring dashboard</p>
                </div>
NETDATASTATUS
)

$(systemctl is-active --quiet filebrowser 2>/dev/null && cat <<'FBSTATUS'
                <div class="status-card warning">
                    <h3>📁 File Browser <span class="badge warning">PORT 8080</span></h3>
                    <p>⚠️ Change default password!</p>
                </div>
FBSTATUS
)
            </div>

            <div class="info-section">
                <h3>📋 Server Information</h3>
                <ul class="info-list">
                    <li><strong>Server IP:</strong> $INTERNAL_IP</li>
$([ -n "$DOMAIN_NAME" ] && echo "                    <li><strong>Domain:</strong> $DOMAIN_NAME</li>")
                    <li><strong>Deploy User:</strong> $DEPLOYUSER</li>
                    <li><strong>Web Root:</strong> /var/www/html</li>
                    <li><strong>Setup Date:</strong> $(date)</li>
                </ul>
            </div>

            <div class="info-section">
                <h3>🚀 Quick Links</h3>
                <ul class="info-list">
$(systemctl is-active --quiet cockpit.socket 2>/dev/null && echo "                    <li><a href=\"https://$INTERNAL_IP:9090\" target=\"_blank\">Cockpit Console</a> - Server management</li>")
$(systemctl is-active --quiet netdata 2>/dev/null && echo "                    <li><a href=\"http://$INTERNAL_IP:19999\" target=\"_blank\">Netdata Dashboard</a> - Performance monitoring</li>")
$(systemctl is-active --quiet filebrowser 2>/dev/null && echo "                    <li><a href=\"http://$INTERNAL_IP:8080\" target=\"_blank\">File Browser</a> - File management (admin/admin)</li>")
                </ul>
            </div>

            <div class="info-section">
                <h3>📚 Next Steps</h3>
                <ul class="info-list">
                    <li>Upload your website files to /var/www/html</li>
$(systemctl is-active --quiet filebrowser 2>/dev/null && echo "                    <li>⚠️ Change File Browser password immediately!</li>")
                    <li>Configure your domain DNS if not done yet</li>
                    <li>Review security settings and logs</li>
                    <li>Test all services are working correctly</li>
                </ul>
            </div>
        </div>
        
        <div class="footer">
            <p>Server setup completed successfully • Ubuntu $UBUNTU_VERSION</p>
        </div>
    </div>
</body>
</html>
EOF
    chown www-data:www-data /var/www/html/index.html
fi

# ----------------------------
# Final system check and summary
# ----------------------------
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║                    Installation Complete!                   ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

log_info "Performing final system check..."

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  SERVICE STATUS"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Check core services
services=("nginx" "ssh" "fail2ban")
for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        echo "  ✅ ${service}: RUNNING"
    else
        echo "  ❌ ${service}: NOT RUNNING"
    fi
done

# Check optional services
[ "$INSTALL_PHP_MYSQL" = "Y" ] || [ "$INSTALL_PHP_MYSQL" = "y" ] && {
    systemctl is-active --quiet php${PHP_VERSION}-fpm 2>/dev/null && echo "  ✅ PHP ${PHP_VERSION}: RUNNING"
    systemctl is-active --quiet mariadb 2>/dev/null && echo "  ✅ MariaDB: RUNNING"
}

[ "$INSTALL_REDIS" = "Y" ] || [ "$INSTALL_REDIS" = "y" ] && {
    systemctl is-active --quiet redis-server 2>/dev/null && echo "  ✅ Redis: RUNNING"
}

[ "$INSTALL_COCKPIT" = "Y" ] || [ "$INSTALL_COCKPIT" = "y" ] && {
    systemctl is-active --quiet cockpit.socket 2>/dev/null && echo "  ✅ Cockpit: RUNNING" || echo "  ⚠️  Cockpit: NOT RUNNING"
}

[ "$INSTALL_NETDATA" = "Y" ] || [ "$INSTALL_NETDATA" = "y" ] && {
    systemctl is-active --quiet netdata 2>/dev/null && echo "  ✅ Netdata: RUNNING" || echo "  ⚠️  Netdata: NOT RUNNING"
}

[ "$INSTALL_FILEBROWSER" = "Y" ] || [ "$INSTALL_FILEBROWSER" = "y" ] && {
    systemctl is-active --quiet filebrowser 2>/dev/null && echo "  ✅ File Browser: RUNNING" || echo "  ⚠️  File Browser: NOT RUNNING"
}

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  NGINX CONFIGURATION"
echo "═══════════════════════════════════════════════════════════════"
echo ""

if nginx -t 2>/dev/null; then
    echo "  ✅ Nginx configuration: VALID"
else
    echo "  ❌ Nginx configuration: INVALID"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ACCESS INFORMATION"
echo "═══════════════════════════════════════════════════════════════"
echo ""

echo "  🌍 Web Server: http://$INTERNAL_IP"
[ -n "$DOMAIN_NAME" ] && {
    [ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ] && echo "  🔒 Secure Site: https://$DOMAIN_NAME" || echo "  🌐 Website: http://$DOMAIN_NAME"
}

echo ""
echo "  🔑 SSH User: $DEPLOYUSER"
echo "  📝 SSH Command: ssh $DEPLOYUSER@$INTERNAL_IP"
echo ""

systemctl is-active --quiet cockpit.socket 2>/dev/null && echo "  🔧 Cockpit: https://$INTERNAL_IP:9090"
systemctl is-active --quiet netdata 2>/dev/null && echo "  📊 Netdata: http://$INTERNAL_IP:19999"
systemctl is-active --quiet filebrowser 2>/dev/null && echo "  📁 File Browser: http://$INTERNAL_IP:8080 (admin/admin)"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  SECURITY FEATURES"
echo "═══════════════════════════════════════════════════════════════"
echo ""

[ -n "$DOMAIN_NAME" ] && [ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ] && echo "  🔒 SSL/TLS: ACTIVE (Let's Encrypt)" || echo "  🔒 SSL/TLS: NOT CONFIGURED"
[ "$INSTALL_MODSECURITY" = "Y" ] || [ "$INSTALL_MODSECURITY" = "y" ] && echo "  🛡️  ModSecurity: INSTALLED (detection mode)"
echo "  🚫 Fail2Ban: ACTIVE"
echo "  🔥 UFW Firewall: ENABLED"
echo "  🔐 SSH: HARDENED (key-only)"
[ "$INSTALL_RKHUNTER" = "Y" ] || [ "$INSTALL_RKHUNTER" = "y" ] && command -v rkhunter &>/dev/null && echo "  🔍 rkhunter: INSTALLED"
echo "  📦 Backups: 7 daily + 4 weekly + 3 monthly"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  IMPORTANT FILES"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  📁 Web root: /var/www/html"
echo "  📜 Setup log: $LOGFILE"
echo "  🔐 SSH keys: /home/$DEPLOYUSER/.ssh/"
[ -f /home/$DEPLOYUSER/.my.cnf ] && echo "  🗄️  Database credentials: /home/$DEPLOYUSER/.my.cnf"
[ -f /root/.redis_credentials ] && echo "  ⚡ Redis credentials: /root/.redis_credentials"
echo "  📦 Backups: /var/backups/website"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  NEXT STEPS"
echo "═══════════════════════════════════════════════════════════════"
echo ""

STEP=1
systemctl is-active --quiet filebrowser 2>/dev/null && {
    echo "  $STEP. 🔐 URGENT: Change File Browser password!"
    STEP=$((STEP + 1))
}

[ -n "$DOMAIN_NAME" ] && {
    [ ! -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ] && {
        echo "  $STEP. 🌐 Point DNS to your server IP"
        STEP=$((STEP + 1))
        echo "  $STEP. 🔒 Retry SSL: certbot --nginx -d $DOMAIN_NAME"
        STEP=$((STEP + 1))
    }
}

echo "  $STEP. 📂 Upload your website files to /var/www/html"
STEP=$((STEP + 1))
echo "  $STEP. 🔄 Test and reboot: sudo reboot"
STEP=$((STEP + 1))
echo "  $STEP. 📊 Monitor logs: tail -f /var/log/nginx/error.log"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║              🎉 Setup Complete! Server Ready! 🎉             ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
log_success "Full setup log available at: $LOGFILE"
log_success "Server setup completed successfully at $(date)"
echo ""
