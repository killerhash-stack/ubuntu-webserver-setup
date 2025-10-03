#!/bin/bash

# Ultimate Ubuntu Web Server Setup Script
# Combines comprehensive features with robust error handling and beautiful UX
# GitHub: https://raw.githubusercontent.com/killerhash-stack/ubuntu-webserver-setup/main/setup-webserver.sh

set -e
set -o pipefail

# Script metadata
SCRIPT_NAME="ultimate-webserver-setup"
SCRIPT_VERSION="3.0"
SCRIPT_URL="https://raw.githubusercontent.com/killerhash-stack/ubuntu-webserver-setup/main/setup-webserver.sh"

# Logging setup
LOG_FILE="/root/webserver-setup.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Configuration
DOMAIN=""
MYSQL_ROOT_PASSWORD=""
PHP_VERSION="8.1"
INSTALL_MYSQL=true
INSTALL_MARIADB=false
ENABLE_SSL=true
EMAIL=""
DEPLOYUSER="deploy"
APPLY_OPTIMIZATIONS=true
INSTALL_REDIS=true
INSTALL_MONITORING=true
INSTALL_SECURITY=true

# Enhanced logging functions
log() { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]${NC} $1"; }
error() { echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]${NC} $1"; }
success() { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS]${NC} $1"; }

# Robust package manager handling
check_and_wait_for_apt() {
    local max_wait=300 wait_time=0
    log "Checking package manager availability..."
    
    while [ $wait_time -lt $max_wait ]; do
        if ! pgrep -x "apt-get" > /dev/null && ! pgrep -x "apt" > /dev/null && \
           ! pgrep -x "dpkg" > /dev/null && [ ! -f /var/lib/dpkg/lock-frontend ] && \
           [ ! -f /var/lib/dpkg/lock ] && [ ! -f /var/cache/apt/archives/lock ]; then
            log "Package manager is available"
            return 0
        fi
        local remaining=$((max_wait - wait_time))
        warn "Waiting for package manager lock... (${remaining}s remaining)"
        sleep 10
        wait_time=$((wait_time + 10))
    done
    error "Timeout waiting for package manager lock after 5 minutes"
}

clear_apt_locks() {
    warn "Clearing package manager locks..."
    sudo pkill -9 apt-get 2>/dev/null || true
    sudo pkill -9 apt 2>/dev/null || true
    sudo pkill -9 dpkg 2>/dev/null || true
    sudo rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock
    sudo dpkg --configure -a 2>/dev/null || true
    log "Package manager locks cleared"
}

install_package() {
    local package=$1 max_retries=3 retry_count=0
    
    while [ $retry_count -lt $max_retries ]; do
        if check_and_wait_for_apt; then
            log "Installing: $package (attempt $((retry_count + 1))/$max_retries)"
            if sudo DEBIAN_FRONTEND=noninteractive apt-get install -yqq "$package"; then
                log "Successfully installed $package"
                return 0
            else
                retry_count=$((retry_count + 1))
                warn "Failed to install $package, attempt $retry_count/$max_retries"
                if [ $retry_count -eq $max_retries ]; then
                    error "Failed to install $package after $max_retries attempts"
                fi
                sleep 5
                clear_apt_locks
            fi
        else
            error "Cannot acquire package manager lock for $package"
        fi
    done
}

update_package_list() {
    local max_retries=3 retry_count=0
    
    while [ $retry_count -lt $max_retries ]; do
        if check_and_wait_for_apt; then
            log "Updating package list (attempt $((retry_count + 1))/$max_retries)"
            if sudo apt-get update -qq; then
                log "Package list updated successfully"
                return 0
            else
                retry_count=$((retry_count + 1))
                warn "Failed to update package list, attempt $retry_count/$max_retries"
                if [ $retry_count -eq $max_retries ]; then
                    error "Failed to update package list after $max_retries attempts"
                fi
                sleep 5
                clear_apt_locks
            fi
        else
            error "Cannot acquire package manager lock for update"
        fi
    done
}

# System check functions
check_system() {
    log "Checking system requirements..."
    
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root or with sudo"
    fi
    
    if [ ! -f /etc/os-release ]; then
        error "This script requires Ubuntu"
    fi
    
    source /etc/os-release
    if [ "$ID" != "ubuntu" ]; then
        error "This script is designed for Ubuntu"
    fi
    
    log "Ubuntu $VERSION_ID detected"
    
    # Check disk space
    local disk_space=$(df / | awk 'NR==2 {print $4}')
    if [ "$disk_space" -lt 1048576 ]; then
        warn "Low disk space (less than 1GB free)"
    fi
    
    # Check memory
    local memory=$(free -m | awk 'NR==2 {print $2}')
    if [ "$memory" -lt 512 ]; then
        warn "Low memory (less than 512MB)"
    fi
}

# User input function
get_user_input() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║           Ultimate Web Server Setup v$SCRIPT_VERSION            ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    
    # Domain name
    while [ -z "$DOMAIN" ]; do
        read -p "Enter your domain name (e.g., example.com): " DOMAIN
        if [ -z "$DOMAIN" ]; then
            warn "Domain name cannot be empty"
        fi
    done
    
    # PHP Version
    read -p "Enter PHP version to install (8.1, 8.2, 8.3) [default: $PHP_VERSION]: " input_php
    if [ -n "$input_php" ]; then
        PHP_VERSION="$input_php"
    fi
    
    # Database selection
    read -p "Install MySQL? (y/n) [default: y]: " mysql_choice
    if [[ "$mysql_choice" =~ ^[Nn]$ ]]; then
        INSTALL_MYSQL=false
        read -p "Install MariaDB instead? (y/n) [default: n]: " mariadb_choice
        if [[ "$mariadb_choice" =~ ^[Yy]$ ]]; then
            INSTALL_MARIADB=true
        fi
    fi
    
    # MySQL root password
    if [ "$INSTALL_MYSQL" = true ] || [ "$INSTALL_MARIADB" = true ]; then
        while [ -z "$MYSQL_ROOT_PASSWORD" ]; do
            read -sp "Enter MySQL/MariaDB root password: " MYSQL_ROOT_PASSWORD
            echo
            if [ -z "$MYSQL_ROOT_PASSWORD" ]; then
                warn "Database password cannot be empty"
            fi
        done
    fi
    
    # SSL setup
    if [ "$ENABLE_SSL" = true ]; then
        read -p "Enable SSL with Let's Encrypt? (y/n) [default: y]: " ssl_choice
        if [[ "$ssl_choice" =~ ^[Nn]$ ]]; then
            ENABLE_SSL=false
        else
            read -p "Enter email for Let's Encrypt (optional): " EMAIL
        fi
    fi
    
    # Additional services
    read -p "Install Redis for caching? (y/n) [default: y]: " redis_choice
    if [[ "$redis_choice" =~ ^[Nn]$ ]]; then
        INSTALL_REDIS=false
    fi
    
    read -p "Install monitoring tools? (y/n) [default: y]: " monitor_choice
    if [[ "$monitor_choice" =~ ^[Nn]$ ]]; then
        INSTALL_MONITORING=false
    fi
    
    read -p "Install security tools? (y/n) [default: y]: " security_choice
    if [[ "$security_choice" =~ ^[Nn]$ ]]; then
        INSTALL_SECURITY=false
    fi
    
    log "Configuration gathered successfully"
}

# Installation functions
install_essentials() {
    log "Installing essential packages..."
    
    if ! update_package_list; then
        error "Failed to update package list"
    fi
    
    local essential_packages=(
        "curl" "wget" "git" "unzip" "software-properties-common"
        "apt-transport-https" "ca-certificates" "gnupg" "ufw" "fail2ban"
        "htop" "iotop" "nethogs" "nmap"
    )
    
    for package in "${essential_packages[@]}"; do
        if ! install_package "$package"; then
            error "Failed to install essential package: $package"
        fi
    done
    
    log "Essential packages installed successfully"
}

install_nginx() {
    log "Installing Nginx..."
    
    # Stop Apache if running to avoid conflicts
    if systemctl is-active --quiet apache2 2>/dev/null; then
        log "Stopping Apache to avoid port conflicts..."
        systemctl stop apache2 2>/dev/null || true
        systemctl disable apache2 2>/dev/null || true
    fi
    
    if ! install_package "nginx"; then
        error "Failed to install Nginx"
    fi
    
    # Start and enable Nginx
    systemctl start nginx
    systemctl enable nginx
    
    log "Nginx installed and started successfully"
}

install_php() {
    log "Installing PHP $PHP_VERSION..."
    
    # Add PHP repository
    if ! install_package "software-properties-common"; then
        error "Failed to install software-properties-common"
    fi
    
    add-apt-repository -y ppa:ondrej/php
    
    if ! update_package_list; then
        error "Failed to update package list after adding PHP repo"
    fi
    
    # Install PHP and common extensions
    local php_packages=(
        "php$PHP_VERSION-fpm" "php$PHP_VERSION-common" "php$PHP_VERSION-mysql"
        "php$PHP_VERSION-xml" "php$PHP_VERSION-curl" "php$PHP_VERSION-gd"
        "php$PHP_VERSION-mbstring" "php$PHP_VERSION-zip" "php$PHP_VERSION-cli"
        "php$PHP_VERSION-bcmath" "php$PHP_VERSION-json" "php$PHP_VERSION-intl"
        "php$PHP_VERSION-soap" "php-redis"
    )
    
    for package in "${php_packages[@]}"; do
        if ! install_package "$package"; then
            error "Failed to install PHP package: $package"
        fi
    done
    
    # Start and enable PHP-FPM
    systemctl start "php$PHP_VERSION-fpm"
    systemctl enable "php$PHP_VERSION-fpm"
    
    log "PHP $PHP_VERSION installed successfully"
}

install_mysql() {
    log "Installing MySQL..."
    
    if ! install_package "mysql-server"; then
        error "Failed to install MySQL"
    fi
    
    # Start and enable MySQL
    systemctl start mysql
    systemctl enable mysql
    
    # Secure MySQL installation
    log "Securing MySQL installation..."
    
    # Generate secure root password if not provided
    if [ -z "$MYSQL_ROOT_PASSWORD" ]; then
        MYSQL_ROOT_PASSWORD=$(openssl rand -base64 32)
    fi
    
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$MYSQL_ROOT_PASSWORD';"
    mysql -e "DELETE FROM mysql.user WHERE User='';"
    mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
    mysql -e "DROP DATABASE IF EXISTS test;"
    mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
    mysql -e "FLUSH PRIVILEGES;"
    
    # Save credentials securely
    cat > /root/.my.cnf << EOF
[client]
user=root
password=$MYSQL_ROOT_PASSWORD
EOF
    chmod 600 /root/.my.cnf
    
    log "MySQL installed and secured successfully"
}

install_mariadb() {
    log "Installing MariaDB..."
    
    if ! install_package "mariadb-server"; then
        error "Failed to install MariaDB"
    fi
    
    # Start and enable MariaDB
    systemctl start mariadb
    systemctl enable mariadb
    
    # Secure MariaDB installation
    log "Securing MariaDB installation..."
    
    if [ -z "$MYSQL_ROOT_PASSWORD" ]; then
        MYSQL_ROOT_PASSWORD=$(openssl rand -base64 32)
    fi
    
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';"
    mysql -e "DELETE FROM mysql.user WHERE User='';"
    mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
    mysql -e "DROP DATABASE IF EXISTS test;"
    mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
    mysql -e "FLUSH PRIVILEGES;"
    
    # Save credentials securely
    cat > /root/.my.cnf << EOF
[client]
user=root
password=$MYSQL_ROOT_PASSWORD
EOF
    chmod 600 /root/.my.cnf
    
    log "MariaDB installed and secured successfully"
}

install_redis() {
    log "Installing Redis..."
    
    if ! install_package "redis-server"; then
        error "Failed to install Redis"
    fi
    
    # Generate secure password
    REDIS_PASSWORD=$(openssl rand -base64 32)
    
    # Configure Redis
    sed -i "s/^# requirepass .*/requirepass $REDIS_PASSWORD/" /etc/redis/redis.conf
    sed -i 's/^bind 127.0.0.1 ::1/bind 127.0.0.1/' /etc/redis/redis.conf
    
    # Start and enable Redis
    systemctl start redis-server
    systemctl enable redis-server
    
    # Save credentials securely
    cat > /root/.redis_credentials << EOF
Redis Connection Info:
Host: localhost
Port: 6379
Password: $REDIS_PASSWORD

Test connection:
redis-cli -a '$REDIS_PASSWORD' ping
EOF
    chmod 600 /root/.redis_credentials
    
    log "Redis installed and secured successfully"
}

# Configuration functions
configure_nginx() {
    log "Configuring Nginx for domain: $DOMAIN"
    
    # Create nginx configuration
    local nginx_config="/etc/nginx/sites-available/$DOMAIN"
    cat > "$nginx_config" << EOF
server {
    listen 80;
    listen [::]:80;
    
    server_name $DOMAIN www.$DOMAIN;
    root /var/www/html;
    index index.php index.html index.htm;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php$PHP_VERSION-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    location ~ /\.ht {
        deny all;
    }
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
}
EOF
    
    # Enable site
    ln -sf "$nginx_config" "/etc/nginx/sites-enabled/$DOMAIN"
    rm -f /etc/nginx/sites-enabled/default
    
    # Test nginx configuration
    if ! nginx -t; then
        error "Nginx configuration test failed"
    fi
    
    # Reload nginx
    systemctl reload nginx
    
    log "Nginx configured successfully for $DOMAIN"
}

install_ssl() {
    if [ "$ENABLE_SSL" != true ]; then
        log "SSL installation skipped"
        return 0
    fi
    
    log "Installing SSL certificate for $DOMAIN"
    
    # Install certbot
    if ! install_package "certbot python3-certbot-nginx"; then
        error "Failed to install certbot"
    fi
    
    # Obtain SSL certificate
    local certbot_cmd="certbot --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos"
    if [ -n "$EMAIL" ]; then
        certbot_cmd="$certbot_cmd --email $EMAIL"
    else
        certbot_cmd="$certbot_cmd --register-unsafely-without-email"
    fi
    
    if ! eval "$certbot_cmd"; then
        error "Failed to obtain SSL certificate"
    fi
    
    # Set up auto-renewal
    (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -
    
    log "SSL certificate installed and auto-renewal configured"
}

configure_firewall() {
    log "Configuring firewall..."
    
    # Enable UFW
    ufw --force enable
    
    # Allow SSH (be careful not to lock yourself out)
    ufw allow OpenSSH
    
    # Allow HTTP and HTTPS
    ufw allow 'Nginx Full'
    
    log "Firewall configured successfully"
}

# Performance optimization functions
optimize_os() {
    log "Applying OS-level performance optimizations..."
    
    # Increase file limits
    cat >> /etc/security/limits.conf << EOF
* soft nofile 65536
* hard nofile 65536
www-data soft nofile 65536
www-data hard nofile 65536
EOF

    # Kernel optimizations
    cat >> /etc/sysctl.conf << EOF
# Network performance
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.somaxconn = 65536

# Memory and file handling
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
fs.file-max = 100000
EOF

    sysctl -p
    log "OS-level optimizations applied"
}

optimize_nginx() {
    log "Optimizing Nginx performance..."
    
    local cpu_cores=$(nproc)
    local worker_connections=4096
    
    # Backup original config
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
    
    # Update worker processes
    sed -i "s/worker_processes auto;/worker_processes $cpu_cores;/" /etc/nginx/nginx.conf
    
    # Add performance settings
    if ! grep -q "worker_connections $worker_connections" /etc/nginx/nginx.conf; then
        sed -i "/events {/a\    worker_connections $worker_connections;\n    multi_accept on;\n    use epoll;" /etc/nginx/nginx.conf
    fi
    
    # Add HTTP performance optimizations
    if grep -q "http {" /etc/nginx/nginx.conf && ! grep -q "client_body_buffer_size" /etc/nginx/nginx.conf; then
        cat >> /etc/nginx/nginx.conf << 'EOF'

    # Performance Optimizations
    client_body_buffer_size 16K;
    client_header_buffer_size 1k;
    client_max_body_size 64m;
    large_client_header_buffers 4 8k;
    
    # Timeout optimizations
    client_body_timeout 12;
    client_header_timeout 12;
    keepalive_timeout 15;
    send_timeout 10;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;
EOF
    fi

    nginx -t && systemctl reload nginx
    log "Nginx optimized: $cpu_cores workers, $worker_connections connections/worker"
}

optimize_php_fpm() {
    local php_version=$1
    log "Optimizing PHP-FPM performance for PHP $php_version..."
    
    local php_pool="/etc/php/${php_version}/fpm/pool.d/www.conf"
    
    if [ ! -f "$php_pool" ]; then
        warn "PHP-FPM pool config not found: $php_pool"
        return 1
    fi
    
    # Backup original config
    cp "$php_pool" "${php_pool}.backup"
    
    # Calculate optimal values based on system resources
    local total_ram=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local ram_mb=$((total_ram / 1024))
    
    # Dynamic calculation based on available RAM
    local pm_max_children=$((ram_mb / 80))
    local pm_start_servers=$((pm_max_children / 4))
    local pm_min_spare_servers=$((pm_max_children / 8))
    local pm_max_spare_servers=$((pm_max_children / 4))
    
    # Ensure minimum values
    pm_max_children=$((pm_max_children < 20 ? 20 : pm_max_children))
    pm_start_servers=$((pm_start_servers < 5 ? 5 : pm_start_servers))
    pm_min_spare_servers=$((pm_min_spare_servers < 3 ? 3 : pm_min_spare_servers))
    pm_max_spare_servers=$((pm_max_spare_servers < 10 ? 10 : pm_max_spare_servers))
    
    # Apply optimizations
    sed -i "s/^pm\.max_children = .*/pm.max_children = $pm_max_children/" "$php_pool"
    sed -i "s/^pm\.start_servers = .*/pm.start_servers = $pm_start_servers/" "$php_pool"
    sed -i "s/^pm\.min_spare_servers = .*/pm.min_spare_servers = $pm_min_spare_servers/" "$php_pool"
    sed -i "s/^pm\.max_spare_servers = .*/pm.max_spare_servers = $pm_max_spare_servers/" "$php_pool"
    
    # Add additional settings
    echo "pm.process_idle_timeout = 10s" >> "$php_pool"
    echo "pm.max_requests = 1000" >> "$php_pool"

    systemctl restart "php${php_version}-fpm"
    log "PHP-FPM optimized: max_children=$pm_max_children, start_servers=$pm_start_servers"
}

optimize_mysql() {
    log "Optimizing MySQL performance..."
    
    local total_ram=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local ram_mb=$((total_ram / 1024))
    
    # Calculate buffer pool size (70% of available RAM, max 1GB)
    local buffer_pool_size=$((ram_mb * 70 / 100))
    buffer_pool_size=$((buffer_pool_size > 1024 ? 1024 : buffer_pool_size))
    
    # Create optimization file
    mkdir -p /etc/mysql/mariadb.conf.d/
    cat > /etc/mysql/mariadb.conf.d/99-performance.cnf << EOF
[mysqld]
# Memory settings
innodb_buffer_pool_size = ${buffer_pool_size}M
innodb_log_file_size = 128M
innodb_log_buffer_size = 16M
key_buffer_size = 256M
tmp_table_size = 64M
max_heap_table_size = 64M

# Connection settings
max_connections = 100
thread_cache_size = 16
table_open_cache = 4000

# InnoDB settings
innodb_flush_log_at_trx_commit = 2
innodb_file_per_table = 1
innodb_flush_method = O_DIRECT

# General settings
sort_buffer_size = 4M
read_buffer_size = 1M
read_rnd_buffer_size = 4M
join_buffer_size = 4M
EOF

    systemctl restart mysql
    log "MySQL optimized with ${buffer_pool_size}MB buffer pool"
}

optimize_redis() {
    log "Optimizing Redis performance..."
    
    local total_ram=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local ram_mb=$((total_ram / 1024))
    local redis_max_memory=$((ram_mb * 10 / 100))
    
    # Update Redis configuration
    sed -i "s/^#*maxmemory .*/maxmemory ${redis_max_memory}mb/" /etc/redis/redis.conf
    sed -i "s/^#*maxmemory-policy .*/maxmemory-policy allkeys-lru/" /etc/redis/redis.conf
    
    systemctl restart redis-server
    log "Redis optimized with ${redis_max_memory}MB memory limit"
}

# Security functions
configure_security() {
    log "Configuring system security..."
    
    # Configure Fail2Ban
    cat > /etc/fail2ban/jail.local << 'EOF'
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
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban
    
    # Install and configure rkhunter
    install_package "rkhunter"
    rkhunter --propupd --quiet
    
    # Configure automatic security updates
    install_package "unattended-upgrades"
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    log "Security configuration completed"
}

# Monitoring functions
install_monitoring() {
    log "Installing monitoring tools..."
    
    # Install Netdata
    if wget -O /tmp/netdata-kickstart.sh https://my-netdata.io/kickstart.sh 2>/dev/null; then
        bash /tmp/netdata-kickstart.sh --disable-telemetry --non-interactive --dont-wait 2>/dev/null || true
        rm -f /tmp/netdata-kickstart.sh
    fi
    
    # Create health monitoring endpoint
    cat > /var/www/html/health.php << 'EOF'
<?php
header('Content-Type: application/json');
$status = [
    'status' => 'healthy',
    'timestamp' => date('c'),
    'services' => [
        'nginx' => shell_exec('systemctl is-active nginx') ? 'active' : 'inactive',
        'php-fpm' => shell_exec('systemctl is-active php-fpm') ? 'active' : 'inactive',
        'mysql' => shell_exec('systemctl is-active mysql') ? 'active' : 'inactive',
        'redis' => shell_exec('systemctl is-active redis-server') ? 'active' : 'inactive',
    ]
];
echo json_encode($status, JSON_PRETTY_PRINT);
?>
EOF
    
    log "Monitoring tools installed"
}

# Backup system
setup_backups() {
    log "Setting up automated backup system..."
    
    mkdir -p /var/backups/website
    chmod 700 /var/backups/website
    
    cat > /usr/local/bin/backup-website.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/website"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR/daily" "$BACKUP_DIR/weekly" "$BACKUP_DIR/monthly"

# Create backups
tar -czf "$BACKUP_DIR/daily/webfiles_$TIMESTAMP.tar.gz" -C /var/www/html . 2>/dev/null
tar -czf "$BACKUP_DIR/daily/nginx_$TIMESTAMP.tar.gz" /etc/nginx 2>/dev/null

if systemctl is-active --quiet mysql 2>/dev/null; then
    mysqldump --all-databases --single-transaction --quick | gzip > "$BACKUP_DIR/daily/databases_$TIMESTAMP.sql.gz" 2>/dev/null
fi

# Cleanup old backups
find "$BACKUP_DIR/daily" -name "*.tar.gz" -mtime +7 -delete
find "$BACKUP_DIR/daily" -name "*.sql.gz" -mtime +7 -delete

echo "$(date): Backup completed" >> /var/log/website-backup.log
EOF

    chmod +x /usr/local/bin/backup-website.sh
    
    # Schedule daily backup at 2 AM
    (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/backup-website.sh") | crontab -
    
    # Run initial backup
    /usr/local/bin/backup-website.sh
    
    log "Automated backup system configured"
}

# Create web content
create_web_content() {
    log "Creating web content..."
    
    mkdir -p /var/www/html
    cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to $DOMAIN</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }
        .info { background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .success { color: #4CAF50; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Welcome to $DOMAIN</h1>
        <div class="info">
            <p class="success">Your web server is successfully configured and optimized!</p>
            <p><strong>PHP Version:</strong> $PHP_VERSION</p>
            <p><strong>Server Time:</strong> $(date)</p>
            <p><strong>Web Root:</strong> /var/www/html</p>
        </div>
        <p>Upload your website files to get started!</p>
        
        <div class="info">
            <h3>Quick Links:</h3>
            <ul>
                <li><a href="/health.php">Server Health Status</a></li>
                <li><a href="http://$(hostname -I | awk '{print $1}'):19999">Netdata Monitoring</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
EOF

    # Create PHP test file
    cat > /var/www/html/test.php << 'EOF'
<?php
echo "<!DOCTYPE html><html><head><title>PHP Test</title></head><body>";
echo "<h1>✅ PHP is Working!</h1>";
echo "<p>PHP Version: " . PHP_VERSION . "</p>";
echo "<p>Server: " . $_SERVER['SERVER_SOFTWARE'] . "</p>";
echo "</body></html>";
?>
EOF

    chown -R www-data:www-data /var/www/html
    chmod -R 755 /var/www/html
    
    log "Web content created successfully"
}

# Beautiful completion message
show_completion() {
    local ip_address=$(hostname -I | awk '{print $1}')
    
    echo
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║          🚀 WEB SERVER SETUP COMPLETE! 🚀                   ║"
    echo "║                                                              ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║                                                              ║"
    echo -e "║    ${CYAN}🌐 Domain:${GREEN} $DOMAIN${GREEN}                                   ║"
    echo -e "║    ${CYAN}📁 Web Root:${GREEN} /var/www/html${GREEN}                              ║"
    echo -e "║    ${CYAN}🐘 PHP Version:${GREEN} $PHP_VERSION${GREEN}                                  ║"
    echo -e "║    ${CYAN}🌐 Server IP:${GREEN} $ip_address${GREEN}                               ║"
    
    if [ "$INSTALL_MYSQL" = true ]; then
        echo -e "║    ${CYAN}🗄️  MySQL:${GREEN} Installed ✅${GREEN}                                 ║"
    fi
    
    if [ "$INSTALL_MARIADB" = true ]; then
        echo -e "║    ${CYAN}🗄️  MariaDB:${GREEN} Installed ✅${GREEN}                               ║"
    fi
    
    if [ "$INSTALL_REDIS" = true ]; then
        echo -e "║    ${CYAN}⚡ Redis:${GREEN} Installed ✅${GREEN}                                  ║"
    fi
    
    if [ "$ENABLE_SSL" = true ]; then
        echo -e "║    ${CYAN}🔒 SSL:${GREEN} Enabled (Let's Encrypt) ✅${GREEN}                    ║"
    fi
    
    echo "║                                                              ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║                                                              ║"
    echo -e "║    ${YELLOW}📋 NEXT STEPS:${GREEN}                                            ║"
    echo "║                                                              ║"
    echo -e "║    ${GREEN}1. 📤 Upload website to /var/www/html/${GREEN}                    ║"
    echo -e "║    ${GREEN}2. 🌐 Configure DNS for $DOMAIN${GREEN}                  ║"
    echo -e "║    ${GREEN}3. 🔧 Test PHP: visit $DOMAIN/test.php${GREEN}           ║"
    echo -e "║    ${GREEN}4. 🩺 Check health: $DOMAIN/health.php${GREEN}           ║"
    echo "║                                                              ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║                                                              ║"
    echo -e "║    ${CYAN}🛠️  USEFUL COMMANDS:${GREEN}                                        ║"
    echo "║                                                              ║"
    echo -e "║    ${GREEN}sudo systemctl status nginx${GREEN}                                ║"
    echo -e "║    ${GREEN}sudo systemctl status php${PHP_VERSION}-fpm${GREEN}                        ║"
    echo -e "║    ${GREEN}sudo systemctl status mysql${GREEN}                                ║"
    echo -e "║    ${GREEN}sudo ufw status${GREEN}                                            ║"
    echo "║                                                              ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║                                                              ║"
    echo -e "║    ${MAGENTA}📊 SERVER INFORMATION:${GREEN}                                     ║"
    echo "║                                                              ║"
    echo -e "║    ${GREEN}IP Address: $ip_address${GREEN}                          ║"
    echo -e "║    ${GREEN}Disk Space: $(df -h / | awk 'NR==2 {print $4}') free${GREEN}        ║"
    echo -e "║    ${GREEN}Memory: $(free -h | awk 'NR==2 {print $4}') available${GREEN}       ║"
    echo -e "║    ${GREEN}Server Time: $(date)${GREEN}                       ║"
    echo "║                                                              ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║                                                              ║"
    echo -e "║    ${YELLOW}📝 Full installation log: $LOG_FILE${GREEN}             ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
    log "Web server is ready! Upload your files and configure DNS."
}

# Main execution function
main() {
    log "Starting Ultimate Web Server Setup v$SCRIPT_VERSION"
    log "Log file: $LOG_FILE"
    
    # Check system requirements
    check_system
    
    # Get user input
    get_user_input
    
    # Install components
    install_essentials
    install_nginx
    install_php
    
    if [ "$INSTALL_MYSQL" = true ]; then
        install_mysql
    elif [ "$INSTALL_MARIADB" = true ]; then
        install_mariadb
    fi
    
    if [ "$INSTALL_REDIS" = true ]; then
        install_redis
    fi
    
    # Configuration
    configure_nginx
    install_ssl
    configure_firewall
    
    # Apply optimizations automatically
    if [ "$APPLY_OPTIMIZATIONS" = true ]; then
        log "Applying automatic performance optimizations..."
        optimize_os
        optimize_nginx
        optimize_php_fpm "$PHP_VERSION"
        
        if [ "$INSTALL_MYSQL" = true ] || [ "$INSTALL_MARIADB" = true ]; then
            optimize_mysql
        fi
        
        if [ "$INSTALL_REDIS" = true ]; then
            optimize_redis
        fi
        log "Performance optimizations completed"
    fi
    
    # Security configuration
    if [ "$INSTALL_SECURITY" = true ]; then
        configure_security
    fi
    
    # Monitoring setup
    if [ "$INSTALL_MONITORING" = true ]; then
        install_monitoring
    fi
    
    # Backup system
    setup_backups
    
    # Create web content
    create_web_content
    
    # Show completion message
    show_completion
    
    log "Web server setup completed successfully!"
}

# Error handlers
trap 'error "Script interrupted at line $LINENO"; exit 1' INT TERM
trap 'error "Script failed at line $LINENO. Check $LOG_FILE for details."' ERR

# Run main function
main "$@"
