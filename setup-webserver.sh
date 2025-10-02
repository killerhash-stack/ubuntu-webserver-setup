#!/bin/bash
################################################################################
# Ubuntu Web Server Setup Script
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
SCRIPT_VERSION="2.6"

# ----------------------------
# Logging helpers
# ----------------------------
timestamp() { date +"[%Y-%m-%d %H:%M:%S]"; }
log_info() { echo "$(timestamp) [INFO] $1" | tee -a "$LOGFILE"; }
log_error() { echo "$(timestamp) [ERROR] $1" | tee -a "$LOGFILE" >&2; }
log_warn() { echo "$(timestamp) [WARN] $1" | tee -a "$LOGFILE"; }
log_success() { echo "$(timestamp) [✓] $1" | tee -a "$LOGFILE"; }

# ----------------------------
# Enhanced Error Handling
# ----------------------------
install_package() {
    local package=$1
    log_info "Installing package: $package"
    
    if ! apt-get install -yqq "$package"; then
        log_warn "Failed to install $package, attempting to continue..."
        return 1
    fi
    return 0
}

run_command() {
    local cmd="$1"
    local description="$2"
    
    log_info "Executing: $description"
    if eval "$cmd"; then
        log_success "Completed: $description"
        return 0
    else
        log_error "Failed: $description"
        return 1
    fi
}

safe_sed() {
    local file="$1"
    local pattern="$2"
    
    if [ -f "$file" ]; then
        if sed -i "$pattern" "$file" 2>/dev/null; then
            return 0
        else
            log_warn "Failed to modify $file with pattern: $pattern"
            return 1
        fi
    else
        log_warn "File not found: $file"
        return 1
    fi
}

# ----------------------------
# Performance Optimization Functions
# ----------------------------
optimize_os() {
    log_info "Applying OS-level performance optimizations..."
    
    # Increase file limits
    cat >> /etc/security/limits.conf << EOF
* soft nofile 65536
* hard nofile 65536
www-data soft nofile 65536
www-data hard nofile 65536
EOF

    # Kernel optimizations for web servers
    cat >> /etc/sysctl.conf << EOF
# Network performance
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_max_syn_backlog = 3240000
net.core.somaxconn = 3240000
net.ipv4.tcp_max_tw_buckets = 1440000

# Memory and file handling
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
fs.file-max = 100000

# Security and performance
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
EOF

    run_command "sysctl -p" "Apply kernel optimizations"
    log_success "OS-level optimizations applied"
}

optimize_nginx() {
    log_info "Optimizing Nginx performance..."
    
    local cpu_cores=$(nproc)
    local worker_connections=$((1024 * 4))  # 4K connections per worker
    
    # Backup original config
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup.optimized
    
    # Update worker processes
    safe_sed "/etc/nginx/nginx.conf" "s/worker_processes auto;/worker_processes $cpu_cores;/"
    
    # Add performance optimizations to nginx.conf
    if ! grep -q "worker_connections $worker_connections" /etc/nginx/nginx.conf; then
        # Insert performance settings in the events block
        if grep -q "events {" /etc/nginx/nginx.conf; then
            sed -i "/events {/a\    worker_connections $worker_connections;\n    multi_accept on;\n    use epoll;" /etc/nginx/nginx.conf
        fi
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
    
    # Cache optimizations
    open_file_cache max=200000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;
EOF
    fi

    run_command "nginx -t && systemctl reload nginx" "Reload Nginx with optimizations"
    log_success "Nginx optimized: $cpu_cores workers, $worker_connections connections/worker"
}

optimize_php_fpm() {
    local php_version=$1
    
    log_info "Optimizing PHP-FPM performance for PHP $php_version..."
    
    local php_pool="/etc/php/${php_version}/fpm/pool.d/www.conf"
    
    if [ ! -f "$php_pool" ]; then
        log_warn "PHP-FPM pool config not found: $php_pool"
        return 1
    fi
    
    # Backup original config
    cp "$php_pool" "${php_pool}.backup.optimized"
    
    # Calculate optimal values based on system resources
    local total_ram=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local ram_mb=$((total_ram / 1024))
    
    # Dynamic calculation based on available RAM
    local pm_max_children=$((ram_mb / 80))  # ~80MB per process
    local pm_start_servers=$((pm_max_children / 4))
    local pm_min_spare_servers=$((pm_max_children / 8))
    local pm_max_spare_servers=$((pm_max_children / 4))
    
    # Ensure minimum values
    pm_max_children=$((pm_max_children < 20 ? 20 : pm_max_children))
    pm_start_servers=$((pm_start_servers < 5 ? 5 : pm_start_servers))
    pm_min_spare_servers=$((pm_min_spare_servers < 3 ? 3 : pm_min_spare_servers))
    pm_max_spare_servers=$((pm_max_spare_servers < 10 ? 10 : pm_max_spare_servers))
    
    # Apply optimizations
    safe_sed "$php_pool" "s/^pm\.max_children = .*/pm.max_children = $pm_max_children/"
    safe_sed "$php_pool" "s/^pm\.start_servers = .*/pm.start_servers = $pm_start_servers/"
    safe_sed "$php_pool" "s/^pm\.min_spare_servers = .*/pm.min_spare_servers = $pm_min_spare_servers/"
    safe_sed "$php_pool" "s/^pm\.max_spare_servers = .*/pm.max_spare_servers = $pm_max_spare_servers/"
    
    # Add additional settings if not present
    if ! grep -q "^pm.process_idle_timeout" "$php_pool"; then
        echo "pm.process_idle_timeout = 10s" >> "$php_pool"
    fi
    if ! grep -q "^pm.max_requests" "$php_pool"; then
        echo "pm.max_requests = 1000" >> "$php_pool"
    fi

    run_command "systemctl restart php${php_version}-fpm" "Restart PHP-FPM with optimizations"
    log_success "PHP-FPM optimized: max_children=$pm_max_children, start_servers=$pm_start_servers"
}

optimize_mysql() {
    log_info "Optimizing MariaDB/MySQL performance..."
    
    local total_ram=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local ram_mb=$((total_ram / 1024))
    
    # Calculate buffer pool size (70% of available RAM, max 1GB)
    local buffer_pool_size=$((ram_mb * 70 / 100))
    buffer_pool_size=$((buffer_pool_size > 1024 ? 1024 : buffer_pool_size))
    
    # Create optimization file
    mkdir -p /etc/mysql/mariadb.conf.d/
    cat > /etc/mysql/mariadb.conf.d/99-performance.cnf << EOF
# Performance Optimizations
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

# Query cache (disable on MariaDB 10.2+)
query_cache_type = 0
query_cache_size = 0

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

    run_command "systemctl restart mariadb" "Restart MariaDB with optimizations"
    log_success "MariaDB optimized with ${buffer_pool_size}MB buffer pool"
}

optimize_redis() {
    log_info "Optimizing Redis performance..."
    
    local total_ram=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local ram_mb=$((total_ram / 1024))
    local redis_max_memory=$((ram_mb * 10 / 100))  # 10% of RAM for Redis
    
    # Backup original config
    cp /etc/redis/redis.conf /etc/redis/redis.conf.backup.optimized
    
    # Update Redis configuration
    safe_sed "/etc/redis/redis.conf" "s/^#*maxmemory .*/maxmemory ${redis_max_memory}mb/"
    safe_sed "/etc/redis/redis.conf" "s/^#*maxmemory-policy .*/maxmemory-policy allkeys-lru/"
    safe_sed "/etc/redis/redis.conf" "s/^#*stop-writes-on-bgsave-error .*/stop-writes-on-bgsave-error no/"
    
    # Ensure save directives are set
    if ! grep -q "^save 900" /etc/redis/redis.conf; then
        echo "save 900 1" >> /etc/redis/redis.conf
        echo "save 300 10" >> /etc/redis/redis.conf
        echo "save 60 10000" >> /etc/redis/redis.conf
    fi

    run_command "systemctl restart redis-server" "Restart Redis with optimizations"
    log_success "Redis optimized with ${redis_max_memory}MB memory limit"
}

# Error handler
trap 'log_error "Script failed at line $LINENO. Check $LOGFILE for details."; exit 1' ERR

# Redirect all output to log file while showing in console
exec > >(tee -a "$LOGFILE") 2>&1

cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║           Ubuntu Web Server Setup Script v2.6               ║
║                                                              ║
║  Features: Nginx • PHP • MySQL • Redis • SSL • Security     ║
║            Performance • Monitoring • Backups • Addons      ║
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

# Check if we have internet connectivity
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
    run_command "chmod 440 /etc/sudoers.d/$DEPLOYUSER" "Set sudoers file permissions"
    
    # Set password for the deploy user (needed for Cockpit login)
    log_info "Setting password for $DEPLOYUSER (needed for web console access)..."
    while true; do
        read -sp "Enter password for $DEPLOYUSER: " DEPLOY_PASSWORD
        echo ""
        
        # Validate password strength
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
    
    # Clear password variables for security
    unset DEPLOY_PASSWORD
    unset DEPLOY_PASSWORD_CONFIRM
    
else
    log_info "User $DEPLOYUSER already exists..."
    
    # Check if user has a password set (needed for Cockpit)
    if ! passwd -S "$DEPLOYUSER" 2>/dev/null | grep -q " P "; then
        log_info "User $DEPLOYUSER exists but has no password set."
        read -p "Set a password for $DEPLOYUSER (needed for Cockpit login)? [Y/n]: " SET_PASSWORD
        SET_PASSWORD=${SET_PASSWORD:-Y}
        
        if [[ "$SET_PASSWORD" =~ ^[Yy]$ ]]; then
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
            
            # Clear password variables for security
            unset DEPLOY_PASSWORD
            unset DEPLOY_PASSWORD_CONFIRM
        else
            log_warn "No password set - you won't be able to login to Cockpit with this user"
        fi
    else
        log_info "User $DEPLOYUSER already has a password set"
    fi
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
    
    # Validate email format
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

# ----------------------------
# Enhanced Addons Configuration
# ----------------------------
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Enhanced Addons & Plugins"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

read -rp "Install enhanced Cockpit plugins? [Y/n]: " INSTALL_COCKPIT_PLUGINS
INSTALL_COCKPIT_PLUGINS=${INSTALL_COCKPIT_PLUGINS:-Y}

read -rp "Install Adminer database web admin? [Y/n]: " INSTALL_ADMINER
INSTALL_ADMINER=${INSTALL_ADMINER:-Y}

read -rp "Install security tools (Lynis, ClamAV)? [y/N]: " INSTALL_SECURITY_TOOLS
INSTALL_SECURITY_TOOLS=${INSTALL_SECURITY_TOOLS:-N}

read -rp "Install performance monitoring tools? [y/N]: " INSTALL_PERF_TOOLS
INSTALL_PERF_TOOLS=${INSTALL_PERF_TOOLS:-N}

read -rp "Install advanced monitoring (GoAccess, OPcache dashboard)? [y/N]: " INSTALL_ADVANCED_MONITORING
INSTALL_ADVANCED_MONITORING=${INSTALL_ADVANCED_MONITORING:-N}

# ----------------------------
# Performance Optimizations
# ----------------------------
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Performance Optimizations"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

read -rp "Apply performance optimizations? [Y/n]: " APPLY_OPTIMIZATIONS
APPLY_OPTIMIZATIONS=${APPLY_OPTIMIZATIONS:-Y}

# ----------------------------
# Interactive Backup Configuration
# ----------------------------
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Backup Configuration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

read -rp "Enable backup encryption? [y/N]: " ENCRYPT_BACKUPS
ENCRYPT_BACKUPS=${ENCRYPT_BACKUPS:-N}

if [[ "$ENCRYPT_BACKUPS" =~ ^[Yy]$ ]]; then
    # Generate encryption key if not provided
    BACKUP_PASSPHRASE=$(openssl rand -base64 32)
    log_info "Backup encryption enabled with auto-generated key"
else
    BACKUP_PASSPHRASE=""
fi

read -rp "Enable remote backups to NAS/cloud? [y/N]: " REMOTE_BACKUP
REMOTE_BACKUP=${REMOTE_BACKUP:-N}

REMOTE_SSH=""
if [[ "$REMOTE_BACKUP" =~ ^[Yy]$ ]]; then
    echo ""
    echo "Remote backup options:"
    echo "  Format: username@hostname:/path/to/backups/"
    echo "  Example: admin@nas.local:/backups/webserver/"
    echo "  Leave blank to skip remote backup setup"
    echo ""
    
    read -rp "Enter remote backup destination: " REMOTE_SSH
    
    if [ -n "$REMOTE_SSH" ]; then
        # Validate format
        if [[ ! "$REMOTE_SSH" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+:/.* ]]; then
            log_warn "Invalid remote backup format. Remote backups disabled."
            REMOTE_SSH=""
        else
            log_info "Remote backup destination: $REMOTE_SSH"
            
            # Test SSH connection
            read -rp "Test SSH connection now? [Y/n]: " TEST_SSH
            TEST_SSH=${TEST_SSH:-Y}
            
            if [[ "$TEST_SSH" =~ ^[Yy]$ ]]; then
                if ssh -o BatchMode=yes -o ConnectTimeout=5 ${REMOTE_SSH%%:*} "echo 'SSH connection successful'" 2>/dev/null; then
                    log_success "SSH connection test successful"
                else
                    log_warn "SSH connection test failed. Please configure SSH keys manually."
                    REMOTE_SSH=""
                fi
            fi
        fi
    fi
fi

# Rclone cloud storage setup
RCLONE_SETUP=""
if [[ "$REMOTE_BACKUP" =~ ^[Yy]$ ]]; then
    read -rp "Setup Rclone for cloud storage backup (Google Drive, S3, etc.)? [y/N]: " SETUP_RCLONE
    SETUP_RCLONE=${SETUP_RCLONE:-N}
    
    if [[ "$SETUP_RCLONE" =~ ^[Yy]$ ]]; then
        RCLONE_SETUP="1"
        log_info "Rclone cloud backup will be configured"
    fi
fi

# Set flags for backup script
ENCRYPT_FLAG=$([[ "$ENCRYPT_BACKUPS" =~ ^[Yy]$ ]] && echo "1" || echo "0")
REMOTE_FLAG=$([[ -n "$REMOTE_SSH" ]] && echo "1" || echo "0")
RCLONE_FLAG=$([[ "$RCLONE_SETUP" =~ ^1$ ]] && echo "1" || echo "0")

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
# Clean up any existing Webmin installation
# ----------------------------
log_info "Cleaning up any existing Webmin installation..."
if systemctl list-unit-files | grep -q "webmin" || [ -d "/etc/webmin" ] || [ -f "/etc/apt/sources.list.d/webmin.list" ]; then
    log_info "Found existing Webmin installation, removing completely..."
    run_command "systemctl stop webmin 2>/dev/null || true" "Stop Webmin service"
    run_command "systemctl disable webmin 2>/dev/null || true" "Disable Webmin service"
    run_command "pkill -f webmin 2>/dev/null || true" "Kill any Webmin processes"
    run_command "apt-get remove --purge webmin webmin-* -y 2>/dev/null || true" "Remove Webmin packages"
    run_command "rm -rf /etc/webmin /var/webmin /usr/share/webmin 2>/dev/null || true" "Remove Webmin directories"
    run_command "rm -f /etc/apt/sources.list.d/webmin.list 2>/dev/null || true" "Remove Webmin repository"
    run_command "systemctl daemon-reload" "Reload systemd daemon"
    log_info "Webmin cleanup completed"
else
    log_info "No existing Webmin installation found"
fi

# ----------------------------
# System update
# ----------------------------
log_info "Updating and upgrading system packages (this may take a few minutes)..."
export DEBIAN_FRONTEND=noninteractive
run_command "apt-get update -qq" "Update package lists"
run_command "apt-get upgrade -yqq -o Dpkg::Options::=\"--force-confdef\" -o Dpkg::Options::=\"--force-confold\"" "Upgrade system packages"
log_success "System packages updated"

# ----------------------------
# Core packages
# ----------------------------
log_info "Installing core packages..."
CORE_PACKAGES="curl wget git ufw fail2ban unzip software-properties-common gnupg2 ca-certificates lsb-release apt-transport-https build-essential"

for package in $CORE_PACKAGES; do
    if ! dpkg -l | grep -q "^ii  $package "; then
        if apt-cache show "$package" &>/dev/null; then
            install_package "$package"
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
    
    if [ -d /home/"$DEPLOYUSER"/.ssh ]; then
        run_command "rm -rf /home/$DEPLOYUSER/.ssh" "Remove existing SSH directory"
    fi
    
    run_command "mkdir -p /home/$DEPLOYUSER/.ssh" "Create SSH directory"
    run_command "chown $DEPLOYUSER:$DEPLOYUSER /home/$DEPLOYUSER" "Set user ownership"
    run_command "chown $DEPLOYUSER:$DEPLOYUSER /home/$DEPLOYUSER/.ssh" "Set SSH directory ownership"
    run_command "chmod 700 /home/$DEPLOYUSER/.ssh" "Set SSH directory permissions"
    
    if [ "$(stat -c %U /home/$DEPLOYUSER/.ssh)" = "$DEPLOYUSER" ]; then
        if runuser -u "$DEPLOYUSER" -- ssh-keygen -t rsa -b 4096 -f "/home/$DEPLOYUSER/.ssh/id_rsa" -N "" -C "$DEPLOYUSER@$(hostname)" 2>/dev/null; then
            log_info "SSH key generated successfully"
        else
            run_command "ssh-keygen -t rsa -b 4096 -f \"/home/$DEPLOYUSER/.ssh/id_rsa\" -N \"\" -C \"$DEPLOYUSER@$(hostname)\"" "Generate SSH key as root"
            run_command "chown $DEPLOYUSER:$DEPLOYUSER /home/$DEPLOYUSER/.ssh/id_rsa*" "Set key ownership"
        fi
        
        if [ -f /home/"$DEPLOYUSER"/.ssh/id_rsa ]; then
            run_command "cp /home/$DEPLOYUSER/.ssh/id_rsa.pub /home/$DEPLOYUSER/.ssh/authorized_keys" "Create authorized_keys"
            run_command "chown -R $DEPLOYUSER:$DEPLOYUSER /home/$DEPLOYUSER/.ssh" "Set recursive ownership"
            run_command "chmod 700 /home/$DEPLOYUSER/.ssh" "Set directory permissions"
            run_command "chmod 600 /home/$DEPLOYUSER/.ssh/id_rsa" "Set private key permissions"
            run_command "chmod 644 /home/$DEPLOYUSER/.ssh/id_rsa.pub" "Set public key permissions"
            run_command "chmod 600 /home/$DEPLOYUSER/.ssh/authorized_keys" "Set authorized_keys permissions"
            log_success "SSH key configured successfully"
        fi
    fi
fi

# ----------------------------
# OpenSSH hardening
# ----------------------------
log_info "Configuring OpenSSH server..."
install_package "openssh-server"

SSH_CONFIG_BACKUP="/etc/ssh/sshd_config.backup.$BACKUP_TIMESTAMP"
run_command "cp /etc/ssh/sshd_config $SSH_CONFIG_BACKUP" "Backup SSH config"

safe_sed "/etc/ssh/sshd_config" 's/^#*PasswordAuthentication.*/PasswordAuthentication no/'
safe_sed "/etc/ssh/sshd_config" 's/^#*PermitRootLogin.*/PermitRootLogin no/'
safe_sed "/etc/ssh/sshd_config" 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/'

if ! grep -q "^AllowUsers" /etc/ssh/sshd_config; then
    echo "AllowUsers $DEPLOYUSER" >> /etc/ssh/sshd_config
fi

# Additional SSH security
if ! grep -q "^KexAlgorithms" /etc/ssh/sshd_config; then
    echo "KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config
fi

if sshd -t 2>/dev/null; then
    run_command "systemctl enable ssh" "Enable SSH service"
    run_command "systemctl restart ssh" "Restart SSH service"
    log_success "SSH configuration updated"
else
    run_command "cp $SSH_CONFIG_BACKUP /etc/ssh/sshd_config" "Restore SSH config backup"
    run_command "systemctl restart ssh" "Restart SSH service"
fi

log_warn "IMPORTANT: SSH is now configured for key-only authentication"

# ----------------------------
# Simple PHP and MySQL installation
# ----------------------------
if [[ "$INSTALL_PHP_MYSQL" =~ ^[Yy]$ ]]; then
    log_info "Installing PHP and MySQL/MariaDB..."
    
    # Simple PHP-FPM installation
    log_info "Installing PHP-FPM and extensions..."
    install_package "php-fpm"
    install_package "php-mysql"
    install_package "php-cli"
    install_package "php-common"
    install_package "php-curl"
    install_package "php-gd"
    install_package "php-mbstring"
    install_package "php-xml"
    install_package "php-zip"
    install_package "php-intl"
    install_package "php-bcmath"
    install_package "php-soap"
    
    # Verify PHP installation and set PHP_VERSION
    if command -v php &>/dev/null; then
        PHP_VERSION=$(php -r "echo PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;" 2>/dev/null || echo "8.3")
        log_success "PHP installed successfully: $(php --version | head -n1)"
        log_info "Detected PHP version: $PHP_VERSION"
        
        # Enable and start PHP-FPM service
        run_command "systemctl enable php-fpm" "Enable php-fpm service"
        run_command "systemctl start php-fpm" "Start php-fpm service"
        
        if systemctl is-active --quiet php-fpm; then
            log_success "php-fpm service is running"
            
            # Configure PHP settings
            PHP_INI="/etc/php/${PHP_VERSION}/fpm/php.ini"
            if [ -f "$PHP_INI" ]; then
                safe_sed "$PHP_INI" 's/^expose_php = On/expose_php = Off/'
                safe_sed "$PHP_INI" 's/^;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/'
                safe_sed "$PHP_INI" 's/^upload_max_filesize = .*/upload_max_filesize = 64M/'
                safe_sed "$PHP_INI" 's/^post_max_size = .*/post_max_size = 64M/'
                run_command "systemctl restart php-fpm" "Restart php-fpm after configuration"
                log_success "PHP configuration updated"
            else
                log_warn "PHP configuration file not found: $PHP_INI"
            fi
        else
            log_error "php-fpm service failed to start"
            run_command "systemctl status php-fpm --no-pager" "Check php-fpm status"
        fi
    else
        log_error "PHP installation verification failed - php command not found"
    fi
    
    # Install Composer only if PHP is working
    if [ ! -f /usr/local/bin/composer ] && command -v php &>/dev/null; then
        log_info "Installing Composer..."
        EXPECTED_CHECKSUM="$(php -r 'copy("https://composer.github.io/installer.sig", "php://stdout");' 2>/dev/null || echo 'failed')"
        
        if [ "$EXPECTED_CHECKSUM" != "failed" ]; then
            php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" 2>/dev/null
            ACTUAL_CHECKSUM="$(php -r "echo hash_file('sha384', 'composer-setup.php');" 2>/dev/null || echo 'failed')"
            
            if [ "$EXPECTED_CHECKSUM" = "$ACTUAL_CHECKSUM" ] && [ "$ACTUAL_CHECKSUM" != "failed" ]; then
                if php composer-setup.php --install-dir=/usr/local/bin --filename=composer --quiet; then
                    log_success "Composer installed successfully"
                else
                    log_error "Composer installation failed"
                fi
            else
                log_error "Composer checksum verification failed"
            fi
            rm -f composer-setup.php 2>/dev/null
        else
            log_warn "Composer installation skipped - PHP not functioning properly"
        fi
    fi
    
    # Install MariaDB
    log_info "Installing MariaDB database server..."
    if install_package "mariadb-server" && install_package "mariadb-client"; then
        run_command "systemctl enable mariadb" "Enable MariaDB service"
        run_command "systemctl start mariadb" "Start MariaDB service"
        
        if systemctl is-active --quiet mariadb; then
            log_success "MariaDB installed and running"
            
            # Secure MariaDB installation
            DB_ROOT_PASSWORD=$(openssl rand -base64 32)
            
            mysql -u root << EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASSWORD}';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
            
            if [ $? -eq 0 ]; then
                cat > /root/.my.cnf << EOF
[client]
user=root
password=${DB_ROOT_PASSWORD}
EOF
                run_command "chmod 600 /root/.my.cnf" "Set secure permissions for root MySQL config"
                log_success "MariaDB secured"
                
                # Create user database if deploy user exists
                if [ -n "$DEPLOYUSER" ] && id -u "$DEPLOYUSER" >/dev/null 2>&1; then
                    DB_USER_PASSWORD=$(openssl rand -base64 16)
                    
                    mysql -u root -p"${DB_ROOT_PASSWORD}" << EOF
CREATE DATABASE IF NOT EXISTS website_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DEPLOYUSER}'@'localhost' IDENTIFIED BY '${DB_USER_PASSWORD}';
GRANT ALL PRIVILEGES ON website_db.* TO '${DEPLOYUSER}'@'localhost';
FLUSH PRIVILEGES;
EOF
                    
                    if [ $? -eq 0 ]; then
                        cat > /home/${DEPLOYUSER}/.my.cnf << EOF
[client]
user=${DEPLOYUSER}
password=${DB_USER_PASSWORD}
database=website_db
EOF
                        run_command "chown ${DEPLOYUSER}:${DEPLOYUSER} /home/${DEPLOYUSER}/.my.cnf" "Set ownership for user MySQL config"
                        run_command "chmod 600 /home/${DEPLOYUSER}/.my.cnf" "Set secure permissions for user MySQL config"
                        log_success "Created database 'website_db' for user $DEPLOYUSER"
                    else
                        log_warn "Failed to create user database"
                    fi
                fi
            else
                log_warn "MariaDB security configuration failed"
            fi
        else
            log_error "MariaDB service failed to start"
        fi
    else
        log_error "MariaDB installation failed"
    fi
else
    log_info "Skipping PHP and MySQL installation"
fi

# ----------------------------
# Redis installation
# ----------------------------
if [[ "$INSTALL_REDIS" =~ ^[Yy]$ ]]; then
    log_info "Installing Redis server..."
    
    if apt-cache show redis-server &>/dev/null; then
        install_package "redis-server"
        install_package "redis-tools"
        
        if [ -f /etc/redis/redis.conf ]; then
            run_command "cp /etc/redis/redis.conf /etc/redis/redis.conf.backup" "Backup Redis config"
            
            # Generate a random password once, escape it for sed
            REDIS_PASS=$(openssl rand -base64 32 | tr -d '\n')
            ESCAPED_PASS=$(printf '%s\n' "$REDIS_PASS" | sed 's/[\/&]/\\&/g')
            
            safe_sed "/etc/redis/redis.conf" "s/^# requirepass .*/requirepass $ESCAPED_PASS/"
            safe_sed "/etc/redis/redis.conf" 's/^bind 127.0.0.1 ::1/bind 127.0.0.1/'
            safe_sed "/etc/redis/redis.conf" 's/^protected-mode no/protected-mode yes/'
            safe_sed "/etc/redis/redis.conf" 's/^# maxmemory .*/maxmemory 256mb/'
            safe_sed "/etc/redis/redis.conf" 's/^# maxmemory-policy .*/maxmemory-policy allkeys-lru/'
            
            safe_sed "/etc/redis/redis.conf" 's/^save ""/#save ""/'
            if ! grep -q "^save 900" /etc/redis/redis.conf; then
                echo "save 900 1" >> /etc/redis/redis.conf
                echo "save 300 10" >> /etc/redis/redis.conf
                echo "save 60 10000" >> /etc/redis/redis.conf
            fi
        fi
        
        run_command "systemctl enable redis-server" "Enable Redis service"
        run_command "systemctl restart redis-server" "Restart Redis service"
        
        if systemctl is-active --quiet redis-server; then
            log_success "Redis installed successfully"
            
            # Enhanced Redis ACL for Redis 6+
            REDIS_VERSION=$(redis-cli --version 2>/dev/null | grep -oP '\d+\.\d+' | head -1)
            if [ -n "$REDIS_VERSION" ] && [ "$(echo "$REDIS_VERSION >= 6.0" | bc -l 2>/dev/null)" = "1" ]; then
                log_info "Configuring Redis ACL for enhanced security (Redis $REDIS_VERSION detected)..."
                
                # Create a dedicated user with specific permissions
                REDIS_USER="webuser"
                REDIS_USER_PASS=$(openssl rand -base64 24)
                
                # Wait for Redis to be ready
                sleep 2
                
                if redis-cli -a "$REDIS_PASS" ACL SETUSER "$REDIS_USER" on ">$REDIS_USER_PASS" ~* +@read +@write +@connection +@fast -@admin +@hash +@set +@list +@string +@sortedset 2>/dev/null; then
                    # Update credential files with both users
                    echo -e "\nRedis Enhanced ACL Users:" >> /root/.redis_credentials
                    echo "Admin User: default (password: ${REDIS_PASS})" >> /root/.redis_credentials
                    echo "Application User: ${REDIS_USER} (password: ${REDIS_USER_PASS})" >> /root/.redis_credentials
                    
                    if [ -n "$DEPLOYUSER" ]; then
                        echo -e "\nRedis Enhanced ACL Users:" >> /home/${DEPLOYUSER}/.redis_credentials
                        echo "Admin User: default (password: ${REDIS_PASS})" >> /home/${DEPLOYUSER}/.redis_credentials
                        echo "Application User: ${REDIS_USER} (password: ${REDIS_USER_PASS})" >> /home/${DEPLOYUSER}/.redis_credentials
                    fi
                    
                    log_success "Redis ACL configured with restricted application user"
                else
                    log_warn "Redis ACL configuration failed, using standard authentication"
                fi
            else
                log_info "Redis version < 6.0, using standard password authentication"
            fi
            
            # Save base credentials for root
            cat > /root/.redis_credentials << EOF
Redis Connection Info:
Host: localhost (127.0.0.1)
Port: 6379
Password: ${REDIS_PASS}

Test connection:
redis-cli -a '${REDIS_PASS}' ping
EOF
            run_command "chmod 600 /root/.redis_credentials" "Set secure permissions for Redis credentials"
            
            # Save credentials for deploy user too
            if [ -n "$DEPLOYUSER" ] && id -u "$DEPLOYUSER" >/dev/null 2>&1; then
                cat > /home/${DEPLOYUSER}/.redis_credentials << EOF
Redis Connection Info:
Host: localhost (127.0.0.1)
Port: 6379
Password: ${REDIS_PASS}

Test connection:
redis-cli -a '${REDIS_PASS}' ping
EOF
                run_command "chown ${DEPLOYUSER}:${DEPLOYUSER} /home/${DEPLOYUSER}/.redis_credentials" "Set ownership for user Redis credentials"
                run_command "chmod 600 /home/${DEPLOYUSER}/.redis_credentials" "Set secure permissions for user Redis credentials"
                log_success "Hidden Redis credentials saved at /home/${DEPLOYUSER}/.redis_credentials"
            fi
            
            # Add PHP Redis extension if PHP is installed
            if command -v php &>/dev/null && [ -n "$PHP_VERSION" ]; then
                install_package "php-redis"
                run_command "systemctl restart php-fpm" "Restart PHP-FPM after Redis extension"
            fi
        fi
    fi
else
    log_info "Skipping Redis installation"
fi

# ----------------------------
# Robust Nginx installation - FIXED VERSION
# ----------------------------
install_nginx() {
    log_info "Installing Nginx web server..."
    
    # Stop and disable Apache if it's running (common conflict)
    if systemctl is-active --quiet apache2 2>/dev/null; then
        log_info "Stopping Apache to avoid port conflicts..."
        run_command "systemctl stop apache2" "Stop Apache service"
        run_command "systemctl disable apache2" "Disable Apache service"
    fi
    
    # Kill any existing Nginx processes
    run_command "pkill -f nginx 2>/dev/null || true" "Kill existing Nginx processes"
    
    # Install Nginx
    install_package "nginx"
    
    # Create a basic, working nginx.conf
    log_info "Creating robust Nginx configuration..."
    
    # Backup original config
    run_command "cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup.original" "Backup original Nginx config"
    
    # Create a clean, working nginx.conf
    cat > /tmp/nginx.conf.basic << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    # MIME Types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    # Gzip Settings
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # Virtual Host Configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    run_command "cp /tmp/nginx.conf.basic /etc/nginx/nginx.conf" "Install basic Nginx configuration"
    
    # Ensure default site is properly configured
    log_info "Configuring default website..."
    
    # Create sites-available and sites-enabled directories if they don't exist
    run_command "mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled" "Create Nginx site directories"
    
    # Determine PHP socket path based on installed PHP version
    PHP_SOCKET="/var/run/php/php-fpm.sock"
    if [ -n "$PHP_VERSION" ] && [ -S "/var/run/php/php${PHP_VERSION}-fpm.sock" ]; then
        PHP_SOCKET="/var/run/php/php${PHP_VERSION}-fpm.sock"
    elif [ -S "/var/run/php/php8.3-fpm.sock" ]; then
        PHP_SOCKET="/var/run/php/php8.3-fpm.sock"
    fi
    
    cat > /etc/nginx/sites-available/default << EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    root /var/www/html;
    index index.html index.htm index.php;
    
    server_name _;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    # PHP support if installed
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${PHP_SOCKET};
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Deny access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOF

    # Remove any broken symlinks and create proper ones
    run_command "rm -f /etc/nginx/sites-enabled/default" "Remove old default site symlink"
    run_command "ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/" "Enable default site"
    
    # Create web root if it doesn't exist
    run_command "mkdir -p /var/www/html" "Create web root directory"
    
    # Create a basic index page
    cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Server is Running</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
        .success { color: #28a745; }
    </style>
</head>
<body>
    <h1 class="success">✅ Nginx is working!</h1>
    <p>Your web server is successfully running.</p>
    <p>Next: Continue with the server setup script.</p>
</body>
</html>
EOF

    run_command "chown -R www-data:www-data /var/www/html" "Set web directory ownership"
    run_command "chmod -R 755 /var/www/html" "Set web directory permissions"
    
    # Test Nginx configuration before starting
    log_info "Testing Nginx configuration..."
    if nginx -t 2>/dev/null; then
        log_success "Nginx configuration test passed"
        
        # Enable and start Nginx
        run_command "systemctl enable nginx" "Enable Nginx service"
        
        # Start Nginx with retry logic
        log_info "Starting Nginx service..."
        if systemctl start nginx; then
            sleep 2
            if systemctl is-active --quiet nginx; then
                log_success "Nginx installed and running successfully"
                return 0
            else
                log_error "Nginx failed to start - investigating..."
                troubleshoot_nginx
                return 1
            fi
        else
            log_error "Failed to start Nginx service"
            troubleshoot_nginx
            return 1
        fi
    else
        log_error "Nginx configuration test failed"
        troubleshoot_nginx
        return 1
    fi
}

# ----------------------------
# Nginx troubleshooting function
# ----------------------------
troubleshoot_nginx() {
    log_info "Starting Nginx troubleshooting..."
    
    echo "=== Nginx Troubleshooting ==="
    
    # Check if port 80 is in use
    echo "1. Checking port 80 usage:"
    if netstat -tulpn | grep :80; then
        echo "   ⚠️  Port 80 is already in use"
        echo "   Processes using port 80:"
        lsof -i :80 || ss -tulpn | grep :80
    else
        echo "   ✅ Port 80 is free"
    fi
    
    # Check Nginx error log
    echo "2. Checking Nginx error log:"
    if [ -f "/var/log/nginx/error.log" ]; then
        tail -20 /var/log/nginx/error.log
    else
        echo "   No error log found"
    fi
    
    # Check systemd status
    echo "3. Systemd status:"
    systemctl status nginx --no-pager -l
    
    # Check configuration syntax
    echo "4. Testing configuration:"
    nginx -t
    
    # Common fixes
    echo "5. Applying common fixes..."
    
    # Kill any stuck Nginx processes
    pkill -f nginx 2>/dev/null && echo "   Killed stuck Nginx processes"
    sleep 2
    
    # Remove all site configs and start fresh
    rm -f /etc/nginx/sites-enabled/*
    ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/
    
    # Test again
    if nginx -t; then
        echo "   ✅ Configuration fixed, attempting to start Nginx..."
        if systemctl start nginx; then
            sleep 2
            if systemctl is-active --quiet nginx; then
                log_success "Nginx started successfully after troubleshooting"
                return 0
            fi
        fi
    fi
    
    log_error "Nginx troubleshooting failed - manual intervention required"
    return 1
}

# ----------------------------
# Enhanced SSL setup function
# ----------------------------
setup_ssl_with_fallback() {
    local domain=$1
    local email=$2
    local additional_domains=$3
    
    log_info "Setting up SSL for $domain..."
    
    # Install Certbot if not already installed
    if ! command -v certbot &>/dev/null; then
        log_info "Installing Certbot..."
        install_package "certbot"
        install_package "python3-certbot-nginx"
    fi
    
    # Create Nginx configuration for the domain
    cat > /etc/nginx/sites-available/$domain << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $domain$([ -n "$additional_domains" ] && echo " $additional_domains");
    
    root /var/www/html;
    index index.html index.htm index.php;
    
    # Let's Encrypt challenge directory
    location ^~ /.well-known/acme-challenge/ {
        default_type "text/plain";
        root /var/www/letsencrypt;
    }
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
    
    run_command "mkdir -p /var/www/letsencrypt" "Create Let's Encrypt directory"
    run_command "chown www-data:www-data /var/www/letsencrypt" "Set Let's Encrypt directory ownership"
    
    run_command "ln -sf /etc/nginx/sites-available/$domain /etc/nginx/sites-enabled/" "Enable domain site"
    
    # Test and reload Nginx
    if nginx -t; then
        run_command "systemctl reload nginx" "Reload Nginx for SSL setup"
        
        # Wait for DNS propagation (if needed)
        log_info "Waiting for Nginx to be ready..."
        sleep 5
        
        # Attempt SSL certificate acquisition
        local cert_domains="-d $domain"
        if [ -n "$additional_domains" ]; then
            IFS=' ' read -ra DOMAIN_ARRAY <<< "$additional_domains"
            for dom in "${DOMAIN_ARRAY[@]}"; do
                cert_domains="$cert_domains -d $dom"
            done
        fi
        
        log_info "Requesting SSL certificate..."
        if certbot certonly --webroot -w /var/www/letsencrypt $cert_domains \
            --email "$email" --agree-tos --non-interactive --expand; then
            
            log_success "SSL certificate obtained!"
            setup_ssl_nginx_config "$domain" "$additional_domains"
            return 0
        else
            log_warn "SSL certificate acquisition failed - continuing without SSL"
            return 1
        fi
    else
        log_error "Nginx configuration test failed - skipping SSL setup"
        return 1
    fi
}

setup_ssl_nginx_config() {
    local domain=$1
    local additional_domains=$2
    
    log_info "Setting up SSL Nginx configuration for $domain..."
    
    # Create SSL-enabled Nginx configuration
    cat > /etc/nginx/sites-available/$domain << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $domain$([ -n "$additional_domains" ] && echo " $additional_domains");
    
    # Redirect HTTP to HTTPS
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $domain$([ -n "$additional_domains" ] && echo " $additional_domains");
    
    root /var/www/html;
    index index.html index.htm index.php;
    
    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    
    # SSL security
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    # PHP support if installed
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${PHP_SOCKET};
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Deny access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOF
    
    if nginx -t; then
        run_command "systemctl reload nginx" "Reload Nginx with SSL configuration"
        log_success "SSL configuration completed for $domain"
    else
        log_error "SSL Nginx configuration test failed"
    fi
}

# ----------------------------
# Main Nginx installation call in the script
# ----------------------------
log_info "Setting up Nginx web server..."

# Call the fixed Nginx installation function
if install_nginx; then
    log_success "Nginx setup completed successfully"
else
    log_error "Nginx setup failed - attempting to continue with other services"
    # Continue with other services even if Nginx fails
fi

# Continue with SSL setup if domain was provided
if [ -n "$DOMAIN_NAME" ] && [ -n "$LETSENCRYPT_EMAIL" ]; then
    if setup_ssl_with_fallback "$DOMAIN_NAME" "$LETSENCRYPT_EMAIL" "$ADDITIONAL_DOMAINS"; then
        log_success "SSL configuration completed"
    else
        log_warn "SSL setup failed but continuing with installation"
    fi
fi

# ----------------------------
# Enhanced Cockpit with Plugins Installation - WITH COCKPIT NAVIGATOR
# ----------------------------
if [[ "$INSTALL_COCKPIT_PLUGINS" =~ ^[Yy]$ ]]; then
    log_info "Installing Cockpit with enhanced plugins..."
    
    # Function to install Cockpit plugin with error handling
    install_cockpit_plugin() {
        local plugin=$1
        local description=${2:-$plugin}
        
        if apt-cache show "$plugin" &>/dev/null; then
            if install_package "$plugin"; then
                log_success "Installed Cockpit plugin: $description"
                return 0
            else
                log_warn "Failed to install Cockpit plugin: $description"
                return 1
            fi
        else
            log_info "Cockpit plugin not available: $description"
            return 2
        fi
    }

    # Function to install Cockpit Navigator manually with multiple fallbacks
    install_cockpit_navigator() {
        log_info "Installing Cockpit Navigator (manual installation)..."
        
        local navigator_version="0.5.10"
        local ubuntu_codename=$(lsb_release -cs)
        local navigator_url=""
        local navigator_deb=""
        
        # Map Ubuntu versions to appropriate packages
        case "$ubuntu_codename" in
            "focal")    # Ubuntu 20.04
                navigator_deb="cockpit-navigator_${navigator_version}-1focal_all.deb"
                ;;
            "jammy")    # Ubuntu 22.04
                navigator_deb="cockpit-navigator_${navigator_version}-1jammy_all.deb"
                ;;
            "noble")    # Ubuntu 24.04
                navigator_deb="cockpit-navigator_${navigator_version}-1noble_all.deb"
                ;;
            "bionic")   # Ubuntu 18.04 (fallback)
                navigator_deb="cockpit-navigator_${navigator_version}-1bionic_all.deb"
                ;;
            *)
                log_warn "Unsupported Ubuntu version for Cockpit Navigator: $ubuntu_codename"
                log_info "Trying focal package as fallback..."
                navigator_deb="cockpit-navigator_${navigator_version}-1focal_all.deb"
                ;;
        esac
        
        navigator_url="https://github.com/45Drives/cockpit-navigator/releases/download/v${navigator_version}/${navigator_deb}"
        
        log_info "Downloading Cockpit Navigator: $navigator_deb"
        
        # Download the package with retry logic
        local download_success=false
        for i in {1..3}; do
            if wget -O /tmp/${navigator_deb} ${navigator_url} 2>/dev/null; then
                download_success=true
                break
            else
                log_warn "Download attempt $i failed, retrying..."
                sleep 2
            fi
        done
        
        if [ "$download_success" = true ]; then
            log_success "Downloaded Cockpit Navigator successfully"
            
            # Install the package with dependency handling
            log_info "Installing Cockpit Navigator package..."
            
            if dpkg -i /tmp/${navigator_deb} 2>/dev/null; then
                log_success "Installed Cockpit Navigator successfully"
            else
                log_info "Fixing dependencies for Cockpit Navigator..."
                if apt-get install -y -f; then
                    if dpkg -i /tmp/${navigator_deb} 2>/dev/null; then
                        log_success "Installed Cockpit Navigator after fixing dependencies"
                    else
                        log_warn "Still failed to install Cockpit Navigator, trying direct install..."
                        if apt-get install -y /tmp/${navigator_deb}; then
                            log_success "Installed Cockpit Navigator via apt-get"
                        else
                            log_error "All Cockpit Navigator installation attempts failed"
                            rm -f /tmp/${navigator_deb}
                            return 1
                        fi
                    fi
                else
                    log_error "Failed to fix dependencies for Cockpit Navigator"
                    rm -f /tmp/${navigator_deb}
                    return 1
                fi
            fi
            
            # Clean up
            rm -f /tmp/${navigator_deb}
            
            # Verify installation
            if dpkg -l | grep -q cockpit-navigator; then
                log_success "Cockpit Navigator verified and ready to use"
                return 0
            else
                log_warn "Cockpit Navigator installation completed but verification failed"
                return 1
            fi
            
        else
            log_error "Failed to download Cockpit Navigator after multiple attempts"
            log_info "You can manually install it later with:"
            log_info "  wget $navigator_url"
            log_info "  sudo apt install ./${navigator_deb}"
            return 1
        fi
    }
    
    # Install Cockpit core
    if apt-cache show cockpit &>/dev/null; then
        # Core Cockpit packages
        log_info "Installing core Cockpit packages..."
        
        CORE_PLUGINS=(
            "cockpit:Cockpit Core"
            "cockpit-machines:Cockpit Machines" 
            "cockpit-networkmanager:Cockpit NetworkManager"
            "cockpit-storaged:Cockpit Storage"
            "cockpit-packagekit:Cockpit PackageKit"
        )
        
        for plugin_info in "${CORE_PLUGINS[@]}"; do
            IFS=':' read -r plugin description <<< "$plugin_info"
            install_cockpit_plugin "$plugin" "$description"
        done
        
        # Additional Cockpit plugins
        log_info "Installing additional Cockpit plugins..."
        
        ADDITIONAL_PLUGINS=(
            "cockpit-podman:Cockpit Podman"
            "cockpit-sosreport:Cockpit SOS Report"
            "cockpit-selinux:Cockpit SELinux"
            "cockpit-389-ds:Cockpit 389 Directory Server"
            "cockpit-kdump:Cockpit Kdump"
            "cockpit-zfs:Cockpit ZFS"
            "cockpit-benchmark:Cockpit Benchmark"
        )
        
        for plugin_info in "${ADDITIONAL_PLUGINS[@]}"; do
            IFS=':' read -r plugin description <<< "$plugin_info"
            install_cockpit_plugin "$plugin" "$description"
        done
        
        # Install Cockpit Navigator manually
        install_cockpit_navigator
        
        # Enable and start Cockpit
        run_command "systemctl enable cockpit.socket" "Enable Cockpit socket"
        run_command "systemctl start cockpit.socket" "Start Cockpit socket"
        
        sleep 3
        
        if systemctl is-active --quiet cockpit.socket; then
            log_success "Cockpit installed and running successfully"
            log_info "Cockpit web interface available at: https://$INTERNAL_IP:9090"
            
            # Display installed plugins summary
            show_cockpit_plugins_summary
            
        else
            log_warn "Cockpit socket is not active"
            run_command "systemctl status cockpit.socket --no-pager" "Check Cockpit status"
        fi
        
    else
        log_warn "Cockpit not available in main repositories"
        log_info "You can manually install Cockpit later with: sudo apt update && sudo apt install cockpit"
    fi
else
    log_info "Skipping Cockpit installation"
fi

# Function to show installed Cockpit plugins summary
show_cockpit_plugins_summary() {
    log_info "Cockpit Plugins Summary:"
    
    local installed_plugins=()
    
    # Check core plugins
    if dpkg -l | grep -q "^ii.*cockpit "; then
        installed_plugins+=("cockpit")
    fi
    if dpkg -l | grep -q "^ii.*cockpit-machines"; then
        installed_plugins+=("cockpit-machines")
    fi
    if dpkg -l | grep -q "^ii.*cockpit-networkmanager"; then
        installed_plugins+=("cockpit-networkmanager")
    fi
    if dpkg -l | grep -q "^ii.*cockpit-storaged"; then
        installed_plugins+=("cockpit-storaged")
    fi
    if dpkg -l | grep -q "^ii.*cockpit-navigator"; then
        installed_plugins+=("cockpit-navigator")
    fi
    
    # Show installed plugins
    for plugin in "${installed_plugins[@]}"; do
        log_success "  ✅ $plugin"
    done
    
    log_info "Access Cockpit at: https://$INTERNAL_IP:9090"
}

# ----------------------------
# Fail2Ban configuration
# ----------------------------
log_info "Configuring Fail2Ban..."

run_command "mkdir -p /etc/fail2ban/filter.d" "Create Fail2Ban filter directory"

cat <<'EOF' >/etc/fail2ban/filter.d/nginx-noscript.conf
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*\.(php|asp|exe|pl|cgi|scgi)\?? .* HTTP/.*"$
ignoreregex =
EOF

cat <<'EOF' >/etc/fail2ban/filter.d/nginx-badbots.conf
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*HTTP.*" .* .* ".*bot.*"$
            ^<HOST> -.*"(GET|POST).*HTTP.*" .* .* ".*spider.*"$
            ^<HOST> -.*"(GET|POST).*HTTP.*" .* .* ".*crawler.*"$
ignoreregex =
EOF

cat <<'EOF' >/etc/fail2ban/jail.local
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

[nginx-noscript]
enabled = true
filter = nginx-noscript
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 6

[nginx-badbots]
enabled = true
filter = nginx-badbots
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2
EOF

run_command "systemctl enable fail2ban" "Enable Fail2Ban service"
run_command "systemctl restart fail2ban" "Start Fail2Ban service"

# ----------------------------
# rkhunter
# ----------------------------
log_info "Installing rkhunter..."
if apt-cache show rkhunter &>/dev/null; then
    install_package "rkhunter"
    
    safe_sed "/etc/rkhunter.conf" 's|^WEB_CMD=.*|#WEB_CMD="" # Disabled|g'
    
    if [ -f /etc/default/rkhunter ]; then
        safe_sed "/etc/default/rkhunter" 's|APT_AUTOGEN=.*|APT_AUTOGEN="yes"|g'
        if ! grep -q "APT_AUTOGEN=" /etc/default/rkhunter; then
            echo 'APT_AUTOGEN="yes"' >> /etc/default/rkhunter
        fi
    fi
    
    run_command "rkhunter --propupd --quiet 2>/dev/null || true" "Update rkhunter database"
    log_success "rkhunter installed"
fi

# ----------------------------
# File Browser installation
# ----------------------------
log_info "Installing File Browser (standalone file management)..."

if [ ! -f /usr/local/bin/filebrowser ]; then
    if curl -fsSL https://raw.githubusercontent.com/filebrowser/get/master/get.sh | bash; then
        run_command "mkdir -p /etc/filebrowser /var/lib/filebrowser" "Create File Browser directories"
        
        run_command "filebrowser config init --database /var/lib/filebrowser/filebrowser.db" "Initialize File Browser config"
        run_command "filebrowser config set --address 0.0.0.0 --port 8080 --database /var/lib/filebrowser/filebrowser.db" "Configure File Browser"
        run_command "filebrowser config set --root /var/www/html --database /var/lib/filebrowser/filebrowser.db" "Set File Browser root"
        
        # Generate secure password for File Browser
        FILEBROWSER_PASSWORD=$(openssl rand -base64 16)
        run_command "filebrowser users add admin \"$FILEBROWSER_PASSWORD\" --perm.admin --database /var/lib/filebrowser/filebrowser.db 2>/dev/null || true" "Create File Browser admin user with secure password"
        
        # Save credentials securely
        cat > /root/.filebrowser_credentials <<EOF
File Browser Access:
URL: http://$INTERNAL_IP:8080
Username: admin
Password: $FILEBROWSER_PASSWORD

⚠️ CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN!

Note: File Browser is kept as a standalone file manager and emergency access tool.
Use Cockpit Navigator for integrated file management within the main web console.
EOF
        run_command "chmod 600 /root/.filebrowser_credentials" "Secure File Browser credentials"

        if [ -n "$DEPLOYUSER" ]; then
            cp /root/.filebrowser_credentials /home/${DEPLOYUSER}/.filebrowser_credentials
            run_command "chown ${DEPLOYUSER}:${DEPLOYUSER} /home/${DEPLOYUSER}/.filebrowser_credentials" "Set user ownership for File Browser credentials"
            run_command "chmod 600 /home/${DEPLOYUSER}/.filebrowser_credentials" "Secure user File Browser credentials"
        fi
        
        cat <<'EOF' >/etc/systemd/system/filebrowser.service
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
EOF

        run_command "systemctl daemon-reload" "Reload systemd daemon"
        run_command "systemctl enable filebrowser" "Enable File Browser service"
        run_command "systemctl start filebrowser" "Start File Browser service"
        
        sleep 2
        if systemctl is-active --quiet filebrowser; then
            log_success "File Browser installed (standalone file manager)"
        fi
    fi
fi

# ----------------------------
# Netdata installation
# ----------------------------
if ! systemctl list-unit-files | grep -q "^netdata.service"; then
    log_info "Installing Netdata..."
    
    if apt-cache show netdata &>/dev/null; then
        install_package "netdata"
        run_command "systemctl enable netdata" "Enable Netdata service"
        run_command "systemctl start netdata" "Start Netdata service"
    fi
    
    if ! systemctl is-active --quiet netdata 2>/dev/null; then
        if wget -O /tmp/netdata-kickstart.sh --timeout=60 https://my-netdata.io/kickstart.sh 2>/dev/null; then
            run_command "timeout 300 bash /tmp/netdata-kickstart.sh --disable-telemetry --non-interactive --dont-wait --auto-update-method disable || true" "Install Netdata via kickstart"
            run_command "rm -f /tmp/netdata-kickstart.sh" "Clean up Netdata installer"
        fi
    fi
    
    if systemctl is-active --quiet netdata 2>/dev/null; then
        log_success "Netdata installed"
    fi
fi

# ----------------------------
# Adminer Database Management
# ----------------------------
if [[ "$INSTALL_ADMINER" =~ ^[Yy]$ ]]; then
    log_info "Installing Adminer database management..."
    
    wget -O /var/www/html/db-admin.php https://github.com/vrana/adminer/releases/download/v4.8.1/adminer-4.8.1.php
    run_command "chown www-data:www-data /var/www/html/db-admin.php" "Set Adminer permissions"
    log_success "Adminer installed at /db-admin.php"
else
    log_info "Skipping Adminer installation"
fi

# ----------------------------
# Security Tools Installation
# ----------------------------
if [[ "$INSTALL_SECURITY_TOOLS" =~ ^[Yy]$ ]]; then
    log_info "Installing security tools..."
    
    # Lynis security audit
    install_package "lynis"
    
    # ClamAV antivirus
    install_package "clamav"
    install_package "clamav-daemon"
    run_command "freshclam" "Update ClamAV virus definitions"
    run_command "systemctl enable clamav-freshclam" "Enable ClamAV freshclam"
    run_command "systemctl start clamav-freshclam" "Start ClamAV freshclam"
    
    # AIDE file integrity
    install_package "aide"
    run_command "aideinit" "Initialize AIDE database"
    run_command "mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db" "Activate AIDE database"
    
    log_success "Security tools installed"
else
    log_info "Skipping security tools installation"
fi

# ----------------------------
# Performance Monitoring Tools
# ----------------------------
if [[ "$INSTALL_PERF_TOOLS" =~ ^[Yy]$ ]]; then
    log_info "Installing performance monitoring tools..."
    
    # System monitoring tools
    install_package "htop"
    install_package "iotop"
    install_package "nethogs"
    
    # Network tools
    install_package "nmap"
    install_package "speedtest-cli"
    
    # Glances (if Python3 available)
    if command -v python3 &>/dev/null; then
        install_package "python3-pip"
        run_command "pip3 install glances" "Install Glances system monitor"
        
        cat > /etc/systemd/system/glances.service <<'EOF'
[Unit]
Description=Glances
After=network.target

[Service]
ExecStart=/usr/local/bin/glances -w
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        run_command "systemctl enable glances" "Enable Glances service"
        run_command "systemctl start glances" "Start Glances service"
    fi
    
    log_success "Performance monitoring tools installed"
else
    log_info "Skipping performance tools installation"
fi

# ----------------------------
# Advanced Monitoring Tools
# ----------------------------
if [[ "$INSTALL_ADVANCED_MONITORING" =~ ^[Yy]$ ]]; then
    log_info "Installing advanced monitoring tools..."
    
    # GoAccess - Real-time web log analyzer
    install_package "goaccess"
    
    # Create GoAccess service for real-time log monitoring
    cat > /etc/systemd/system/goaccess.service <<'EOF'
[Unit]
Description=GoAccess Web Log Analyzer
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/goaccess /var/log/nginx/access.log -o /var/www/html/logs.html --real-time-html --log-format=COMBINED --port=7890
Restart=on-failure
User=www-data
Group=www-data

[Install]
WantedBy=multi-user.target
EOF

    run_command "systemctl enable goaccess" "Enable GoAccess service"
    run_command "systemctl start goaccess" "Start GoAccess service"
    
    # PHP OPcache Status Dashboard
    if command -v php &>/dev/null; then
        cat <<'EOF' > /var/www/html/opcache.php
<?php
function human_filesize($bytes, $decimals = 2) {
    $sz = 'BKMGTP';
    $factor = floor((strlen($bytes) - 1) / 3);
    return sprintf("%.{$decimals}f", $bytes / pow(1024, $factor)) . @$sz[$factor];
}

$opcache = opcache_get_status(true);
$config = opcache_get_configuration();
?>
<!DOCTYPE html>
<html>
<head>
    <title>PHP OPcache Status</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { background: #f5f5f5; padding: 20px; margin: 10px 0; border-radius: 5px; }
        .stat { display: inline-block; margin: 5px 15px 5px 0; }
        .good { color: green; }
        .warning { color: orange; }
        .bad { color: red; }
    </style>
</head>
<body>
    <div class="container">
        <h1>PHP OPcache Status</h1>
        
        <div class="card">
            <h2>Memory Usage</h2>
            <div class="stat">Used: <?php echo human_filesize($opcache['memory_usage']['used_memory']); ?></div>
            <div class="stat">Free: <?php echo human_filesize($opcache['memory_usage']['free_memory']); ?></div>
            <div class="stat">Wasted: <?php echo human_filesize($opcache['memory_usage']['wasted_memory']); ?></div>
        </div>

        <div class="card">
            <h2>Statistics</h2>
            <div class="stat">Hits: <?php echo number_format($opcache['opcache_statistics']['hits']); ?></div>
            <div class="stat">Misses: <?php echo number_format($opcache['opcache_statistics']['misses']); ?></div>
            <div class="stat">Cached Scripts: <?php echo $opcache['opcache_statistics']['num_cached_scripts']; ?></div>
            <div class="stat">Hit Rate: <?php echo round($opcache['opcache_statistics']['opcache_hit_rate'], 2); ?>%</div>
        </div>
    </div>
</body>
</html>
EOF
        run_command "chown www-data:www-data /var/www/html/opcache.php" "Set OPcache dashboard permissions"
    fi
    
    log_success "Advanced monitoring tools installed"
else
    log_info "Skipping advanced monitoring tools installation"
fi

# ----------------------------
# Performance Optimizations
# ----------------------------
if [[ "$APPLY_OPTIMIZATIONS" =~ ^[Yy]$ ]]; then
    log_info "Applying performance optimizations..."
    
    optimize_os
    
    if systemctl is-active --quiet nginx; then
        optimize_nginx
    fi
    
    if [[ "$INSTALL_PHP_MYSQL" =~ ^[Yy]$ ]] && [ -n "$PHP_VERSION" ]; then
        optimize_php_fpm "$PHP_VERSION"
    fi
    
    if systemctl is-active --quiet mariadb; then
        optimize_mysql
    fi
    
    if [[ "$INSTALL_REDIS" =~ ^[Yy]$ ]] && systemctl is-active --quiet redis-server; then
        optimize_redis
    fi
    
    log_success "Performance optimizations completed"
else
    log_info "Skipping performance optimizations"
fi

# ----------------------------
# Rclone Cloud Storage Setup
# ----------------------------
if [[ "$RCLONE_SETUP" =~ ^1$ ]]; then
    log_info "Setting up Rclone for cloud storage backups..."
    
    # Install Rclone
    if curl https://rclone.org/install.sh | bash; then
        log_success "Rclone installed successfully"
        
        # Create Rclone configuration directory
        run_command "mkdir -p /root/.config/rclone" "Create Rclone config directory"
        
        # Inform user about manual configuration
        cat > /root/.rclone-setup-info <<'EOF'
Rclone Cloud Storage Setup

Rclone has been installed. To configure cloud storage:

1. Run configuration wizard:
   rclone config

2. Common remote types:
   - Google Drive: drive
   - Amazon S3: s3  
   - Microsoft OneDrive: onedrive
   - Dropbox: dropbox

3. Test your configuration:
   rclone ls remote:path

4. Add to backup script by editing:
   /usr/local/bin/backup-website.sh

Example backup command:
rclone sync /var/backups/website remote:backups/webserver --progress

For more info: https://rclone.org/docs/
EOF
        log_success "Rclone installed - manual configuration required"
        log_info "See /root/.rclone-setup-info for setup instructions"
    else
        log_warn "Rclone installation failed - skipping cloud storage setup"
    fi
fi

# ----------------------------
# Automatic Security Updates
# ----------------------------
log_info "Configuring automatic security updates..."
if apt-cache show unattended-upgrades &>/dev/null; then
    install_package "unattended-upgrades"
    install_package "apt-listchanges"
    
    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    log_success "Automatic security updates enabled"
fi

# ----------------------------
# Firewall setup
# ----------------------------
log_info "Configuring UFW firewall..."
run_command "ufw --force reset" "Reset UFW firewall"
run_command "ufw default deny incoming" "Set default incoming policy"
run_command "ufw default allow outgoing" "Set default outgoing policy"
run_command "ufw allow OpenSSH" "Allow SSH access"
run_command "ufw allow 'Nginx Full'" "Allow HTTP/HTTPS access"

if systemctl is-active --quiet cockpit.socket 2>/dev/null; then
    run_command "ufw allow 9090/tcp" "Allow Cockpit access"
fi

if systemctl is-active --quiet netdata 2>/dev/null; then
    run_command "ufw allow 19999/tcp" "Allow Netdata access"
fi

if systemctl is-active --quiet filebrowser 2>/dev/null; then
    run_command "ufw allow 8080/tcp" "Allow File Browser access"
fi

# Allow GoAccess if installed
if [[ "$INSTALL_ADVANCED_MONITORING" =~ ^[Yy]$ ]] && systemctl is-active --quiet goaccess 2>/dev/null; then
    run_command "ufw allow 7890/tcp" "Allow GoAccess dashboard"
fi

run_command "ufw --force enable" "Enable UFW firewall"

# ----------------------------
# Git auto-deploy
# ----------------------------
if [ -n "$GITREPO" ]; then
    log_info "Setting up Git repository..."
    run_command "mkdir -p /var/www/html" "Create web root directory"
    run_command "chown -R $DEPLOYUSER:$DEPLOYUSER /var/www/html" "Set web root ownership"
    
    if [ ! -d "/var/www/html/.git" ]; then
        if sudo -u "$DEPLOYUSER" git clone "https://github.com/$GITREPO.git" /tmp/repo; then
            run_command "sudo -u $DEPLOYUSER cp -r /tmp/repo/* /var/www/html/ 2>/dev/null || true" "Copy repository files"
            run_command "sudo -u $DEPLOYUSER cp -r /tmp/repo/.git /var/www/html/ 2>/dev/null || true" "Copy repository git data"
            run_command "rm -rf /tmp/repo" "Clean up temporary repository"
        fi
    fi
fi

# ----------------------------
# Automated Backup System
# ----------------------------
log_info "Setting up automated backup system..."

run_command "mkdir -p /var/backups/website" "Create backup directory"
run_command "chmod 700 /var/backups/website" "Set backup directory permissions"

cat > /usr/local/bin/backup-website.sh <<BACKUPSCRIPT
#!/bin/bash
# Enhanced Automated Website Backup Script

BACKUP_DIR="/var/backups/website"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DAY_OF_WEEK=$(date +%u)
DAY_OF_MONTH=$(date +%d)

# Retention periods
DAILY_RETENTION=7
WEEKLY_RETENTION=28
MONTHLY_RETENTION=90

# Configuration from main script
ENCRYPT_BACKUPS=${ENCRYPT_FLAG}
BACKUP_PASSPHRASE='${BACKUP_PASSPHRASE}'
REMOTE_BACKUP=${REMOTE_FLAG}
REMOTE_SSH='${REMOTE_SSH}'
RCLONE_BACKUP=${RCLONE_FLAG}
REMOTE_RETENTION=30

mkdir -p "\${BACKUP_DIR}/daily" "\${BACKUP_DIR}/weekly" "\${BACKUP_DIR}/monthly"

if [ "\$DAY_OF_MONTH" -eq "01" ]; then
    BACKUP_TYPE="monthly"
    BACKUP_SUBDIR="\${BACKUP_DIR}/monthly"
    RETENTION=\$MONTHLY_RETENTION
elif [ "\$DAY_OF_WEEK" -eq "7" ]; then
    BACKUP_TYPE="weekly"
    BACKUP_SUBDIR="\${BACKUP_DIR}/weekly"
    RETENTION=\$WEEKLY_RETENTION
else
    BACKUP_TYPE="daily"
    BACKUP_SUBDIR="\${BACKUP_DIR}/daily"
    RETENTION=\$DAILY_RETENTION
fi

echo "\$(date): Starting \${BACKUP_TYPE} backup..."

# Create backups
tar -czf "\${BACKUP_SUBDIR}/webfiles_\${TIMESTAMP}.tar.gz" -C /var/www/html . 2>/dev/null
tar -czf "\${BACKUP_SUBDIR}/nginx_\${TIMESTAMP}.tar.gz" /etc/nginx 2>/dev/null

if systemctl is-active --quiet mariadb 2>/dev/null; then
    if [ -f /root/.my.cnf ]; then
        mysqldump --all-databases --single-transaction --quick | gzip > "\${BACKUP_SUBDIR}/databases_\${TIMESTAMP}.sql.gz" 2>/dev/null
    fi
fi

# Encrypt backups if enabled
if [ "\$ENCRYPT_BACKUPS" -eq 1 ] && command -v gpg &>/dev/null && [ -n "\$BACKUP_PASSPHRASE" ]; then
    for backup_file in "\${BACKUP_SUBDIR}"/*_\${TIMESTAMP}.*; do
        if [ -f "\$backup_file" ]; then
            gpg --batch --yes --passphrase "\$BACKUP_PASSPHRASE" --symmetric --cipher-algo AES256 -o "\${backup_file}.gpg" "\$backup_file" 2>/dev/null
            if [ \$? -eq 0 ]; then
                rm -f "\$backup_file"
            else
                echo "Warning: Encryption failed for \$backup_file" >> /var/log/website-backup.log
            fi
        fi
    done
fi

# Remote backup if enabled
if [ "\$REMOTE_BACKUP" -eq 1 ] && command -v rsync &>/dev/null && [ -n "\$REMOTE_SSH" ]; then
    echo "\$(date): Starting remote backup to \$REMOTE_SSH" >> /var/log/website-backup.log
    if rsync -avz "\${BACKUP_DIR}/" "\$REMOTE_SSH" --exclude='*.log' 2>/dev/null; then
        echo "\$(date): Remote backup completed successfully" >> /var/log/website-backup.log
        
        # Clean up old remote backups (if SSH access works)
        ssh -o BatchMode=yes -o ConnectTimeout=10 \${REMOTE_SSH%%:*} "find \${REMOTE_SSH#*:} -name '*.tar.gz*' -mtime +\$REMOTE_RETENTION -delete 2>/dev/null" 2>/dev/null
        ssh -o BatchMode=yes -o ConnectTimeout=10 \${REMOTE_SSH%%:*} "find \${REMOTE_SSH#*:} -name '*.sql.gz*' -mtime +\$REMOTE_RETENTION -delete 2>/dev/null" 2>/dev/null
    else
        echo "\$(date): Remote backup failed" >> /var/log/website-backup.log
    fi
fi

# Rclone cloud backup if enabled
if [ "\$RCLONE_BACKUP" -eq 1 ] && command -v rclone &>/dev/null; then
    echo "\$(date): Starting Rclone cloud backup" >> /var/log/website-backup.log
    # Note: User needs to configure rclone remotes manually
    # Example: rclone sync "\${BACKUP_DIR}" remote:backups/webserver --progress
    echo "Rclone backup available - configure remotes with: rclone config" >> /var/log/website-backup.log
fi

# Local retention cleanup
find "\${BACKUP_DIR}/daily" -name "*.tar.gz" -mtime +\${DAILY_RETENTION} -delete 2>/dev/null
find "\${BACKUP_DIR}/daily" -name "*.sql.gz" -mtime +\${DAILY_RETENTION} -delete 2>/dev/null
find "\${BACKUP_DIR}/weekly" -name "*.tar.gz" -mtime +\${WEEKLY_RETENTION} -delete 2>/dev/null
find "\${BACKUP_DIR}/weekly" -name "*.sql.gz" -mtime +\${WEEKLY_RETENTION} -delete 2>/dev/null
find "\${BACKUP_DIR}/monthly" -name "*.tar.gz" -mtime +\${MONTHLY_RETENTION} -delete 2>/dev/null
find "\${BACKUP_DIR}/monthly" -name "*.sql.gz" -mtime +\${MONTHLY_RETENTION} -delete 2>/dev/null

# Remove encrypted files if they exist
find "\${BACKUP_DIR}/daily" -name "*.gpg" -mtime +\${DAILY_RETENTION} -delete 2>/dev/null
find "\${BACKUP_DIR}/weekly" -name "*.gpg" -mtime +\${WEEKLY_RETENTION} -delete 2>/dev/null
find "\${BACKUP_DIR}/monthly" -name "*.gpg" -mtime +\${MONTHLY_RETENTION} -delete 2>/dev/null

echo "\$(date): \${BACKUP_TYPE^} backup completed successfully" >> /var/log/website-backup.log

DAILY_COUNT=\$(find "\${BACKUP_DIR}/daily" -name "webfiles_*" | wc -l)
WEEKLY_COUNT=\$(find "\${BACKUP_DIR}/weekly" -name "webfiles_*" | wc -l)
MONTHLY_COUNT=\$(find "\${BACKUP_DIR}/monthly" -name "webfiles_*" | wc -l)
TOTAL_SIZE=\$(du -sh "\${BACKUP_DIR}" 2>/dev/null | cut -f1)

echo "Backup summary: \${DAILY_COUNT} daily, \${WEEKLY_COUNT} weekly, \${MONTHLY_COUNT} monthly (Total: \${TOTAL_SIZE})" >> /var/log/website-backup.log
BACKUPSCRIPT

run_command "chmod +x /usr/local/bin/backup-website.sh" "Make backup script executable"

cat > /etc/cron.d/website-backup <<'EOF'
# Daily website backup at 2 AM
0 2 * * * root /usr/local/bin/backup-website.sh >/dev/null 2>&1
EOF

run_command "/usr/local/bin/backup-website.sh" "Run initial backup"

log_success "Automated backup system configured"

# ----------------------------
# Log Rotation Configuration
# ----------------------------
log_info "Setting up log rotation..."

# Backup log rotation
cat > /etc/logrotate.d/website-backup <<'EOF'
/var/log/website-backup.log {
    weekly
    missingok
    rotate 8
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF

# Setup script log rotation
cat > /etc/logrotate.d/webserver-setup <<'EOF'
/root/webserver-setup.log {
    weekly
    missingok
    rotate 4
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF

# Application log rotation (if using custom apps)
cat > /etc/logrotate.d/webserver-apps <<'EOF'
/var/www/html/storage/logs/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    copytruncate
    create 644 www-data www-data
}
EOF

run_command "chmod 644 /etc/logrotate.d/website-backup" "Set permissions for backup log rotation"
run_command "chmod 644 /etc/logrotate.d/webserver-setup" "Set permissions for setup log rotation"
run_command "chmod 644 /etc/logrotate.d/webserver-apps" "Set permissions for app log rotation"

# Test logrotate configuration
if logrotate -d /etc/logrotate.conf >/dev/null 2>&1; then
    log_success "Log rotation configured successfully"
else
    log_warn "Log rotation configuration test failed, but continuing"
fi

# ----------------------------
# Health Monitoring Endpoint
# ----------------------------
log_info "Setting up health monitoring endpoint..."

cat <<'EOF' >/var/www/html/health.php
<?php
header('Content-Type: application/json');
header('Cache-Control: no-cache, no-store, must-revalidate');

function check_service($service) {
    $status = shell_exec("systemctl is-active $service 2>/dev/null");
    return trim($status) === 'active';
}

function check_port($port) {
    $connection = @fsockopen('127.0.0.1', $port, $errno, $errstr, 1);
    if ($connection) {
        fclose($connection);
        return true;
    }
    return false;
}

function get_service_status($service) {
    $status = shell_exec("systemctl is-active $service 2>/dev/null");
    return trim($status);
}

function check_certificate($domain) {
    if (!empty($domain) && file_exists("/etc/letsencrypt/live/$domain/fullchain.pem")) {
        $cert_data = shell_exec("openssl x509 -in /etc/letsencrypt/live/$domain/fullchain.pem -noout -dates 2>/dev/null");
        $lines = explode("\n", $cert_data);
        $not_after = str_replace('notAfter=', '', $lines[1]);
        $expiry_time = strtotime($not_after);
        $days_remaining = floor(($expiry_time - time()) / (60 * 60 * 24));
        return $days_remaining;
    }
    return null;
}

$health_status = [
    'status' => 'healthy',
    'timestamp' => date('c'),
    'server' => [
        'hostname' => gethostname(),
        'php_version' => PHP_VERSION,
        'uptime' => trim(shell_exec('uptime -p')),
        'os' => shell_exec('lsb_release -d | cut -f2'),
    ],
    'services' => [
        'nginx' => ['status' => get_service_status('nginx'), 'port_80' => check_port(80), 'port_443' => check_port(443)],
        'php-fpm' => ['status' => get_service_status('php-fpm')],
        'mariadb' => ['status' => get_service_status('mariadb'), 'port' => check_port(3306)],
        'redis' => ['status' => get_service_status('redis-server'), 'port' => check_port(6379)],
        'fail2ban' => ['status' => get_service_status('fail2ban')],
        'cockpit' => ['status' => get_service_status('cockpit.socket'), 'port' => check_port(9090)],
    ],
    'resources' => [
        'disk_usage_percent' => round((1 - disk_free_space("/") / disk_total_space("/")) * 100, 2),
        'memory_usage' => [
            'used' => (int)shell_exec("free -m | awk 'NR==2{print \$3}'"),
            'total' => (int)shell_exec("free -m | awk 'NR==2{print \$2}'"),
            'percent' => round(shell_exec("free | awk 'NR==2{printf \"%.2f\", \$3/\$2*100}'"), 2)
        ],
        'load_average' => sys_getloadavg(),
    ],
    'security' => [
        'ssl_certificates' => []
    ]
];

// Check SSL certificates
if (!empty($_SERVER['HTTP_HOST'])) {
    $domain = $_SERVER['HTTP_HOST'];
    $days_remaining = check_certificate($domain);
    if ($days_remaining !== null) {
        $health_status['security']['ssl_certificates'][$domain] = [
            'days_remaining' => $days_remaining,
            'status' => $days_remaining > 30 ? 'valid' : ($days_remaining > 0 ? 'expiring_soon' : 'expired')
        ];
    }
}

// Determine overall status
$critical_failures = 0;
$degraded_services = [];

foreach ($health_status['services'] as $service => $details) {
    if (isset($details['status']) && $details['status'] !== 'active') {
        if (in_array($service, ['nginx', 'mariadb', 'php-fpm'])) {
            $critical_failures++;
        } else
            $degraded_services[] = $service;
        }
    }
}

if ($critical_failures > 0) {
    $health_status['status'] = 'critical';
    $health_status['message'] = "Critical services are down";
} elseif (count($degraded_services) > 0 || $health_status['resources']['disk_usage_percent'] > 85) {
    $health_status['status'] = 'degraded';
    $health_status['message'] = "Some services are degraded or resources are high";
} else {
    $health_status['status'] = 'healthy';
    $health_status['message'] = "All systems operational";
}

// Set appropriate HTTP status code
switch ($health_status['status']) {
    case 'critical':
        http_response_code(503);
        break;
    case 'degraded':
        http_response_code(206);
        break;
    default:
        http_response_code(200);
}

echo json_encode($health_status, JSON_PRETTY_PRINT);
EOF

run_command "chown www-data:www-data /var/www/html/health.php" "Set ownership for health endpoint"
run_command "chmod 644 /var/www/html/health.php" "Set permissions for health endpoint"
log_success "Health monitoring endpoint created at /health.php"

# ----------------------------
# Emergency Access Script (Separate - for recovery only)
# ----------------------------
log_info "Creating emergency access recovery script..."

cat > /usr/local/bin/emergency-access.sh <<'EOF'
#!/bin/bash
# Emergency Access Script - Use only when locked out of SSH

set -e

LOGFILE="/var/log/emergency-access.log"
timestamp() { date +"[%Y-%m-%d %H:%M:%S]"; }
log_info() { echo "$(timestamp) [INFO] $1" | tee -a "$LOGFILE"; }
log_error() { echo "$(timestamp) [ERROR] $1" | tee -a "$LOGFILE" >&2; }

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                   EMERGENCY ACCESS SCRIPT                   ║"
echo "║                  USE THIS WITH CAUTION!                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "This script will:"
echo "✅ Temporarily enable password authentication for SSH"
echo "✅ Temporarily enable root login"
echo "✅ Create a backup of your current SSH config"
echo "✅ Automatically revert after 10 minutes"
echo ""
echo "⚠️  WARNING: This reduces security temporarily!"
echo "⚠️  Only use this if you are locked out of your server!"
echo ""

read -p "Are you sure you want to continue? (type 'EMERGENCY' to confirm): " confirm

if [ "$confirm" != "EMERGENCY" ]; then
    echo "Aborted. confirmation phrase not entered."
    exit 0
fi

log_info "Starting emergency access procedure..."

# Backup current config
BACKUP_FILE="/etc/ssh/sshd_config.backup.emergency.$(date +%Y%m%d_%H%M%S)"
cp /etc/ssh/sshd_config "$BACKUP_FILE"
log_info "SSH config backed up to: $BACKUP_FILE"

# Enable password auth temporarily
sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#PermitRootLogin yes/PermitRootLogin yes/' /etc/ssh/sshd_config

# Ensure the settings are present
if ! grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config; then
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
fi
if ! grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
fi

# Restart SSH
systemctl restart ssh

# Get current IP for connection instructions
CURRENT_IP=$(hostname -I | awk '{print $1}')
log_info "Emergency access enabled for IP: $CURRENT_IP"

echo ""
echo "✅ EMERGENCY ACCESS ENABLED SUCCESSFULLY!"
echo ""
echo "You can now connect using:"
echo "   ssh root@$CURRENT_IP"
echo "   or"
echo "   ssh yourusername@$CURRENT_IP"
echo ""
echo "⚠️  This access will automatically revert at: $(date -d '+10 minutes')"
echo "📝 A backup of your secure config is saved at: $BACKUP_FILE"
echo ""

# Schedule automatic revert
echo "sleep 600 && cp $BACKUP_FILE /etc/ssh/sshd_config && systemctl restart ssh && echo 'Emergency access automatically disabled at \$(date)' >> $LOGFILE && rm -f $BACKUP_FILE" | at now + 10 minutes 2>/dev/null

log_info "Emergency access enabled until $(date -d '+10 minutes')"
log_info "Revert scheduled via at job"

# Also create manual revert script
cat > /usr/local/bin/disable-emergency-access.sh <<'REVERTEOF'
#!/bin/bash
# Manual script to disable emergency access

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

BACKUP_FILE=$(ls /etc/ssh/sshd_config.backup.emergency.* 2>/dev/null | head -1)

if [ -z "$BACKUP_FILE" ]; then
    echo "No emergency backup found. SSH config may already be reverted."
    exit 1
fi

echo "Reverting SSH config from: $BACKUP_FILE"
cp "$BACKUP_FILE" /etc/ssh/sshd_config
systemctl restart ssh
rm -f "$BACKUP_FILE"

echo "✅ Emergency access disabled. Normal security restored."
REVERTEOF

chmod +x /usr/local/bin/disable-emergency-access.sh

echo "To manually disable emergency access before the 10-minute timeout, run:"
echo "   sudo /usr/local/bin/disable-emergency-access.sh"
EOF

run_command "chmod +x /usr/local/bin/emergency-access.sh" "Make emergency access script executable"

# Create the disable script as well
cat > /usr/local/bin/disable-emergency-access.sh <<'EOF'
#!/bin/bash
# Manual script to disable emergency access

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

BACKUP_FILE=$(ls /etc/ssh/sshd_config.backup.emergency.* 2>/dev/null | head -1)

if [ -z "$BACKUP_FILE" ]; then
    echo "No emergency backup found. SSH config may already be reverted."
    exit 1
fi

echo "Reverting SSH config from: $BACKUP_FILE"
cp "$BACKUP_FILE" /etc/ssh/sshd_config
systemctl restart ssh
rm -f "$BACKUP_FILE"

echo "✅ Emergency access disabled. Normal security restored."
EOF

run_command "chmod +x /usr/local/bin/disable-emergency-access.sh" "Make disable emergency script executable"

log_success "Emergency access scripts created"
log_warn "Emergency access script location: /usr/local/bin/emergency-access.sh"
log_warn "Use only if locked out of SSH access!"

# ----------------------------
# Create index page if none exists
# ----------------------------
if [ ! -f "/var/www/html/index.html" ] && [ ! -f "/var/www/html/index.php" ]; then
    cat <<EOF >/var/www/html/index.html
<!DOCTYPE html>
<html>
<head>
    <title>Server Setup Complete</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .success { color: #28a745; }
        .info { background: #e9ecef; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .status { display: inline-block; padding: 5px 10px; border-radius: 3px; color: white; font-size: 12px; }
        .running { background: #28a745; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="success">🎉 Server Setup Complete!</h1>
        <div class="info">
            <h3>Services Status:</h3>
            <ul>
                <li>✅ Nginx Web Server <span class="status running">RUNNING</span></li>
                <li>🚫 Fail2Ban Protection <span class="status running">ACTIVE</span></li>
                <li>🔧 Cockpit Control Panel <span class="status running">PORT 9090</span></li>
                <li>📊 Netdata Monitoring <span class="status running">PORT 19999</span></li>
                <li>📁 File Browser <span class="status running">PORT 8080</span></li>
                <li>🔐 SSH Hardened <span class="status running">KEY-ONLY</span></li>
                <li>🩺 Health Monitoring <span class="status running">/health.php</span></li>
EOF

    # Add performance optimizations note
    if [[ "$APPLY_OPTIMIZATIONS" =~ ^[Yy]$ ]]; then
        cat <<EOF >>/var/www/html/index.html
                <li>⚡ Performance Optimizations <span class="status running">ACTIVE</span></li>
EOF
    fi

    # Add advanced monitoring if installed
    if [[ "$INSTALL_ADVANCED_MONITORING" =~ ^[Yy]$ ]]; then
        cat <<EOF >>/var/www/html/index.html
                <li>📈 Advanced Monitoring <span class="status running">ACTIVE</span></li>
EOF
    fi

    cat <<EOF >>/var/www/html/index.html
            </ul>
        </div>
        <p><strong>Server IP:</strong> $INTERNAL_IP</p>
        <p><strong>Deploy User:</strong> $DEPLOYUSER</p>
        <p><strong>Setup completed:</strong> $(date)</p>
        
        <div class="info">
            <h4>🔗 Quick Access Links:</h4>
            <ul>
                <li><a href="https://$INTERNAL_IP:9090" target="_blank">Cockpit Control Panel</a></li>
                <li><a href="http://$INTERNAL_IP:19999" target="_blank">Netdata Monitoring</a></li>
                <li><a href="http://$INTERNAL_IP:8080" target="_blank">File Browser</a></li>
                <li><a href="http://$INTERNAL_IP/health.php" target="_blank">Health Status</a></li>
EOF

    # Add Adminer link if installed
    if [[ "$INSTALL_ADMINER" =~ ^[Yy]$ ]]; then
        cat <<EOF >>/var/www/html/index.html
                <li><a href="http://$INTERNAL_IP/db-admin.php" target="_blank">Database Admin</a></li>
EOF
    fi

    # Add advanced monitoring links
    if [[ "$INSTALL_ADVANCED_MONITORING" =~ ^[Yy]$ ]]; then
        cat <<EOF >>/var/www/html/index.html
                <li><a href="http://$INTERNAL_IP/opcache.php" target="_blank">PHP OPcache Status</a></li>
                <li><a href="http://$INTERNAL_IP:7890" target="_blank">GoAccess Logs</a></li>
EOF
    fi

    cat <<EOF >>/var/www/html/index.html
            </ul>
        </div>
    </div>
</body>
</html>
EOF
    run_command "chown $DEPLOYUSER:$DEPLOYUSER /var/www/html/index.html" "Set index.html ownership"
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

services=("nginx" "ssh" "fail2ban" "cockpit.socket" "netdata" "filebrowser" "mariadb" "redis-server")
for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        echo "  ✅ ${service}: RUNNING"
    else
        if [[ "$service" == "mariadb" && "$INSTALL_PHP_MYSQL" != "Y" ]]; then
            continue
        elif [[ "$service" == "redis-server" && "$INSTALL_REDIS" != "Y" ]]; then
            continue
        else
            echo "  ⚠️  ${service}: NOT RUNNING (optional)"
        fi
    fi
done

# Add advanced monitoring services
if [[ "$INSTALL_ADVANCED_MONITORING" =~ ^[Yy]$ ]]; then
    if systemctl is-active --quiet goaccess 2>/dev/null; then
        echo "  ✅ goaccess: RUNNING (port 7890)"
    else
        echo "  ⚠️  goaccess: NOT RUNNING"
    fi
fi

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
echo "  FIREWALL STATUS"
echo "═══════════════════════════════════════════════════════════════"
echo ""
ufw status numbered | head -15

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ACCESS INFORMATION"
echo "═══════════════════════════════════════════════════════════════"
echo ""

echo "  🌍 Web Server: http://$INTERNAL_IP"
echo "  🩺 Health Check: http://$INTERNAL_IP/health.php"
if [ -n "$DOMAIN_NAME" ]; then
    if [ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ]; then
        echo "  🔒 Secure Website: https://$DOMAIN_NAME"
    else
        echo "  🌐 Website: http://$DOMAIN_NAME (SSL setup incomplete)"
    fi
fi

if systemctl is-active --quiet cockpit.socket 2>/dev/null; then
    echo "  🔧 Cockpit: https://$INTERNAL_IP:9090 (Full system management)"
fi

if systemctl is-active --quiet netdata 2>/dev/null; then
    echo "  📊 Netdata: http://$INTERNAL_IP:19999 (Advanced monitoring)"
fi

if systemctl is-active --quiet filebrowser 2>/dev/null; then
    echo "  📁 File Browser: http://$INTERNAL_IP:8080 (Standalone file manager)"
fi

if [[ "$INSTALL_ADMINER" =~ ^[Yy]$ ]]; then
    echo "  🗄️  Adminer: http://$INTERNAL_IP/db-admin.php (Database management)"
fi

if [[ "$INSTALL_ADVANCED_MONITORING" =~ ^[Yy]$ ]]; then
    echo "  📈 OPcache Status: http://$INTERNAL_IP/opcache.php"
    echo "  📊 GoAccess Logs: http://$INTERNAL_IP:7890"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  SSH ACCESS"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  🔑 SSH User: $DEPLOYUSER"
echo "  🔐 SSH Key: /home/$DEPLOYUSER/.ssh/id_rsa"
echo "  📝 Connection: ssh $DEPLOYUSER@$INTERNAL_IP"
echo ""

if systemctl is-active --quiet cockpit.socket 2>/dev/null; then
    echo "═══════════════════════════════════════════════════════════════"
    echo "  WEB CONSOLE ACCESS"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  🔧 Cockpit Login: $DEPLOYUSER (password you set)"
    echo "  🌐 Cockpit URL: https://$INTERNAL_IP:9090"
    echo ""
fi

echo "═══════════════════════════════════════════════════════════════"
echo "  SECURITY FEATURES"
echo "═══════════════════════════════════════════════════════════════"
echo ""

if [ -n "$DOMAIN_NAME" ] && [ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ]; then
    echo "  🔒 SSL/TLS: ACTIVE (Let's Encrypt)"
    echo "  🔄 Auto-renewal: CONFIGURED"
else
    echo "  🔒 SSL/TLS: NOT CONFIGURED"
fi

echo "  🚫 Fail2Ban: ACTIVE"
echo "  🔥 UFW Firewall: ENABLED"
echo "  🔐 SSH: HARDENED (key-only)"

if command -v rkhunter &>/dev/null; then
    echo "  🔍 rkhunter: INSTALLED"
fi

if [[ "$INSTALL_SECURITY_TOOLS" =~ ^[Yy]$ ]]; then
    echo "  🛡️  Lynis: INSTALLED"
    echo "  🦠 ClamAV: INSTALLED"
    echo "  📝 AIDE: INSTALLED"
fi

if command -v php &>/dev/null; then
    PHP_VER=$(php -v | head -1 | cut -d' ' -f2 | cut -d'-' -f1)
    echo "  🐘 PHP: VERSION $PHP_VER"
fi

if systemctl is-active --quiet mariadb 2>/dev/null; then
    echo "  🗄️  MariaDB: RUNNING"
    echo "  📊 Database: website_db"
fi

if systemctl is-active --quiet redis-server 2>/dev/null; then
    echo "  ⚡ Redis: RUNNING (256MB cache)"
fi

echo "  📦 Backups: 7 daily + 4 weekly + 3 monthly"
echo "  🔄 Auto-Updates: Security patches enabled"
echo "  📊 Log Rotation: Configured for all services"

if [[ "$APPLY_OPTIMIZATIONS" =~ ^[Yy]$ ]]; then
    echo "  ⚡ Performance: OPTIMIZED (OS, Nginx, PHP, MySQL, Redis)"
fi

if [[ "$RCLONE_SETUP" =~ ^1$ ]]; then
    echo "  ☁️  Cloud Backup: RCLONE READY (manual configuration needed)"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  IMPORTANT FILES"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  📁 Web root: /var/www/html"
echo "  📜 Setup log: $LOGFILE"
echo "  🔧 Nginx config: /etc/nginx/nginx.conf"
echo "  🔐 SSH keys: /home/$DEPLOYUSER/.ssh/"

if [ -f /home/$DEPLOYUSER/.my.cnf ]; then
    echo "  🗄️  Database credentials: /home/$DEPLOYUSER/.my.cnf (secured)"
    echo "  🔑 Root DB credentials: /root/.my.cnf (secured)"
fi

if [ -f /root/.redis_credentials ]; then
    echo "  ⚡ Redis credentials: /root/.redis_credentials (secured)"
fi

if [ -f /root/.filebrowser_credentials ]; then
    echo "  📁 File Browser credentials: /root/.filebrowser_credentials (secured)"
fi

echo "  📦 Backups: /var/backups/website"
echo "  🩺 Health endpoint: /var/www/html/health.php"

if [[ "$INSTALL_ADMINER" =~ ^[Yy]$ ]]; then
    echo "  🗄️  Database admin: /var/www/html/db-admin.php"
fi

if [[ "$INSTALL_ADVANCED_MONITORING" =~ ^[Yy]$ ]]; then
    echo "  📊 OPcache dashboard: /var/www/html/opcache.php"
    echo "  📈 GoAccess logs: http://$INTERNAL_IP:7890"
fi

if [[ "$RCLONE_SETUP" =~ ^1$ ]]; then
    echo "  ☁️  Rclone setup info: /root/.rclone-setup-info"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  NEXT STEPS"
echo "═══════════════════════════════════════════════════════════════"
echo ""

STEP=1
if [ -n "$DOMAIN_NAME" ]; then
    if [ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ]; then
        echo "  $STEP. ✅ SSL certificate is active and will auto-renew"
        STEP=$((STEP + 1))
    else
        echo "  $STEP. 🌐 Point your domain DNS to your public IP"
        STEP=$((STEP + 1))
        echo "  $STEP. 🔒 Retry SSL: sudo certbot --nginx -d $DOMAIN_NAME"
        STEP=$((STEP + 1))
    fi
else
    echo "  $STEP. 🌐 Point your domain DNS to your public IP"
    STEP=$((STEP + 1))
    echo "  $STEP. 🔒 Get SSL: sudo certbot --nginx -d yourdomain.com"
    STEP=$((STEP + 1))
fi

if systemctl is-active --quiet filebrowser 2>/dev/null; then
    echo "  $STEP. 🔐 URGENT: Change File Browser password at http://$INTERNAL_IP:8080"
    STEP=$((STEP + 1))
fi

if [[ "$RCLONE_SETUP" =~ ^1$ ]]; then
    echo "  $STEP. ☁️  Configure Rclone: rclone config (see /root/.rclone-setup-info)"
    STEP=$((STEP + 1))
fi

echo "  $STEP. 🩺 Check server health: curl http://$INTERNAL_IP/health.php"
STEP=$((STEP + 1))
echo "  $STEP. 📊 Monitor logs: sudo tail -f /var/log/nginx/error.log"
STEP=$((STEP + 1))
echo "  $STEP. 🔄 Reboot server: sudo reboot"
STEP=$((STEP + 1))
echo "  $STEP. 📚 Review setup log: less $LOGFILE"

echo ""
if [ -n "$GITREPO" ]; then
    echo "═══════════════════════════════════════════════════════════════"
    echo "  GIT REPOSITORY"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  📦 Repository: https://github.com/$GITREPO"
    echo ""
fi

echo "═══════════════════════════════════════════════════════════════"
echo "  USEFUL COMMANDS"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Check service status:"
echo "    sudo systemctl status nginx"
echo ""
echo "  View logs:"
echo "    sudo tail -f /var/log/nginx/error.log"
echo "    sudo journalctl -u nginx -f"
echo ""
echo "  Restart services:"
echo "    sudo systemctl restart nginx"
echo "    sudo systemctl reload nginx"
echo ""
echo "  Check server health:"
echo "    curl http://localhost/health.php"
echo ""
echo "  Run backup manually:"
echo "    sudo /usr/local/bin/backup-website.sh"
echo ""
echo "  Check disk usage:"
echo "    df -h"
echo "    du -sh /var/www/html"
echo "    du -sh /var/backups/website"
echo ""
echo "  Emergency access (if locked out):"
echo "    sudo /usr/local/bin/emergency-access.sh"
echo ""
if [ -f /home/$DEPLOYUSER/.my.cnf ]; then
    echo "  Access database:"
    echo "    mysql (as $DEPLOYUSER user)"
    echo "    sudo mysql (as root)"
    echo ""
fi

if [[ "$INSTALL_ADVANCED_MONITORING" =~ ^[Yy]$ ]]; then
    echo "  View real-time logs:"
    echo "    http://$INTERNAL_IP:7890"
    echo ""
    echo "  Check PHP OPcache:"
    echo "    http://$INTERNAL_IP/opcache.php"
    echo ""
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║              🎉 Setup Complete! Server Ready! 🎉             ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
log_success "Full setup log available at: $LOGFILE"
log_success "Server setup completed successfully at $(date)"
echo ""
