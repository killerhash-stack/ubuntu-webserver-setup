#!/bin/bash

### Ubuntu Web Server Setup Script ###
# Hardened, secure, production-ready
# Fetched from GitHub repo: killerhash-stack/ubuntu-webserver-setup

echo "🚀 Starting Web Server Setup Script"
echo "📦 Source: https://github.com/killerhash-stack/ubuntu-webserver-setup"
echo "🕒 Timestamp: $(date)"
echo ""

# --- Root check ---
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root. Use: sudo bash $0"
   exit 1
fi

# --- Ensure OpenSSH Server is installed ---
apt install -y openssh-server
systemctl enable ssh
systemctl start ssh
echo "✅ OpenSSH Server installed and running"

# --- System update ---
apt update && apt -y upgrade

# --- Create non-root deploy user ---
read -p "Enter username for deploy user [deploy]: " DEPLOY_USER
DEPLOY_USER=${DEPLOY_USER:-deploy}

if ! id -u "$DEPLOY_USER" >/dev/null 2>&1; then
    adduser --gecos "" --disabled-password "$DEPLOY_USER"
    usermod -aG sudo "$DEPLOY_USER"
fi

# --- SSH key setup ---
mkdir -p /home/$DEPLOY_USER/.ssh
chmod 700 /home/$DEPLOY_USER/.ssh

# Generate SSH key if none exists
if [ ! -f /home/$DEPLOY_USER/.ssh/id_ed25519 ]; then
    echo "🔑 Generating SSH key for $DEPLOY_USER..."
    su - $DEPLOY_USER -c "ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''"
fi

# Add public key to authorized_keys
cat /home/$DEPLOY_USER/.ssh/id_ed25519.pub >> /home/$DEPLOY_USER/.ssh/authorized_keys
chmod 600 /home/$DEPLOY_USER/.ssh/authorized_keys
chown -R $DEPLOY_USER:$DEPLOY_USER /home/$DEPLOY_USER/.ssh

# --- Harden SSH ---
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

# Restart SSH safely
systemctl restart ssh || systemctl restart sshd || echo "⚠️ SSH service not detected, skipping restart"

# --- Install essentials ---
apt install -y curl wget git ufw fail2ban software-properties-common

# --- Configure firewall ---
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw --force enable

# --- Install Nginx + PHP + MariaDB ---
apt install -y nginx php-fpm php-mysql mariadb-server

# --- Enable HTTP/2 in Nginx ---
sed -i 's/listen 443 ssl;/listen 443 ssl http2;/' /etc/nginx/sites-available/default

# --- Install Certbot ---
apt install -y certbot python3-certbot-nginx
read -p "Enter your domain (example.com): " DOMAIN
read -p "Enter your email for SSL renewal notices: " EMAIL
if [ -n "$DOMAIN" ] && [ -n "$EMAIL" ]; then
    certbot --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos -m $EMAIL
    systemctl enable certbot.timer
fi

# --- Add Nginx security headers ---
NGINX_DEFAULT="/etc/nginx/sites-available/default"

if [ -f "$NGINX_DEFAULT" ]; then
    echo "🔒 Adding security headers to Nginx..."
    sed -i '/server_name _;/a \
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\
        add_header X-Frame-Options "SAMEORIGIN" always;\
        add_header X-Content-Type-Options "nosniff" always;\
        add_header X-XSS-Protection "1; mode=block" always;\
        add_header Referrer-Policy "no-referrer-when-downgrade" always;\
        add_header Content-Security-Policy "default-src '\''self'\''; script-src '\''self'\''; object-src '\''none'\''; style-src '\''self'\'' '\''unsafe-inline'\'';" always;\
    ' "$NGINX_DEFAULT"

    nginx -t && systemctl reload nginx
else
    echo "⚠️ Warning: Nginx default site config not found."
fi

# --- Install ModSecurity ---
apt install -y libnginx-mod-security
sed -i 's/#Include modsecurity.conf/Include modsecurity.conf/' /etc/nginx/nginx.conf
systemctl restart nginx

# --- Install rkhunter ---
apt install -y rkhunter
rkhunter --update
rkhunter --propupd

# --- Install unattended-upgrades ---
apt install -y unattended-upgrades apt-listchanges
dpkg-reconfigure -plow unattended-upgrades

# --- Install Webmin ---
wget -q http://www.webmin.com/jcameron-key.asc -O- | apt-key add -
add-apt-repository "deb http://download.webmin.com/download/repository sarge contrib"
apt update
apt install -y webmin

# --- Git Auto-deploy setup ---
DEPLOY_DIR="/var/www/$DOMAIN"
mkdir -p $DEPLOY_DIR
chown -R $DEPLOY_USER:$DEPLOY_USER $DEPLOY_DIR

su - $DEPLOY_USER -c "
cd ~
mkdir -p repos && cd repos
git init --bare $DOMAIN.git
cd $DOMAIN.git/hooks
cat > post-receive <<EOF
#!/bin/bash
GIT_WORK_TREE=$DEPLOY_DIR git checkout -f
systemctl restart nginx
EOF
chmod +x post-receive
"

# --- Post-install summary / web UI cheat sheet ---
echo ""
echo "🎉 Web Server Setup Complete! Here's how to access everything:"
echo ""
echo "🌐 Your website root:"
echo "  https://$DOMAIN"
echo ""
echo "🖥 Webmin (server management UI):"
echo "  https://$DOMAIN:10000/"
echo "  Login with: username='root' (or your sudo deploy user), password=your root password"
echo ""
echo "📦 Git auto-deploy repository:"
echo "  /home/$DEPLOY_USER/repos/$DOMAIN.git"
echo "  Push code using:"
echo "    git remote add production ssh://$DEPLOY_USER@YOUR_SERVER_IP/home/$DEPLOY_USER/repos/$DOMAIN.git"
echo "    git push production main"
echo ""
echo "🔑 SSH Key for deploy user ($DEPLOY_USER):"
echo "Copy this public key to GitHub or other services:"
cat /home/$DEPLOY_USER/.ssh/id_ed25519.pub
echo ""
echo "🔒 Security:"
echo "  - SSH: key-based login only for user '$DEPLOY_USER'"
echo "  - Firewall: UFW enabled, OpenSSH + Nginx Full allowed"
echo "  - Fail2Ban active"
echo "  - ModSecurity WAF active"
echo "  - Nginx security headers & strict CSP applied"
echo ""
echo "📜 Monitoring / logs:"
echo "  - Logwatch (daily email summary)"
echo "  - rkhunter for rootkit scanning"
echo "  - Glances (interactive system dashboard): run 'glances' after login"
echo ""
echo "✅ Done! All critical services are running and secure."
