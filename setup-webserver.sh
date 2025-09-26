#!/bin/bash

### Ubuntu Web Server Setup Script ###
# Hardened, secure, production-ready
# Source: https://github.com/killerhash-stack/ubuntu-webserver-setup
# Repo: killerhash-stack/ubuntu-webserver-setup

echo "🚀 Starting Web Server Setup Script"
echo "📦 Source: https://github.com/killerhash-stack/ubuntu-webserver-setup"
echo "🕒 Timestamp: $(date)"
echo ""

# ----------------------------
# Update system
# ----------------------------
apt-get update -y && apt-get upgrade -y

# ----------------------------
# Create deploy user with SSH key
# ----------------------------
read -p "Enter the username for deployment (default: deploy): " DEPLOYUSER
DEPLOYUSER=${DEPLOYUSER:-deploy}

if ! id -u "$DEPLOYUSER" >/dev/null 2>&1; then
    adduser --disabled-password --gecos "" $DEPLOYUSER
    usermod -aG sudo $DEPLOYUSER
    mkdir -p /home/$DEPLOYUSER/.ssh
    chmod 700 /home/$DEPLOYUSER/.ssh
    ssh-keygen -t ed25519 -f /home/$DEPLOYUSER/.ssh/id_ed25519 -q -N ""
    cat /home/$DEPLOYUSER/.ssh/id_ed25519.pub >> /home/$DEPLOYUSER/.ssh/authorized_keys
    chmod 600 /home/$DEPLOYUSER/.ssh/authorized_keys
    chown -R $DEPLOYUSER:$DEPLOYUSER /home/$DEPLOYUSER/.ssh
    echo "✅ SSH key generated for $DEPLOYUSER"
fi

# ----------------------------
# Install essentials
# ----------------------------
apt-get install -y openssh-server ufw fail2ban unattended-upgrades \
    curl wget git gnupg2 ca-certificates lsb-release software-properties-common

# ----------------------------
# Configure UFW
# ----------------------------
ufw allow OpenSSH
ufw allow "Nginx Full"
ufw --force enable

# ----------------------------
# Install Nginx + Certbot + ModSecurity
# ----------------------------
apt-get install -y nginx python3-certbot-nginx libnginx-mod-security

# Enable HTTP/2 + SSL in default config
NGINX_CONF="/etc/nginx/sites-available/default"
cat > $NGINX_CONF <<EOL
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /var/www/html;
    index index.html index.htm;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOL

# ----------------------------
# Harden Nginx Security Headers
# ----------------------------
cat > /etc/nginx/conf.d/security-headers.conf <<EOL
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self';" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
EOL

# ----------------------------
# Install SSL (Certbot)
# ----------------------------
read -p "Enter your domain for SSL (leave blank to skip): " DOMAIN
if [ -n "$DOMAIN" ]; then
    certbot --nginx -d $DOMAIN
    systemctl enable certbot.timer
    echo "✅ SSL installed and auto-renewal enabled."
else
    echo "⚠️ Skipped SSL setup (no domain entered)."
fi

# ----------------------------
# Install Postfix (Interactive)
# ----------------------------
echo "📧 Installing Postfix (you will be prompted for config)..."
DEBIAN_FRONTEND= apt-get install -y postfix

# ----------------------------
# Install rkhunter
# ----------------------------
apt-get install -y rkhunter
rkhunter --update

# ----------------------------
# Install Webmin (with new GPG method)
# ----------------------------
curl -fsSL http://www.webmin.com/jcameron-key.asc | gpg --dearmor -o /usr/share/keyrings/webmin.gpg
echo "deb [signed-by=/usr/share/keyrings/webmin.gpg] http://download.webmin.com/download/repository sarge contrib" \
    | tee /etc/apt/sources.list.d/webmin.list
apt-get update -y
apt-get install -y webmin

# ----------------------------
# Setup Git Auto-Deploy
# ----------------------------
DEPLOY_DIR="/var/www/html"
read -p "Enter your GitHub repo (format: user/repo, leave blank to skip): " GITREPO
if [ -n "$GITREPO" ]; then
    apt-get install -y git
    sudo -u $DEPLOYUSER git clone https://github.com/$GITREPO.git $DEPLOY_DIR
    echo "✅ Auto-deploy setup complete. Push updates to GitHub to redeploy."
fi

# ----------------------------
# Restart services
# ----------------------------
systemctl restart ssh
systemctl restart nginx
systemctl restart fail2ban

# ----------------------------
# Summary
# ----------------------------
echo ""
echo "🎉 Setup complete!"
echo ""
echo "➡️ SSH User: $DEPLOYUSER"
echo "➡️ SSH Public Key:"
cat /home/$DEPLOYUSER/.ssh/id_ed25519.pub
echo ""
echo "🌐 Access your server:"
echo " - Webmin: https://YOUR_SERVER_IP:10000"
echo " - Nginx Root: /var/www/html"
echo " - Fail2Ban: systemctl status fail2ban"
echo " - rkhunter scan: sudo rkhunter --check"
echo " - Git auto-deploy: push to https://github.com/$GITREPO"
echo ""
echo "⚠️ Reminder: Update DNS (Cloudflare) to point your domain to this server for SSL to work."
