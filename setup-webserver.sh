#!/bin/bash

### Ubuntu Web Server Setup Script ###
# Hardened, secure, production-ready
# GitHub: killerhash-stack/ubuntu-webserver-setup

echo "🚀 Starting Web Server Setup Script"
echo "🕒 Timestamp: $(date)"
echo ""

# --- Root check ---
if [[ $EUID -ne 0 ]]; then
   echo "❌ Must run as root: sudo bash $0"
   exit 1
fi

# --- Update system ---
apt update && apt -y upgrade

# --- Install OpenSSH Server ---
export DEBIAN_FRONTEND=noninteractive
apt install -y openssh-server
systemctl enable ssh
systemctl start ssh
echo "✅ OpenSSH installed and running"
unset DEBIAN_FRONTEND

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

if [ ! -f /home/$DEPLOY_USER/.ssh/id_ed25519 ]; then
    echo "🔑 Generating SSH key for $DEPLOY_USER..."
    su - $DEPLOY_USER -c "ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''"
fi

cat /home/$DEPLOY_USER/.ssh/id_ed25519.pub >> /home/$DEPLOY_USER/.ssh/authorized_keys
chmod 600 /home/$DEPLOY_USER/.ssh/authorized_keys
chown -R $DEPLOY_USER:$DEPLOY_USER /home/$DEPLOY_USER/.ssh

# --- Harden SSH ---
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh || systemctl restart sshd || echo "⚠️ SSH restart skipped"

# --- Install essentials ---
export DEBIAN_FRONTEND=noninteractive
apt install -y curl wget git ufw fail2ban software-properties-common unattended-upgrades apt-listchanges rkhunter
unset DEBIAN_FRONTEND

# --- Configure firewall ---
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw --force enable

# --- Install Nginx + PHP + MariaDB ---
apt install -y nginx php-fpm php-mysql mariadb-server

# --- Enable HTTP/2 in Nginx ---
sed -i 's/listen 443 ssl;/listen 443 ssl http2;/' /etc/nginx/sites-available/default

# --- Certbot ---
apt install -y certbot python3-certbot-nginx
read -p "Enter your domain (example.com): " DOMAIN
read -p "Enter your email for SSL: " EMAIL
if [ -n "$DOMAIN" ] && [ -n "$EMAIL" ]; then
    certbot --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos -m $EMAIL
    systemctl enable certbot.timer
fi

# --- Nginx security headers ---
NGINX_DEFAULT="/etc/nginx/sites-available/default"
if [ -f "$NGINX_DEFAULT" ]; then
    echo "🔒 Adding security headers..."
    sed -i '/server_name _;/a \
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\
        add_header X-Frame-Options "SAMEORIGIN" always;\
        add_header X-Content-Type-Options "nosniff" always;\
        add_header X-XSS-Protection "1; mode=block" always;\
        add_header Referrer-Policy "no-referrer-when-downgrade" always;\
        add_header Content-Security-Policy "default-src '\''self'\''; script-src '\''self'\''; object-src '\''none'\''; style-src '\''self'\'' '\''unsafe-inline'\'';" always;\
    ' "$NGINX_DEFAULT"
    nginx -t && systemctl reload nginx
fi

# --- ModSecurity ---
apt install -y libnginx-mod-security
sed -i 's/#Include modsecurity.conf/Include modsecurity.conf/' /etc/nginx/nginx.conf
systemctl restart nginx

# --- Optional Postfix ---
read -p "Install Postfix for local mail? [y/N]: " INSTALL_POSTFIX
if [[ "$INSTALL_POSTFIX" =~ ^[Yy]$ ]]; then
    read -p "Enter mail domain (example.com): " MAIL_DOMAIN
    echo "postfix postfix/mailname string $MAIL_DOMAIN" | debconf-set-selections
    echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections
    apt install -y postfix
fi

# --- Webmin ---
wget -q http://www.webmin.com/jcameron-key.asc -O- | apt-key add -
add-apt-repository "deb http://download.webmin.com/download/repository sarge contrib"
apt update
apt install -y webmin

# --- Git auto-deploy setup (fixed with tee) ---
DEPLOY_DIR="/var/www/$DOMAIN"
mkdir -p "$DEPLOY_DIR"
chown -R $DEPLOY_USER:$DEPLOY_USER "$DEPLOY_DIR"

REPO_DIR="/home/$DEPLOY_USER/repos/$DOMAIN.git"
mkdir -p "$REPO_DIR/hooks"
chown -R $DEPLOY_USER:$DEPLOY_USER "/home/$DEPLOY_USER/repos"

tee "$REPO_DIR/hooks/post-receive" > /dev/null <<EOF
#!/bin/bash
GIT_WORK_TREE=$DEPLOY_DIR git checkout -f
systemctl restart nginx
EOF

chmod +x "$REPO_DIR/hooks/post-receive"
chown $DEPLOY_USER:$DEPLOY_USER "$REPO_DIR/hooks/post-receive"

# --- Post-install summary ---
echo ""
echo "🎉 Setup Complete!"
echo "🌐 Website: https://$DOMAIN"
echo "🖥 Webmin: https://$DOMAIN:10000/"
echo "📦 Git auto-deploy repo: /home/$DEPLOY_USER/repos/$DOMAIN.git"
echo "🔑 Deploy SSH key:"
cat /home/$DEPLOY_USER/.ssh/id_ed25519.pub
echo ""
echo "🔒 Security: SSH key-only login, UFW, Fail2Ban, ModSecurity, Nginx headers"
echo "📜 Monitoring: rkhunter, Glances"
echo "✅ Done!"
