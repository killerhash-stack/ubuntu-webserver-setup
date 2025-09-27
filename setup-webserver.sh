#!/bin/bash
set -e

echo "🚀 Ubuntu Web Server Setup Starting..."

# ============================
# Update and Upgrade System
# ============================
apt-get update -y && apt-get upgrade -y

# ============================
# Prompt for deploy user
# ============================
read -p "Enter the name for the deploy user: " DEPLOYUSER

# ============================
# Create deploy user
# ============================
if ! id -u "$DEPLOYUSER" >/dev/null 2>&1; then
    adduser --disabled-password --gecos "" $DEPLOYUSER
    usermod -aG sudo $DEPLOYUSER
fi

# ============================
# SSH Key Setup
# ============================
mkdir -p /home/$DEPLOYUSER/.ssh
chmod 700 /home/$DEPLOYUSER/.ssh
read -p "Paste your SSH public key: " SSHKEY
echo "$SSHKEY" > /home/$DEPLOYUSER/.ssh/authorized_keys
chmod 600 /home/$DEPLOYUSER/.ssh/authorized_keys
chown -R $DEPLOYUSER:$DEPLOYUSER /home/$DEPLOYUSER/.ssh

# Harden SSH
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh

# ============================
# Install Essentials
# ============================
apt-get install -y \
    nginx \
    software-properties-common \
    ufw \
    fail2ban \
    git \
    curl \
    wget \
    unzip \
    unattended-upgrades \
    apt-listchanges \
    rkhunter

# ============================
# Enable Firewall
# ============================
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw --force enable

# ============================
# Configure unattended upgrades
# ============================
dpkg-reconfigure -plow unattended-upgrades

# ============================
# Install Certbot (SSL)
# ============================
apt-get install -y certbot python3-certbot-nginx

# ============================
# Install ModSecurity + OWASP CRS
# ============================
apt-get install -y libnginx-mod-security2
cp /etc/nginx/modsecurity/modsecurity.conf-recommended /etc/nginx/modsecurity/modsecurity.conf
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsecurity/modsecurity.conf
wget https://github.com/coreruleset/coreruleset/archive/refs/heads/v3.3/master.zip -O /tmp/owasp-crs.zip
unzip /tmp/owasp-crs.zip -d /etc/nginx/
mv /etc/nginx/coreruleset-*/ /etc/nginx/owasp-crs
cp /etc/nginx/owasp-crs/crs-setup.conf.example /etc/nginx/owasp-crs/crs-setup.conf

cat > /etc/nginx/modsec/main.conf <<EOL
Include /etc/nginx/modsecurity/modsecurity.conf
Include /etc/nginx/owasp-crs/crs-setup.conf
Include /etc/nginx/owasp-crs/rules/*.conf
EOL

sed -i '/http {/a \    modsecurity on;\n    modsecurity_rules_file /etc/nginx/modsec/main.conf;' /etc/nginx/nginx.conf

# ============================
# Enable HTTP/2 + Security Headers
# ============================
sed -i 's/listen 80 default_server;/listen 80 default_server;\n    listen [::]:80 default_server;\n    listen 443 ssl http2 default_server;\n    listen [::]:443 ssl http2 default_server;/' /etc/nginx/sites-available/default

cat > /etc/nginx/snippets/security-headers.conf <<EOL
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
EOL

sed -i '/server_name _;/a \    include snippets/security-headers.conf;' /etc/nginx/sites-available/default

# ============================
# Restart Nginx
# ============================
systemctl restart nginx || echo "⚠️ Nginx failed to start. Check config: sudo nginx -t"

# ============================
# Install Webmin
# ============================
wget -q -O- http://www.webmin.com/jcameron-key.asc | gpg --dearmor > /etc/apt/trusted.gpg.d/webmin.gpg
echo "deb https://download.webmin.com/download/repository sarge contrib" > /etc/apt/sources.list.d/webmin.list
apt-get update -y
apt-get install -y webmin

# Bind Webmin to internal IP only
INTERNAL_IP=$(hostname -I | awk '{print $1}')
sed -i "s/^\(listen=\).*/\1$INTERNAL_IP/" /etc/webmin/miniserv.conf || echo "listen=$INTERNAL_IP" >> /etc/webmin/miniserv.conf
systemctl restart webmin

# ============================
# Install Netdata (via kickstart)
# ============================
bash <(curl -Ss https://my-netdata.io/kickstart.sh) --dont-wait

# ============================
# Setup Git Auto-Deploy
# ============================
GITREPO="killerhash-stack/ubuntu-webserver-setup"
mkdir -p /var/www/html
chown -R $DEPLOYUSER:$DEPLOYUSER /var/www/html

cat > /home/$DEPLOYUSER/deploy.sh <<'EOL'
#!/bin/bash
cd /var/www/html
unset GIT_DIR
git pull origin main
EOL

chmod +x /home/$DEPLOYUSER/deploy.sh
chown $DEPLOYUSER:$DEPLOYUSER /home/$DEPLOYUSER/deploy.sh

# ============================
# ----------------------------
# Final Access Summary
# ----------------------------
echo ""
echo "🌐 Access your server:"
echo ""

# Webmin
if systemctl list-unit-files | grep -q "^webmin.service"; then
    echo " - Webmin: https://$INTERNAL_IP:10000"
    echo "   🔑 Use SSH tunnel if remote over ZeroTier:"
    echo "     ssh -L 10000:localhost:10000 $DEPLOYUSER@YOUR_SERVER_PUBLIC_IP_OR_ZEROTIER_IP"
    echo "     Then open https://localhost:10000 in your browser."
else
    echo " - Webmin: ⚠️ Not installed or service missing."
fi

# Netdata
if systemctl list-unit-files | grep -q "^netdata.service"; then
    echo ""
    echo " - Netdata: http://$INTERNAL_IP:19999"
    echo "   🔑 Use SSH tunnel if remote over ZeroTier:"
    echo "     ssh -L 19999:localhost:19999 $DEPLOYUSER@YOUR_SERVER_PUBLIC_IP_OR_ZEROTIER_IP"
    echo "     Then open http://localhost:19999 in your browser."
else
    echo " - Netdata: ⚠️ Not installed or service missing."
fi

# Nginx root
echo ""
echo " - Nginx Root: /var/www/html"

# Fail2Ban
echo " - Fail2Ban: systemctl status fail2ban"

# rkhunter
echo " - rkhunter scan: sudo rkhunter --check"

# Git auto-deploy
if [ -n "$GITREPO" ]; then
    echo " - Git auto-deploy: push to https://github.com/$GITREPO"
fi

# ModSecurity / WAF
echo ""
echo "🛡️ ModSecurity WAF is active with OWASP CRS rules"
echo "Check Nginx logs for blocked requests: sudo tail -f /var/log/nginx/modsec_audit.log"

# SSL
echo ""
echo "🔐 Certbot SSL certificates:"
certbot certificates || echo "  ⚠️ No certificates installed yet."

# Firewall
echo ""
echo "🛡 Firewall status:"
ufw status verbose

# SSH key info
echo ""
echo "🔑 SSH Key for deploy user ($DEPLOYUSER): /home/$DEPLOYUSER/.ssh/authorized_keys"

# Optional Nginx config test
echo ""
echo "📝 Optional: Test Nginx config before reload"
echo "    sudo nginx -t"

# SSL reminder
echo ""
echo "⚠️ Reminder: Update DNS (Cloudflare) to point your domain to this server for SSL to work."
echo ""
echo "✅ Setup complete!"
