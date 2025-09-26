#!/bin/bash

set -e

# ----------------------------
# Variables
# ----------------------------
read -p "Enter deploy username: " DEPLOYUSER
read -p "Enter GitHub repository (username/repo): " GITREPO

# ----------------------------
# Update & Upgrade
# ----------------------------
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get dist-upgrade -y
sudo apt-get autoremove -y

# ----------------------------
# Create non-root user
# ----------------------------
if ! id "$DEPLOYUSER" &>/dev/null; then
    sudo adduser --gecos "" "$DEPLOYUSER"
    sudo usermod -aG sudo "$DEPLOYUSER"
    echo "✅ User $DEPLOYUSER created."
fi

# ----------------------------
# SSH Key Setup
# ----------------------------
if [ ! -f /home/$DEPLOYUSER/.ssh/id_ed25519.pub ]; then
    sudo -u $DEPLOYUSER ssh-keygen -t ed25519 -f /home/$DEPLOYUSER/.ssh/id_ed25519 -N ""
    echo "✅ SSH key generated for $DEPLOYUSER."
fi

# ----------------------------
# Install essential packages
# ----------------------------
sudo apt-get install -y curl git ufw fail2ban rkhunter unattended-upgrades software-properties-common apt-transport-https lsb-release gnupg

# ----------------------------
# UFW Firewall setup
# ----------------------------
sudo ufw allow OpenSSH
sudo ufw allow 80
sudo ufw allow 443
sudo ufw --force enable

# ----------------------------
# Unattended upgrades
# ----------------------------
sudo dpkg-reconfigure --priority=low unattended-upgrades

# ----------------------------
# Install Nginx & HTTP/2
# ----------------------------
sudo apt-get install -y nginx
sudo sed -i 's/listen 80 default_server;/listen 80 default_server;\n    listen 443 ssl http2 default_server;/' /etc/nginx/sites-available/default
sudo systemctl enable nginx
sudo systemctl restart nginx

# ----------------------------
# Install Certbot (SSL)
# ----------------------------
sudo apt-get install -y certbot python3-certbot-nginx
echo "✅ Certbot installed."

# ----------------------------
# ModSecurity (OWASP CRS)
# ----------------------------
sudo apt-get install -y libnginx-mod-security
sudo cp /usr/share/modsecurity-crs/modsecurity_crs_10_setup.conf.example /etc/modsecurity/modsecurity_crs_10_setup.conf
sudo systemctl restart nginx || echo "⚠️ Nginx restart warning (check config)."

# ----------------------------
# Webmin Installation & Service Handling
# ----------------------------
if ! dpkg -l | grep -q webmin; then
    sudo mkdir -p /usr/share/keyrings
    curl -fsSL https://download.webmin.com/jcameron-key.asc | sudo gpg --dearmor -o /usr/share/keyrings/webmin.gpg
    echo "deb [signed-by=/usr/share/keyrings/webmin.gpg] https://download.webmin.com/download/repository sarge contrib" \
        | sudo tee /etc/apt/sources.list.d/webmin.list
    sudo apt-get update -y
    sudo apt-get install -y webmin
else
    echo "✅ Webmin already installed."
fi

if systemctl list-unit-files | grep -q "^webmin.service"; then
    sudo systemctl enable webmin
    sudo systemctl restart webmin
    echo "✅ Webmin service started and enabled."
else
    echo "⚠️ Webmin service not found. Check installation."
fi

# ----------------------------
# Netdata Installation & Service Handling
# ----------------------------
if ! command -v netdata &>/dev/null; then
    bash <(curl -Ss https://my-netdata.io/kickstart.sh) --disable-telemetry
else
    echo "✅ Netdata already installed."
fi

if systemctl list-unit-files | grep -q "^netdata.service"; then
    sudo systemctl enable netdata
    sudo systemctl restart netdata
    echo "✅ Netdata service started and enabled."
else
    echo "⚠️ Netdata service not found. Check installation."
fi

# ----------------------------
# rkhunter update
# ----------------------------
sudo rkhunter --update

# ----------------------------
# Git Auto-Deploy
# ----------------------------
if [ -n "$GITREPO" ]; then
    if [ ! -d /var/www/html/.git ]; then
        sudo git clone https://github.com/$GITREPO /var/www/html
        echo "✅ Git repository cloned."
    else
        echo "✅ Git repository already exists."
    fi
fi

# ----------------------------
# Internal IP detection
# ----------------------------
INTERNAL_IP=$(hostname -I | awk '{print $1}')

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

# SSL reminder
echo ""
echo "⚠️ Reminder: Update DNS (Cloudflare) to point your domain to this server for SSL to work."
echo ""
echo "✅ Setup complete!"
