#!/bin/bash

# ----------------------------
# Color definitions
# ----------------------------
GREEN="\e[32m"
YELLOW="\e[33m"
RED="\e[31m"
RESET="\e[0m"

echo -e "${GREEN}🛡️ Server Health Check - $(date)${RESET}"
echo "-----------------------------------"

# ----------------------------
# SSH & Deploy User
# ----------------------------
DEPLOYUSER=$(whoami)
echo -e "${YELLOW}🔹 SSH User: $DEPLOYUSER${RESET}"
[ -f ~/.ssh/id_ed25519.pub ] && echo -e "SSH key exists: ${GREEN}✅ Yes${RESET}" || echo -e "SSH key exists: ${RED}❌ No${RESET}"

# ----------------------------
# Nginx
# ----------------------------
echo -e "\n${YELLOW}🌐 Nginx Status:${RESET}"
systemctl is-active --quiet nginx && echo -e "Status: ${GREEN}✅ Running${RESET}" || echo -e "Status: ${RED}❌ Not Running${RESET}"
nginx -t &>/dev/null && echo -e "Config: ${GREEN}✅ OK${RESET}" || echo -e "Config: ${RED}❌ Error${RESET}"

# ----------------------------
# Firewall (UFW)
# ----------------------------
echo -e "\n${YELLOW}🔥 UFW Status:${RESET}"
ufw status verbose | grep -E 'Status|Open'

# ----------------------------
# SSL / Certbot
# ----------------------------
echo -e "\n${YELLOW}🔒 SSL / Certbot:${RESET}"
certbot certificates &>/dev/null && echo -e "Certificates: ${GREEN}✅ Present${RESET}" || echo -e "Certificates: ${RED}❌ Not Found${RESET}"

# ----------------------------
# Webmin
# ----------------------------
WEBMIN_PORT=10000
echo -e "\n${YELLOW}🖥️ Webmin:${RESET}"
systemctl is-active --quiet webmin && echo -e "Status: ${GREEN}✅ Running on port $WEBMIN_PORT${RESET}" || echo -e "Status: ${RED}❌ Not Running${RESET}"

# ----------------------------
# Netdata
# ----------------------------
NETDATA_PORT=19999
echo -e "\n${YELLOW}📊 Netdata:${RESET}"
systemctl is-active --quiet netdata && echo -e "Status: ${GREEN}✅ Running on port $NETDATA_PORT${RESET}" || echo -e "Status: ${RED}❌ Not Running${RESET}"

# ----------------------------
# Fail2Ban
# ----------------------------
echo -e "\n${YELLOW}🔐 Fail2Ban:${RESET}"
systemctl is-active --quiet fail2ban && echo -e "Status: ${GREEN}✅ Running${RESET}" || echo -e "Status: ${RED}❌ Not Running${RESET}"
fail2ban-client status &>/dev/null && echo -e "Status accessible: ${GREEN}✅${RESET}" || echo -e "Status accessible: ${RED}❌${RESET}"

# ----------------------------
# rkhunter
# ----------------------------
echo -e "\n${YELLOW}🕵️ Rootkit Check (rkhunter):${RESET}"
rkhunter --versioncheck &>/dev/null && echo -e "Version check: ${GREEN}✅ Up-to-date${RESET}" || echo -e "Version check: ${YELLOW}⚠️ Failed${RESET}"
rkhunter --check --sk &>/dev/null && echo -e "Rootkit scan: ${GREEN}✅ No obvious threats${RESET}" || echo -e "Rootkit scan: ${YELLOW}⚠️ Check logs${RESET}"

# ----------------------------
# ModSecurity / Nginx WAF
# ----------------------------
echo -e "\n${YELLOW}🛡️ ModSecurity WAF:${RESET}"
[ -f /etc/nginx/modsec/main.conf ] && echo -e "Config: ${GREEN}✅ Exists${RESET}" || echo -e "Config: ${RED}❌ Missing${RESET}"

# ----------------------------
# Nginx Root Path
# ----------------------------
echo -e "\n${YELLOW}📂 Nginx Root Path:${RESET} /var/www/html"
ls -la /var/www/html | head -n 10

# ----------------------------
# Git Auto-Deploy
# ----------------------------
GIT_DIR="/var/www/html/.git"
echo -e "\n${YELLOW}📦 Git Auto-Deploy:${RESET}"
[ -d "$GIT_DIR" ] && echo -e "Repository: ${GREEN}✅ Exists${RESET}" || echo -e "Repository: ${RED}❌ Not Configured${RESET}"

echo -e "\n${GREEN}✅ Server health check complete!${RESET}"
