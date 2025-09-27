### Run the Setup Script

```bash
# Remove old script if exists
[ -f ~/setup-webserver.sh ] && rm ~/setup-webserver.sh

# Download and run latest version
curl -fsSL https://raw.githubusercontent.com/killerhash-stack/ubuntu-webserver-setup/main/setup-webserver.sh -o ~/setup-webserver.sh
chmod +x ~/setup-webserver.sh
sudo ~/setup-webserver.sh

This will check your server to make sure all services are running
curl -fsSL https://raw.githubusercontent.com/killerhash-stack/ubuntu-webserver-setup/main/server-health.sh -o server-health.sh
chmod +x server-health.sh
sudo ./server-health.sh
