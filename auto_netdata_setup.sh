#!/bin/bash
# =========================================
# Netdata Setup Script
# =========================================
#
# Version: 1.0.0
# Script written by Warith AL Maawali
#
# Discord channel: https://discord.gg/KEFErEx
# Twitter: http://twitter.com/warith2020
# Linkedin: http://www.linkedin.com/in/warith1977
# Website: https://www.digi77.com
# (c) 2024
#
# Description:
# This script sets up Netdata on a Debian-based system.
# It ensures root privileges, updates system packages, installs Netdata,
# configures Apache for proxying, and sets up basic HTTP authentication.
#
# For more information, visit: https://learn.netdata.cloud/docs/netdata-agent/installation/linux/
#
# This software is dual-licensed:
#
# Personal, non-commercial use: Apache License 2.0
# Commercial, corporate, or organizational use: Separate commercial license required.
# Contact me for licensing inquiries.
#
# Usage: ./net-data-setup.sh
#
# Usage Examples:
#   Run this script as root to set up Netdata:
#     ./net-data-setup.sh
# =========================================

# Global Variables
NETDATA_USER="xxx_your_username_xxx"
NETDATA_PASSWORD="xxx_your_password_xxx"
PORT="4430"
SERVER_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || curl -s ipecho.net/plain || hostname -I | awk '{print $1}')
NETDATA_PATH="/DYP1BYuftXbk0vgXErux" # User-defined variable for Netdata path
VHOST_CONF="/etc/apache2/sites-available/000-default.conf"

# Function to set up Netdata
function setup_netdata() {
  # Update package lists
  echo "===================="
  echo "Updating package lists..."
  echo "===================="
  sudo apt update -y

  # Install dependencies
  echo "===================="
  echo "Installing dependencies..."
  echo "===================="
  sudo apt install -y curl apache2-utils

  # Install Netdata using the official installer
  echo "===================="
  echo "Installing Netdata..."
  echo "===================="
  wget -O /tmp/netdata-kickstart.sh https://get.netdata.cloud/kickstart.sh && sh /tmp/netdata-kickstart.sh --disable-telemetry || {
    echo "===================="
    echo "Official installer failed, trying package manager..."
    echo "===================="
    sudo apt-get install netdata -y
  }

  # Dump Netdata configuration
  netdatacli dumpconfig >/etc/netdata/netdata.conf

  # Update package list and install Apache utilities if not installed
  echo "===================="
  echo "Updating package list and installing Apache utilities..."
  echo "===================="
  sudo apt update -y
  sudo apt install -y apache2 apache2-utils

  # Enable necessary Apache modules
  echo "===================="
  echo "Enabling necessary Apache modules for proxying..."
  echo "===================="
  sudo a2enmod proxy
  sudo a2enmod proxy_http
  sudo a2enmod auth_basic

  # Set up basic HTTP authentication
  echo "===================="
  echo "Setting up basic HTTP authentication for Netdata..."
  echo "===================="
  sudo htpasswd -bc /etc/apache2/.htpasswd "$NETDATA_USER" "$NETDATA_PASSWORD"

  # Create or edit the Apache virtual host configuration for Netdata
  echo "===================="
  echo "Configuring Apache to serve Netdata at $NETDATA_PATH on $SERVER_IP..."
  echo "===================="

  # Create temporary file with configuration
  TEMP_CONF=$(mktemp)
  cat >"$TEMP_CONF" <<EOL
<VirtualHost *:80>
    ServerName $SERVER_IP

    # Proxy configuration to serve Netdata at $NETDATA_PATH
    ProxyPreserveHost On
    ProxyRequests Off
    ProxyPass $NETDATA_PATH http://127.0.0.1:19999
    ProxyPassReverse $NETDATA_PATH http://127.0.0.1:19999

    # Basic authentication for Netdata
    <Location $NETDATA_PATH>
        AuthType Basic
        AuthName "Restricted Access"
        AuthUserFile /etc/apache2/.htpasswd
        Require valid-user
    </Location>

    # Other existing configuration settings for your website
    DocumentRoot /var/www/html
</VirtualHost>
EOL

  # Copy temp file to actual location with sudo
  sudo cp "$TEMP_CONF" "$VHOST_CONF"

  # Clean up temp file
  rm "$TEMP_CONF"

  # Restart Apache to apply changes
  echo "===================="
  echo "Restarting Apache to apply the new configuration..."
  echo "===================="
  sudo systemctl restart apache2

  # Configure Netdata to require HTTP authentication
  sudo tee -a /etc/netdata/netdata.conf >/dev/null <<EOF
[web]
    bind to = localhost:19999
EOF

  # Restart Netdata service to apply the changes
  echo "===================="
  echo "Restarting Netdata service to apply changes..."
  echo "===================="
  timeout 2 sudo systemctl restart netdata

  # Enable Netdata to start on boot
  echo "===================="
  echo "Enabling Netdata to start on boot..."
  echo "===================="
  timeout 2 sudo systemctl enable netdata

  # Check Netdata service status
  echo "===================="
  echo "Checking Netdata service status..."
  echo "===================="
  timeout 2 sudo systemctl status netdata

  # Display access information
  IP_ADDRESS=$(hostname -I | awk '{print $1}')
  echo "===================="
  echo "Installation complete. Access Netdata at: http://$IP_ADDRESS:$PORT with username: $NETDATA_USER"
  echo "===================="

  # Display access URLs for reference
  echo "===================="
  echo "You can access Netdata through Apache at: http://$IP_ADDRESS$NETDATA_PATH"
  echo "===================="
  echo "Direct Netdata access (if configured) at: http://$IP_ADDRESS:19999"
  echo "===================="
  echo "Your Apache htpasswd file is located at: /etc/apache2/.htpasswd"
  echo "===================="
  echo "Your Netdata htpasswd file is located at: /etc/netdata/netdata.htpasswd"
  echo "===================="

  # Display the private key needed for Netdata Cloud connection
  echo "===================="
  echo "Your Netdata Cloud private key is:"
  sudo cat /var/lib/netdata/netdata_random_session_id
  echo "===================="
  echo "You'll need this key to connect your node to Netdata Cloud"
  echo "===================="
}

# Execute the setup function
setup_netdata
