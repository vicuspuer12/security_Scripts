#!/bin/bash
# =========================================
# Let's Encrypt Setup Script
# =========================================
#
# Version: 1.0.0
# Author: Warith AL Maawali
#
# Contact:
# - Discord: https://discord.gg/KEFErEx
# - Twitter: http://twitter.com/warith2020
# - LinkedIn: http://www.linkedin.com/in/warith1977
# - Website: https://www.digi77.com
#
# Copyright (c) 2024 Warith AL Maawali
#
# Description:
# This script automates the setup and configuration of Let's Encrypt SSL certificates
# for Apache web servers on Kodachi VPS instances. It performs the following tasks:
# - Installs and configures Apache web server
# - Installs Certbot and its dependencies
# - Obtains and configures SSL certificates
# - Sets up automatic certificate renewal
# - Configures Apache virtual hosts
#
# License:
# Dual-licensed under:
# 1. Apache License 2.0 (personal, non-commercial use)
# 2. Commercial license (for corporate/organizational use)
# Contact author for commercial licensing details.
#
# Usage:
# sudo ./lets-encrypt-setup.sh
#
# Requirements:
# - Debian-based Linux distribution
# - Root/sudo privileges
# - Active internet connection
# - Domain name with DNS access
# - Apache web server
# =========================================

# Define script variables
DOMAIN="yourdomain.com"                                              # Domain name to secure
EMAIL="youremail@gmail.com"                                          # Contact email for Let's Encrypt
CLOUDFLARE_DNS="1.1.1.1"                                            # Primary DNS resolver
GOOGLE_DNS="8.8.8.8"                                                # Backup DNS resolver
CERTBOT_PATH="/usr/bin/certbot"                                     # Path to certbot executable
APACHE_CONFIG="/etc/apache2/sites-available/${DOMAIN}.conf"         # Apache vhost config location
RENEW_HOOK="/etc/letsencrypt/renewal-hooks/deploy/reload-apache.sh" # Renewal hook script path
CRON_JOB="/etc/cron.d/letsencrypt-renew"                            # Auto-renewal cron job path
CERT_PATH="/etc/letsencrypt/live/$DOMAIN"                           # SSL certificate storage path
VALIDATION_STRING=""                                                # DNS validation string

# Display current DNS TXT records for domain validation
echo "Current TXT records for _acme-challenge.$DOMAIN:"
# Try Cloudflare DNS first, fallback to Google DNS if it fails
dig +short -t TXT "_acme-challenge.$DOMAIN" @$CLOUDFLARE_DNS ||
  dig +short -t TXT "_acme-challenge.$DOMAIN" @$GOOGLE_DNS ||
  echo "No TXT records found"
echo "----------------------------------------"

# Function to verify and install Apache if needed
check_apache() {
  if ! [ -x "$(command -v apache2)" ]; then
    echo "Apache is not installed. Installing it now..."
    apt update
    apt install -y apache2
    systemctl enable apache2
    systemctl start apache2
  else
    echo "Apache is already installed."
  fi
}

# Function to install Certbot and its Apache plugin
install_certbot() {
  echo "Installing Certbot and dependencies..."
  apt update
  apt install -y certbot python3-certbot-apache
  if [ $? -eq 0 ]; then
    echo "Certbot successfully installed."
  else
    echo "Error installing Certbot. Please check your system configuration."
    exit 1
  fi
}

# Function to verify Certbot installation
check_certbot_installed() {
  if ! [ -x "$(command -v $CERTBOT_PATH)" ]; then
    echo "Certbot is not installed. Installing it now..."
    install_certbot
  else
    echo "Certbot is already installed."
  fi
}

# Function to configure Apache virtual host with SSL support
configure_apache() {
  # Check if SSL certificates exist
  if [ -d "$CERT_PATH" ] && [ -f "$CERT_PATH/fullchain.pem" ] && [ -f "$CERT_PATH/privkey.pem" ]; then
    # Configure HTTPS with SSL certificates
    echo "SSL certificates found, configuring Apache with HTTPS..."
    cat >"$APACHE_CONFIG" <<EOF
<VirtualHost *:80>
    ServerName $DOMAIN
    ServerAlias *.$DOMAIN
    DocumentRoot /var/www/html
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined

    # Redirect all HTTP traffic to HTTPS
    Redirect permanent / https://$DOMAIN/
</VirtualHost>

<VirtualHost *:443>
    ServerName $DOMAIN
    ServerAlias *.$DOMAIN
    DocumentRoot /var/www/html

    # SSL Configuration
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/$DOMAIN/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/$DOMAIN/privkey.pem

    # Logging Configuration
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF
    a2ensite "${DOMAIN}.conf"
    a2enmod ssl
  else
    # Configure HTTP-only virtual host
    echo "SSL certificates not found, configuring Apache for HTTP only..."
    cat >"$APACHE_CONFIG" <<EOF
<VirtualHost *:80>
    ServerName $DOMAIN
    ServerAlias *.$DOMAIN
    DocumentRoot /var/www/html
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF
    a2ensite "${DOMAIN}.conf"
  fi

  # Validate and reload Apache configuration
  if apachectl configtest; then
    systemctl reload apache2
    echo "Apache configuration updated successfully"
  else
    echo "Error in Apache configuration. Please check the syntax."
    exit 1
  fi
}

# Function to generate DNS validation string
generate_validation() {
  VALIDATION_STRING=$(openssl rand -hex 32)
  echo "Please add this DNS TXT record:"
  echo "Record Name: _acme-challenge.$DOMAIN"
  echo "Record Value: $VALIDATION_STRING"
}

# Function to verify DNS record propagation
verify_dns_record() {
  local attempt=1
  local max_attempts=12 # 2 minute timeout (12 attempts * 10 seconds)

  while [ $attempt -le $max_attempts ]; do
    # Check both Cloudflare and Google DNS for record propagation
    if dig +short -t TXT "_acme-challenge.$DOMAIN" @$CLOUDFLARE_DNS | grep -q "$VALIDATION_STRING" ||
      dig +short -t TXT "_acme-challenge.$DOMAIN" @$GOOGLE_DNS | grep -q "$VALIDATION_STRING"; then
      echo "DNS record verified successfully!"
      return 0
    fi
    echo "Attempt $attempt of $max_attempts: DNS record not found yet. Waiting 10 seconds..."
    echo "Found TXT record (Cloudflare): $(dig +short -t TXT "_acme-challenge.$DOMAIN" @$CLOUDFLARE_DNS)"
    echo "Found TXT record (Google): $(dig +short -t TXT "_acme-challenge.$DOMAIN" @$GOOGLE_DNS)"
    echo "Expected TXT record: $VALIDATION_STRING"
    sleep 10
    attempt=$((attempt + 1))
  done

  echo "Could not verify DNS record after $max_attempts attempts."
  return 1
}

# Function to obtain SSL certificate using DNS validation
obtain_certificate() {
  echo "Starting DNS validation process for $DOMAIN..."

  # Generate and verify DNS record
  generate_validation

  # Wait for user to add DNS record and verify
  while true; do
    read -p "Have you added the DNS TXT record? (yes/no): " response
    if [ "$response" = "yes" ]; then
      if verify_dns_record; then
        break
      fi
    elif [ "$response" = "no" ]; then
      echo "Please add the DNS record and try again."
    else
      echo "Please answer 'yes' or 'no'"
    fi
  done

  # Request certificate from Let's Encrypt
  echo "DNS verified! Running certbot to obtain certificate..."

  $CERTBOT_PATH certonly \
    --manual \
    --preferred-challenges dns-01 \
    --agree-tos \
    --email "$EMAIL" \
    --domains "$DOMAIN,*.${DOMAIN}" \
    --manual-public-ip-logging-ok \
    --force-interactive

  # Verify certificate creation and configure Apache
  if [ -d "$CERT_PATH" ]; then
    echo "Wildcard certificate successfully obtained."
    configure_apache
  else
    echo "Error obtaining certificate. Check logs for details."
    exit 1
  fi
}

# Function to configure automatic certificate renewal
setup_auto_renew() {
  echo "Setting up auto-renewal..."

  # Create renewal hook directory and script
  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  cat >"$RENEW_HOOK" <<EOF
#!/bin/bash
systemctl reload apache2
EOF
  chmod +x "$RENEW_HOOK"

  # Configure cron job for automatic renewal
  echo "0 3 * * * root $CERTBOT_PATH renew --deploy-hook $RENEW_HOOK" >$CRON_JOB
  chmod 644 $CRON_JOB
  echo "Auto-renewal configured."
}

# Main script execution
echo "Starting Let's Encrypt wildcard certificate setup for $DOMAIN..."
check_apache
check_certbot_installed
configure_apache
echo "Obtaining Let's Encrypt wildcard SSL certificate for $DOMAIN..."
echo "Saving debug log to /var/log/letsencrypt/letsencrypt.log"
echo "Requesting a certificate for $DOMAIN and *.$DOMAIN"
obtain_certificate
setup_auto_renew

# Display completion message and verify renewal configuration
echo "Setup complete! Your domain $DOMAIN and all subdomains are now secured with Let's Encrypt SSL."
echo "Wildcard certificate will auto-renew before expiration."

echo -e "\nVerifying auto-renewal configuration:"
if [ -f "$CRON_JOB" ]; then
  echo "Auto-renewal cron job is configured as follows:"
  cat "$CRON_JOB"
else
  echo "Warning: Auto-renewal cron job file not found at $CRON_JOB"
fi
