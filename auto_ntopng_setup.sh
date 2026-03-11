#!/bin/bash
# =========================================
# Ntopng Setup Script
# =========================================
#
# Version: 1.0.1
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
# This script automates the installation and configuration of Ntopng on Debian-based systems.
# It performs the following tasks:
# - Ensures root privileges
# - Detects the primary network interface
# - Updates system packages
# - Configures the Ntopng repository
# - Installs Ntopng and its dependencies
#
# License:
# Dual-licensed under:
# 1. Apache License 2.0 (personal, non-commercial use)
# 2. Commercial license (for corporate/organizational use)
# Contact author for commercial licensing details.
#
# Usage:
# sudo ./ntopng-setup.sh
#
# Requirements:
# - Debian-based Linux distribution
# - Root/sudo privileges
# - Active internet connection
# =========================================

# Global configuration variables with descriptive comments
NTOPNG_PORT="4400"                     # Web interface port (non-standard for security)
NTOPNG_CONF="/etc/ntopng/ntopng.conf"   # Main configuration file location
NTOPNG_START="/etc/ntopng/ntopng.start" # Startup configuration file location

# Main installation and configuration function
function install_ntopng() {
  # Network interface detection with progressive fallbacks
  # First try: Get default route interface
  INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

  # Second try: Find first active non-virtual interface
  if [ -z "$INTERFACE" ]; then
    INTERFACE=$(ip link show | grep -v "lo\|docker\|veth\|br-\|vir" |
      grep "UP" | head -n1 | awk -F: '{print $2}' | tr -d '[:space:]')
  fi

  # Exit if no valid interface found
  if [ -z "$INTERFACE" ]; then
    echo "===================="
    echo "ERROR: No valid network interface detected"
    echo "===================="
    exit 1
  fi

  # Detect and configure local networks
  # Excludes virtual interfaces and uses common private ranges as fallback
  LOCAL_NETWORKS=$(ip route | grep -v "default\|docker\|br-\|vir" |
    awk '{print $1}' | tr '\n' ',' | sed 's/,$//')

  # Fallback to common private network ranges if detection fails
  if [ -z "$LOCAL_NETWORKS" ]; then
    LOCAL_NETWORKS="192.168.0.0/24,10.0.0.0/8,172.16.0.0/12"
  fi

  # Clean existing installation if present
  if dpkg -l | grep -q "apt-ntop"; then
    echo "===================="
    echo "Removing existing Ntopng installation..."
    echo "===================="
    # Remove all related packages
    sudo apt-get purge -y apt-ntop
    sudo apt-get autoremove -y

    # Clean up repository keys
    echo "Removing existing repository keys..."
    sudo apt-key del "$(sudo apt-key list | grep -i ntop -B 1 | head -n 1 | awk '{print $9}')" 2>/dev/null || true
  fi

  # Repository configuration
  echo "===================="
  echo "Configuring package repositories..."
  echo "===================="
  if ! grep -q "contrib" /etc/apt/sources.list; then
    sudo sed -i '/^deb\|^deb-src/ s/$/ contrib/' /etc/apt/sources.list
  fi

  # Download and install repository package
  echo "Installing Ntopng repository..."
  if ! wget https://packages.ntop.org/apt/bookworm/all/apt-ntop.deb ||
    ! mv apt-ntop.deb /tmp/ ||
    ! sudo apt install /tmp/apt-ntop.deb; then
    echo "ERROR: Repository configuration failed"
    exit 1
  fi

  # Install Ntopng and dependencies
  echo "Installing Ntopng packages..."
  sudo apt-get clean all
  sudo apt-get update
  if ! sudo apt-get install -y pfring-dkms nprobe ntopng n2disk cento ntap; then
    echo "ERROR: Package installation failed"
    exit 1
  fi
  # Create the config directory
  echo "Creating Ntopng config directory..."
  sudo mkdir -p $(dirname $NTOPNG_CONF)

  # Configure main settings
  echo "Configuring Ntopng..."
  sudo tee $NTOPNG_CONF >/dev/null <<EOL
-i=$INTERFACE
-w=$NTOPNG_PORT
EOL

  # Configure network settings
  sudo tee $NTOPNG_START >/dev/null <<EOL
--local-networks "$LOCAL_NETWORKS"
--interface 1
EOL

  # Service management and validation
  echo "Enabling and starting services..."
  if ! sudo systemctl enable ntopng; then
    echo "ERROR: Failed to enable ntopng service"
    exit 1
  fi

  if ! sudo systemctl restart ntopng; then
    echo "ERROR: Failed to restart ntopng service"
    exit 1
  fi

  if ! sudo systemctl is-active ntopng >/dev/null 2>&1; then
    echo "ERROR: ntopng service is not active"
    exit 1
  fi

  # Installation completion message
  echo "===================="
  echo "Installation successful!"
  ss -tnlp | grep ":$NTOPNG_PORT"
  echo "Access Ntopng at: http://localhost:$NTOPNG_PORT"
  echo "Default credentials: admin/admin"
  echo "Please change the password after first login"
  echo "===================="

  # Cleanup
  rm -f /tmp/apt-ntop.deb
}

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: This script must be run as root"
  exit 1
fi

# Execute main installation function
install_ntopng
