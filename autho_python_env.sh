#!/bin/bash

# =========================================
# Virtual Environment Setup Script
# =========================================
#
# Version: 1.1
# Script written by Warith Al Maawali
# (c) 2024
#
# This script creates and activates a Python
# virtual environment, and optionally installs
# specified pip packages.
#
# Usage: ./1.sh [pip_package1 pip_package2 ...]
# =========================================

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if python3-venv is installed
if ! dpkg -s python3-venv >/dev/null 2>&1; then
    echo "python3-venv is not installed. Installing now..."
    sudo apt update
    sudo apt install -y python3-venv
    if [ $? -ne 0 ]; then
        echo "Failed to install python3-venv. Please install it manually and run this script again."
        exit 1
    fi
fi

# Ask for the virtual environment name
read -p "Enter the name for the virtual environment (default: venv): " VENV_NAME
VENV_NAME=${VENV_NAME:-venv}

# Name of the virtual environment directory
VENV_DIR="$SCRIPT_DIR/$VENV_NAME"

# Create the virtual environment with correct permissions
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment in $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo "Failed to create virtual environment. Please check your Python installation and try again."
        exit 1
    fi
    # Set correct permissions and ownership for the virtual environment
    chmod -R u+w "$VENV_DIR"
    chown -R $(logname):$(logname) "$VENV_DIR"
    echo "Virtual environment created with correct permissions and ownership."
else
    echo "Virtual environment already exists in $VENV_DIR."
    # Ensure correct permissions and ownership for existing virtual environment
    chmod -R u+w "$VENV_DIR"
    chown -R $(logname):$(logname) "$VENV_DIR"
    echo "Permissions and ownership updated for existing virtual environment."
fi

# Activate the virtual environment
echo "Activating virtual environment..."
if [ -f "$VENV_DIR/bin/activate" ]; then
    source "$VENV_DIR/bin/activate"
else
    echo "Failed to find the activation script. The virtual environment may not have been created correctly."
    exit 1
fi

# Confirm activation
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "Virtual environment activated."
else
    echo "Failed to activate the virtual environment."
    exit 1
fi

# Switch to the virtual environment directory
echo "Switching to virtual environment directory..."
cd "$VENV_DIR"
echo "Current directory: $(pwd)"

# Install pip packages if provided as arguments
if [ $# -gt 0 ]; then
    echo "Installing pip packages: $@"
    pip install "$@"
fi

# Inform the user how to deactivate
echo "To deactivate the virtual environment, run: deactivate"

# Provide instructions to use pip
echo "You can now use pip within this virtual environment."

# Instructions to navigate to and activate the virtual environment
echo -e "\n### How to Navigate and Activate the Virtual Environment ###"
echo "1. Open a new terminal window or tab."
echo "2. Change to the virtual environment directory by running:"
echo "   cd $VENV_DIR"
echo "3. Once inside the directory, activate the virtual environment with:"
echo "   source bin/activate"
echo ""
echo "Alternatively, you can activate the virtual environment from any directory using:"
echo "   source $VENV_DIR/bin/activate"
echo "or directly:"
echo "   source /home/kodachi/Desktop/epy/venv/bin/activate"
echo "============================================================"
