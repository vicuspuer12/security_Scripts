#!/bin/bash
# =========================================
# Domain API Setup Script
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
# This script automates the management of DNS records for a specified domain using the Porkbun API.
# It includes functionalities to query existing DNS records, add new subdomains with random names,
# and delete subdomains with specific criteria.
#
# This software is dual-licensed:
#
# Personal, non-commercial use: Apache License 2.0
# Commercial, corporate, or organizational use: Separate commercial license required.
# Contact me for licensing inquiries.
#
# Usage: ./domain-api-setup.sh [domain]
#
# Usage Examples:
#   Run this script to manage DNS records for the default domain:
#     ./domain-api-setup.sh
#   Run this script to manage DNS records for a specified domain:
#     ./domain-api-setup.sh example.com
# ========================================= 


# Global variables for API authentication and domain configuration
API_KEY="pk1_3xxxxxxxxxxxxxxxx"
SECRET_API_KEY="sk1_xxxxxxxxxxxxxxxxxxxxxxxxxx"
DOMAIN="xxx.com"  # Default domain name
TYPE="A"  # DNS record type
TARGET_IP="34.27.202.113"  # Target IP address for subdomains
TTL="600"  # Time to live for DNS records
NUM_SUBDOMAINS=4  # Number of subdomains to add

# Check if the user provided a domain as an argument and override the default if so
if [ ! -z "$1" ]; then
  DOMAIN="$1"
fi

# Function to query DNS records for the specified domain
query_dns_records() {
  echo "Fetching DNS records for: $DOMAIN, Type: $TYPE"
  echo "------------------------------------------------"

  # Query Porkbun API for DNS records by domain and type
  RESPONSE=$(curl -s -X POST https://api.porkbun.com/api/json/v3/dns/retrieve/"$DOMAIN" \
    -H "Content-Type: application/json" \
    -d '{
      "apikey": "'"$API_KEY"'",
      "secretapikey": "'"$SECRET_API_KEY"'"
  }')

  # Check if the response was successful
  STATUS=$(echo "$RESPONSE" | jq -r '.status')

  if [[ "$STATUS" != "SUCCESS" ]]; then
    echo "Error retrieving DNS records: $RESPONSE"
    exit 1
  fi

  # Get the main domain IP address
  MAIN_IP=$(dig +short "$DOMAIN" | head -n 1)

  # List subdomains with their IDs and IP addresses, excluding those with the main domain IP and ensuring valid IP addresses
  echo "Subdomains with different and valid IP Addresses:"
  echo "-------------------------------------------------"
  echo "$RESPONSE" | jq -r --arg MAIN_IP "$MAIN_IP" '.records[] | select(.name != "'"$DOMAIN"'") | select(.content != $MAIN_IP) | select(.content | test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$")) | "\(.id) - \(.name) - \(.content)"'
}

# Function to add a specified number of subdomains with random names
add_subdomain() {
  for ((i = 0; i < NUM_SUBDOMAINS; i++)); do
    # Generate a random subdomain string
    RANDOM_SUBDOMAIN="$(openssl rand -hex 8)"

    # Create the subdomain via Porkbun API
    RESPONSE=$(curl -s -X POST https://api.porkbun.com/api/json/v3/dns/create/"$DOMAIN" \
      -H "Content-Type: application/json" \
      -d '{
        "apikey": "'"$API_KEY"'",
        "secretapikey": "'"$SECRET_API_KEY"'",
        "name": "'"$RANDOM_SUBDOMAIN"'",
        "type": "'"$TYPE"'",
        "content": "'"$TARGET_IP"'",
        "ttl": "'"$TTL"'"
    }')

    # Check if the subdomain was created successfully
    STATUS=$(echo "$RESPONSE" | jq -r '.status')

    if [[ "$STATUS" == "SUCCESS" ]]; then
      echo "Subdomain created successfully!"
      echo "Subdomain: $RANDOM_SUBDOMAIN.$DOMAIN -> $TARGET_IP"
    else
      echo "Error creating subdomain: $RESPONSE"
    fi
  done
}

# Function to delete subdomains with different and valid IP addresses
delete_subdomains() {
  echo "Deleting subdomains with different and valid IP Addresses:"
  echo "----------------------------------------------------------"

  # Query Porkbun API for DNS records by domain and type
  RESPONSE=$(curl -s -X POST https://api.porkbun.com/api/json/v3/dns/retrieve/"$DOMAIN" \
    -H "Content-Type: application/json" \
    -d '{
      "apikey": "'"$API_KEY"'",
      "secretapikey": "'"$SECRET_API_KEY"'"
  }')

  # Check if the response was successful
  STATUS=$(echo "$RESPONSE" | jq -r '.status')

  if [[ "$STATUS" != "SUCCESS" ]]; then
    echo "Error retrieving DNS records: $RESPONSE"
    exit 1
  fi

  # Get the main domain IP address
  MAIN_IP=$(dig +short "$DOMAIN" | head -n 1)

  # Delete subdomains with different and valid IP addresses
  echo "$RESPONSE" | jq -r --arg MAIN_IP "$MAIN_IP" '.records[] | select(.name != "'"$DOMAIN"'") | select(.content != $MAIN_IP) | select(.content | test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$")) | .id' | while read -r ID; do
    DELETE_RESPONSE=$(curl -s -X POST https://api.porkbun.com/api/json/v3/dns/delete/"$DOMAIN"/"$ID" \
      -H "Content-Type: application/json" \
      -d '{
        "apikey": "'"$API_KEY"'",
        "secretapikey": "'"$SECRET_API_KEY"'"
    }')

    DELETE_STATUS=$(echo "$DELETE_RESPONSE" | jq -r '.status')

    if [[ "$DELETE_STATUS" == "SUCCESS" ]]; then
      echo "Subdomain with ID $ID deleted successfully."
    else
      echo "Error deleting subdomain with ID $ID: $DELETE_RESPONSE"
    fi
  done
}

# Call the functions in sequence to manage DNS records
query_dns_records  # Initial query to list current DNS records
add_subdomain      # Add new subdomains
query_dns_records  # Query again to verify new subdomains
delete_subdomains  # Delete specific subdomains
query_dns_records  # Final query to confirm deletions

exit 0  # Exit the script successfully
