#!/bin/bash

# RSS Feed Tester Script
# ================================
#
# Author: Warith Al Maawali
# Copyright (c) 2025 Warith Al Maawali
# License: See /home/kodachi/LICENSE
#
# Version: 1.0.0
# Last updated: 2025-03-23
#
# Description:
# This script tests the availability and content of various cybersecurity
# RSS feeds. It fetches each feed, verifies its accessibility, and extracts
# the latest articles. The script provides colored output for better readability
# and saves detailed results to a log file.
#
# Usage:
# ./rss-tester.sh
#
# Output Information:
# - Feed accessibility status (OK/FAILED)
# - Latest 5 articles from each feed
# - Processing time for each feed
# - Total script execution time
#
# Dependencies:
# - curl: For fetching RSS feeds
# - bc: For time calculations
#
# Return Values:
# The script creates a timestamped log file with test results
# and returns 0 on success, non-zero on failure.
#
# Examples:
# ./rss-tester.sh    # Test all configured RSS feeds
#
# Links:
# - Website: https://www.digi77.com
# - GitHub: https://github.com/WMAL
# - Discord: https://discord.gg/KEFErEx
# - LinkedIn: https://www.linkedin.com/in/warith1977
# - X (Twitter): https://x.com/warith2020

# Start timing the entire script execution
SCRIPT_START=$(date +%s.%N)

# Array of RSS feeds to test
RSS_FEEDS=(
  "https://threatpost.com/feed/"
  "https://www.darkreading.com/rss.xml"
  "https://www.infosecurity-magazine.com/rss/news/"
  "https://www.cyberscoop.com/feed/"
  "https://www.securitymagazine.com/rss/15"
  "https://www.helpnetsecurity.com/feed/"
  "https://www.computerweekly.com/rss/All-Computer-Weekly-content.xml"
  "https://www.bleepingcomputer.com/feed/"
  "https://www.securityaffairs.co/wordpress/feed"
  "https://www.cybersecurity-insiders.com/feed/"
  "https://www.hackread.com/feed/"
)

# ANSI color codes for better readability
GREEN='\033[0;32m'  # Success messages
RED='\033[0;31m'    # Error messages
BLUE='\033[0;34m'   # Information messages
YELLOW='\033[0;33m' # Feed content and warnings
NC='\033[0m'        # No Color (reset)

echo -e "${BLUE}Testing RSS feeds...${NC}"
echo -e "${BLUE}====================${NC}"

# Check for required dependencies
if ! command -v curl >/dev/null 2>&1; then
  echo -e "${RED}Error: curl is required but not installed.${NC}"
  exit 1
fi

if ! command -v bc >/dev/null 2>&1; then
  echo -e "${RED}Warning: bc is required for timing calculations but not installed.${NC}"
  echo -e "${RED}Timing information will not be accurate.${NC}"
fi

# Create results directory if it doesn't exist
mkdir -p rss_test_results

# Get current timestamp for the log file name
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULTS_FILE="rss_test_results/feed_test_${TIMESTAMP}.log"

# Function to test and parse feed
test_feed() {
  local feed=$1
  local feed_start=$(date +%s.%N)
  local temp_file=$(mktemp)

  echo -e "Testing: ${YELLOW}$feed${NC}"

  # Use timeout to prevent hanging on unresponsive feeds
  curl -s -L --connect-timeout 10 --max-time 30 -o "$temp_file" "$feed" 2>/dev/null
  local curl_status=$?
  local http_code=0

  # Set HTTP code based on file existence
  if [ -s "$temp_file" ]; then
    http_code=200
  else
    http_code=0
  fi

  # Handle connection failures
  if [[ $curl_status -ne 0 ]]; then
    echo -e "${RED}[ERROR] Connection failed for $feed (curl status: $curl_status)${NC}" | tee -a "$RESULTS_FILE"
    rm -f "$temp_file"
    return
  fi

  # Process successful responses
  if [ $http_code -eq 200 ] && [ -s "$temp_file" ]; then
    echo -e "${GREEN}[OK] $feed${NC}" | tee -a "$RESULTS_FILE"
    echo -e "${BLUE}Latest 5 items:${NC}" | tee -a "$RESULTS_FILE"

    # Simple approach - extract title tags
    grep -o "<title>.*</title>" "$temp_file" |
      sed 's/<title>//g; s/<\/title>//g' |
      sed 's/^[ \t]*//;s/[ \t]*$//' |
      head -n 6 | tail -n 5 |
      while read -r title; do
        echo -e "${YELLOW}- $title${NC}" | tee -a "$RESULTS_FILE"
      done

    # If no titles found with simple approach, try more methods
    if [ $(grep -c "<title" "$temp_file") -eq 0 ]; then
      echo -e "${YELLOW}No standard titles found, trying alternative parsing...${NC}" | tee -a "$RESULTS_FILE"

      # Try to detect feed type and extract accordingly
      if grep -q "<entry" "$temp_file"; then
        # Atom feed format
        grep -o "<entry.*</entry>" "$temp_file" |
          grep -o "<title.*</title>" |
          sed 's/<title[^>]*>//g; s/<\/title>//g' |
          head -n 5 |
          while read -r title; do
            echo -e "${YELLOW}- $title${NC}" | tee -a "$RESULTS_FILE"
          done
      elif grep -q "<item" "$temp_file"; then
        # RSS feed format
        grep -o "<item.*</item>" "$temp_file" |
          grep -o "<title.*</title>" |
          sed 's/<title[^>]*>//g; s/<\/title>//g' |
          head -n 5 |
          while read -r title; do
            echo -e "${YELLOW}- $title${NC}" | tee -a "$RESULTS_FILE"
          done
      fi
    fi

    # Calculate and display feed processing time
    if command -v bc >/dev/null 2>&1; then
      local feed_end=$(date +%s.%N)
      local feed_time=$(echo "$feed_end - $feed_start" | bc)
      echo -e "${BLUE}[Time] Feed processed in ${feed_time} seconds${NC}" | tee -a "$RESULTS_FILE"
    fi
    echo "" | tee -a "$RESULTS_FILE"
  else
    # Handle failed responses
    echo -e "${RED}[FAILED] $feed (HTTP Code: $http_code, File size: $(wc -c <"$temp_file") bytes)${NC}" | tee -a "$RESULTS_FILE"
    # Save first few lines of the response for debugging
    echo -e "${RED}Response preview:${NC}" | tee -a "$RESULTS_FILE"
    head -n 10 "$temp_file" | tee -a "$RESULTS_FILE"
  fi

  # Cleanup temporary file
  rm -f "$temp_file"
}

# Write header to results file
echo "RSS Feed Test Results - $(date)" >"$RESULTS_FILE"
echo "=================================" >>"$RESULTS_FILE"

# Run feeds sequentially for reliability
echo -e "${BLUE}Processing feeds sequentially...${NC}"
for feed in "${RSS_FEEDS[@]}"; do
  test_feed "$feed"
done

# Calculate total script execution time
if command -v bc >/dev/null 2>&1; then
  SCRIPT_END=$(date +%s.%N)
  TOTAL_TIME=$(echo "$SCRIPT_END - $SCRIPT_START" | bc)
  echo -e "\n${GREEN}Test completed. Results saved to: $RESULTS_FILE${NC}"
  echo -e "${BLUE}Total execution time: ${TOTAL_TIME} seconds${NC}" | tee -a "$RESULTS_FILE"
else
  echo -e "\n${GREEN}Test completed. Results saved to: $RESULTS_FILE${NC}"
  echo -e "${BLUE}Total execution time: Not available (bc command missing)${NC}" | tee -a "$RESULTS_FILE"
fi
