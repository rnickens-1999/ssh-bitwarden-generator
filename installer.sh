#!/bin/bash
# SSH Key to Bitwarden Generator - Remote Installer
# Usage: curl https://raw.githubusercontent.com/YOUR_USERNAME/ssh-bitwarden-generator/main/install.sh | bash

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://raw.githubusercontent.com/rnickens-1999/ssh-bitwarden-generator/refs/heads/main"
SCRIPT_NAME="ssh_to_bitwarden.py"
INSTALL_DIR="$HOME/.local/bin"
SCRIPT_PATH="$INSTALL_DIR/$SCRIPT_NAME"

echo -e "${BLUE}SSH Key to Bitwarden Generator - Installer${NC}"
echo -e "${BLUE}=============================================${NC}"

# Check if Python3 is available
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python3 is not installed. Please install Python3 and try again.${NC}"
    exit 1
fi

# Check if we're running as root (we don't want to)
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}Warning: Running as root. Installing to /usr/local/bin instead.${NC}"
    INSTALL_DIR="/usr/local/bin"
    SCRIPT_PATH="$INSTALL_DIR/$SCRIPT_NAME"
fi

# Create install directory if it doesn't exist
echo -e "${BLUE}Creating install directory: $INSTALL_DIR${NC}"
mkdir -p "$INSTALL_DIR"

# Check if script already exists and prompt for upgrade
if [ -f "$SCRIPT_PATH" ]; then
    echo -e "${YELLOW}Existing installation found at: $SCRIPT_PATH${NC}"
    printf "Would you like to upgrade/reinstall? (y/N): "
    read -n 1 -r REPLY </dev/tty
    printf "\n"
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}Installation cancelled. Existing script unchanged.${NC}"
        exit 0
    fi
    echo -e "${BLUE}Upgrading existing installation...${NC}"
fi

# Download the Python script
echo -e "${BLUE}Downloading SSH to Bitwarden generator...${NC}"
if curl -fsSL "$REPO_URL/$SCRIPT_NAME" -o "$SCRIPT_PATH"; then
    if [ -f "$SCRIPT_PATH" ]; then
        echo -e "${GREEN}✓ Script downloaded/updated successfully${NC}"
    else
        echo -e "${RED}✗ Download appeared successful but file not found${NC}"
        exit 1
    fi
else
    echo -e "${RED}✗ Failed to download script from $REPO_URL/$SCRIPT_NAME${NC}"
    exit 1
fi

# Make the script executable
chmod +x "$SCRIPT_PATH"
echo -e "${GREEN}✓ Script made executable${NC}"

# Check if install directory is in PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo -e "${YELLOW}Warning: $INSTALL_DIR is not in your PATH${NC}"
    echo -e "${YELLOW}Add this line to your ~/.bashrc or ~/.zshrc:${NC}"
    echo -e "${YELLOW}export PATH=\"\$PATH:$INSTALL_DIR\"${NC}"
    echo ""
    echo -e "${BLUE}For now, you can run the script with:${NC}"
    echo -e "${GREEN}$SCRIPT_PATH${NC}"
else
    echo -e "${GREEN}✓ Install directory is in PATH${NC}"
    echo -e "${BLUE}You can now run the script with:${NC}"
    echo -e "${GREEN}$SCRIPT_NAME${NC}"
fi

echo ""
echo -e "${BLUE}Installation complete!${NC}"
echo ""
echo -e "${BLUE}Usage:${NC}"
if [[ ":$PATH:" == *":$INSTALL_DIR:"* ]]; then
    echo -e "  ${GREEN}$SCRIPT_NAME${NC}                 # Run interactively"
else
    echo -e "  ${GREEN}$SCRIPT_PATH${NC}                 # Run interactively"
fi
echo ""
echo -e "${BLUE}The script will:${NC}"
echo -e "  • Scan your ~/.ssh directory for SSH keys"
echo -e "  • Generate Bitwarden-ready secure note entries"
echo -e "  • Save formatted text files you can copy/paste into Bitwarden"
echo ""
echo -e "${BLUE}Happy key organizing! 🔐${NC}"

# Offer to run the script immediately
printf "\n"
printf "Would you like to run the script now? (y/N): "
read -n 1 -r REPLY </dev/tty
printf "\n"
if [[ $REPLY =~ ^[Yy]$ ]]; then
    printf "${BLUE}Running SSH to Bitwarden generator...${NC}\n"
    printf "\n"
    python3 "$SCRIPT_PATH"
fi