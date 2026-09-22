#!/usr/bin/env bash
#
# Alien Hunter Installer & Service Configurator
# Installs system dependencies, creates global CLI symlink, and configures systemd.
#
# License: MIT
#

set -e

# Color palette
RED="\033[91m"
GREEN="\033[92m"
YELLOW="\033[93m"
CYAN="\033[96m"
BOLD="\033[1m"
RESET="\033[0m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_FILE="/etc/systemd/system/alien-hunter.service"
BIN_LINK="/usr/local/bin/alien-hunter"
PYTHON_BIN="$(command -v python3 || echo /usr/bin/python3)"

print_banner() {
    echo -e "${BOLD}${CYAN}"
    echo "========================================================================"
    echo "                 Alien Hunter: Setup and Installation                   "
    echo "========================================================================"
    echo -e "${RESET}"
}

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${YELLOW}[!] Root privileges required for installation.${RESET}"
        echo -e "${CYAN}[*] Re-running with sudo...${RESET}"
        exec sudo bash "$0" "$@"
    fi
}

uninstall() {
    echo -e "${YELLOW}[*] Uninstalling Alien Hunter service and CLI link...${RESET}"
    if command -v systemctl &>/dev/null; then
        if systemctl is-active --quiet alien-hunter.service 2>/dev/null; then
            echo "[-] Stopping alien-hunter service..."
            systemctl stop alien-hunter.service
        fi
        if systemctl is-enabled --quiet alien-hunter.service 2>/dev/null; then
            echo "[-] Disabling alien-hunter service..."
            systemctl disable alien-hunter.service
        fi
    fi
    if [[ -f "$SERVICE_FILE" ]]; then
        echo "[-] Removing $SERVICE_FILE..."
        rm -f "$SERVICE_FILE"
        if command -v systemctl &>/dev/null; then
            systemctl daemon-reload
        fi
    fi
    if [[ -L "$BIN_LINK" ]] || [[ -f "$BIN_LINK" ]]; then
        echo "[-] Removing $BIN_LINK..."
        rm -f "$BIN_LINK"
    fi
    echo -e "${GREEN}[+] Uninstallation complete.${RESET}"
    exit 0
}

check_dependencies() {
    echo -e "${CYAN}[1/4] Checking system dependencies...${RESET}"

    PYTHON_BIN="$(command -v python3 || echo /usr/bin/python3)"
    if ! command -v "$PYTHON_BIN" &>/dev/null; then
        echo -e "${RED}[-] Python 3 is not installed. Please install python3 first.${RESET}"
        exit 1
    fi
    echo -e "      ${GREEN}✔${RESET} Python 3 detected ($("$PYTHON_BIN" --version)) at $PYTHON_BIN"

    if ! command -v arp-scan &>/dev/null; then
        echo -e "      ${YELLOW}!${RESET} arp-scan not found. Attempting installation..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y arp-scan || true
        elif command -v dnf &>/dev/null; then
            dnf install -y arp-scan || true
        elif command -v pacman &>/dev/null; then
            pacman -S --noconfirm arp-scan || true
        elif command -v zypper &>/dev/null; then
            zypper install -y arp-scan || true
        elif command -v apk &>/dev/null; then
            apk add arp-scan || true
        fi

        if command -v arp-scan &>/dev/null; then
            echo -e "      ${GREEN}✔${RESET} arp-scan installed successfully."
        else
            echo -e "      ${CYAN}ℹ${RESET} arp-scan not installed. Alien Hunter will use standard-library fallbacks (Layer-2 raw sockets & kernel neighbor tables)."
        fi
    else
        echo -e "      ${GREEN}✔${RESET} arp-scan detected."
    fi
}

setup_configs() {
    echo -e "${CYAN}[2/4] Setting up configuration templates...${RESET}"

    # Initialize known_devices.json if not present
    if [[ ! -f "$SCRIPT_DIR/known_devices.json" ]]; then
        if [[ -f "$SCRIPT_DIR/known_devices.json.example" ]]; then
            cp "$SCRIPT_DIR/known_devices.json.example" "$SCRIPT_DIR/known_devices.json"
            echo -e "      ${GREEN}✔${RESET} Created known_devices.json from template."
        fi
    else
        echo -e "      ${GREEN}✔${RESET} Preserving existing known_devices.json."
    fi

    # Initialize config.json if not present
    if [[ ! -f "$SCRIPT_DIR/config.json" ]]; then
        if [[ -f "$SCRIPT_DIR/config.json.example" ]]; then
            cp "$SCRIPT_DIR/config.json.example" "$SCRIPT_DIR/config.json"
            echo -e "      ${GREEN}✔${RESET} Created config.json from template."
        fi
    else
        echo -e "      ${GREEN}✔${RESET} Preserving existing config.json."
    fi

    # Enforce secure file permissions on sensitive config and inventory files
    chmod 600 "$SCRIPT_DIR/config.json" 2>/dev/null || true
    chmod 600 "$SCRIPT_DIR/known_devices.json" 2>/dev/null || true
}

setup_cli_symlink() {
    echo -e "${CYAN}[3/4] Creating global CLI symlink...${RESET}"
    chmod +x "$SCRIPT_DIR/alien_hunter.py"
    ln -sf "$SCRIPT_DIR/alien_hunter.py" "$BIN_LINK"
    echo -e "      ${GREEN}✔${RESET} Linked $BIN_LINK -> $SCRIPT_DIR/alien_hunter.py"
}

setup_systemd_service() {
    echo -e "${CYAN}[4/4] Configuring background service...${RESET}"

    if ! command -v systemctl &>/dev/null || ! [ -d /run/systemd/system ]; then
        echo -e "      ${YELLOW}!${RESET} systemd init system not detected on this machine."
        echo -e "      ${CYAN}ℹ${RESET} Skipping systemd service configuration."
        return 0
    fi

    cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=Alien Hunter Network Sentinel Daemon
Documentation=https://github.com/jekyll86/alien-hunter
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$SCRIPT_DIR
Environment=PYTHONUNBUFFERED=1
ExecStart=$PYTHON_BIN $SCRIPT_DIR/alien_hunter.py --watch --interval 300
Restart=always
RestartSec=15
StandardOutput=journal
StandardError=journal
SyslogIdentifier=alien-hunter

[Install]
WantedBy=multi-user.target
EOF

    echo -e "      ${GREEN}✔${RESET} Generated $SERVICE_FILE pointing to $SCRIPT_DIR"
    systemctl daemon-reload
}

main() {
    if [[ "$1" == "--uninstall" ]]; then
        check_root "$@"
        uninstall
    fi

    print_banner
    check_root "$@"

    echo -e "Target directory: ${BOLD}$SCRIPT_DIR${RESET}\n"

    check_dependencies
    setup_configs
    setup_cli_symlink
    setup_systemd_service

    echo -e "\n${BOLD}${GREEN}========================================================================${RESET}"
    echo -e "${BOLD}${GREEN}                        Installation Complete                           ${RESET}"
    echo -e "${BOLD}${GREEN}========================================================================${RESET}\n"

    echo -e "You can now run Alien Hunter from anywhere in your terminal:"
    echo -e "  ${CYAN}sudo alien-hunter${RESET}            # Run manual scan"
    echo -e "  ${CYAN}sudo alien-hunter --deep${RESET}     # Run deep scan"
    echo -e "  ${CYAN}sudo alien-hunter --whitelist${RESET}# Interactive whitelisting\n"

    if command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        echo -e "To start the 24/7 background sentinel daemon now:"
        echo -e "  ${BOLD}sudo systemctl enable --now alien-hunter.service${RESET}\n"
        echo -e "To view live streaming intrusion logs:"
        echo -e "  ${BOLD}journalctl -u alien-hunter -f${RESET}\n"
    else
        echo -e "To run Alien Hunter as a background daemon (non-systemd):"
        echo -e "  ${BOLD}nohup sudo $PYTHON_BIN $SCRIPT_DIR/alien_hunter.py --watch --interval 300 > /var/log/alien-hunter.log 2>&1 &${RESET}\n"
    fi
}

main "$@"
