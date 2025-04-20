#!/bin/bash
echo " 
      __      ___         _______    __    __       __        ________  __    __   __     _______  ___       ________   
     /\"\\    |\"  |       |   __ \"\\  /\" |  | \"\\     /\"\\      /\"       )/\" |  | \"\\ |\" \\   /\"     \"||\"  |     |\"      \"\\  
    /    \\   ||  |       (. |__) :)(:  (__)  :)   /    \\    (:   \\___/(:  (__)  :)||  | (: ______)||  |     (.  ___  :) 
   /' /\\  \\  |:  |       |:  ____/  \\/      \\/   /' /\\  \\    \\___  \\   \\/      \\/ |:  |  \\/    |  |:  |     |: \\   ) || 
  //  __'  \\  \\  |___    (|  /      //  __  \\\\  //  __'  \\    __/  \\\\  //  __  \\\\ |.  |  // ___)_  \\  |___  (| (___\\ || 
 /   /  \\\\  \\( \\_|:  \\  /|__/ \\    (:  (  )  :)/   /  \\\\  \\  /\" \\   :)(:  (  )  :)/\\  |\\(:      \"|( \\_|:  \\ |:       :) 
(___/    \\___)\\_______)(_______)    \\__|  |__/(___/    \\___)(_______/  \\__|  |__/(__\\_|_)\\_______) \\_______)(________/  
"


# Main menu
while true; do
    echo "========================================="
    echo "AlphaShield: Enhance Robotness of Linux Server"
    echo "========================================="
    echo "1. System Information"
    echo "2. Perform Security Audit"
    echo "3. Configure Server "
    echo "4. Setup Honeypot"
    echo "5. Exit"
    echo "========================================="
    read -p "Choose an option [1-5]: " choice

    case $choice in
       1)
            echo "System Information"
            # Begin audit.sh content
            #!/bin/bash
#sokdr


echo "###############################################"
echo "Welcome to security audit of your Linux machine:"
echo "###############################################"
echo
echo "Script will automatically gather the required info:"
echo "The checklist can help you in the process of hardening your system:"
echo "Note: it has been tested for Debian Linux Distro:"
echo
sleep 3
echo

# Prompt
while true; do
    read -p "Would you like to save the output? [Y/N] " output
    case "${output^^}" in
        Y)
            read -p "Please enter the path to save the output (e.g., /path_to_save/LinuxAudit.txt): " path
            echo 
            echo "File will be saved to LinuxAudit.txt"
            break
            ;;
        N)
            echo "OK, not saving moving on."
            break
            ;;
        *)
            echo "Invalid input. Please enter Y or N."
            ;;
    esac
done

echo
echo "OK... $HOSTNAME ...let's continue, please wait for it to finish:"
echo
sleep 3
echo
echo "Script Starts ;)"
START=$(date +%s)
echo

# Function to perform audit and write to file
perform_audit() {
    echo
    echo -e "\e[0;33m 1. Linux Kernel Information////// \e[0m"
    echo
    uname -a
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 2. Current User and ID information////// \e[0m"
    echo
    whoami
    echo
    id
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 3.  Linux Distribution Information///// \e[0m"
    echo
    lsb_release -a
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 4. List Current Logged In Users///// \e[0m"
    echo
    w
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 5. $HOSTNAME Uptime Information///// \e[0m"
    echo
    uptime
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 6. Running Services///// \e[0m"
    echo
    service --status-all |grep "+"
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 7. Active Internet Connections and Open Ports///// \e[0m"
    echo
    netstat -natp
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 8. Check Available Space///// \e[0m"
    echo
    df -h
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 9. Check Memory///// \e[0m"
    echo
    free -h
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 10. History (Commands)///// \e[0m"
    echo
    history
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 11. Network Interfaces///// \e[0m"
    echo
    ifconfig -a
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 12. IPtable Information///// \e[0m"
    echo
    iptables -L -n -v
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 13. Check Running Processes///// \e[0m"
    echo
    ps -a
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 14. Check SSH Configuration///// \e[0m"
    echo
    cat /etc/ssh/sshd_config
    echo
    echo "###############################################"
    echo -e "\e[0;33m 15. List All Packages Installed///// \e[0m"
    apt-cache pkgnames
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 16. Network Parameters///// \e[0m"
    echo
    cat /etc/sysctl.conf
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 17. Password Policies///// \e[0m"
    echo
    cat /etc/pam.d/common-password
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 18. Check your Source List File///// \e[0m"
    echo
    cat /etc/apt/sources.list
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 19. Check for Broken Dependencies///// \e[0m"
    echo
    apt-get check
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 20. MOTD Banner Message///// \e[0m"
    echo
    cat /etc/motd
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 21. List User Names///// \e[0m"
    echo
    cut -d: -f1 /etc/passwd
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 22. Check for Null Passwords///// \e[0m"
    echo
    users="$(cut -d: -f 1 /etc/passwd)"
    for x in $users
    do
    passwd -S $x |grep "NP"
    done
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 23. IP Routing Table///// \e[0m"
    echo
    route
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 24. Kernel Messages///// \e[0m"
    echo
    dmesg
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 25. Check Upgradable Packages///// \e[0m"
    echo
    apt list --upgradeable
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 26. CPU/System Information///// \e[0m"
    echo
    cat /proc/cpuinfo
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 27. TCP wrappers///// \e[0m"
    echo
    cat /etc/hosts.allow
    echo "///////////////////////////////////////"
    echo
    cat /etc/hosts.deny
    echo
    echo "###############################################"
    echo
    echo -e "\e[0;33m 28. Failed login attempts///// \e[0m"
    echo
    grep --color "failure" /var/log/auth.log
    echo
    echo "###############################################"
    echo

}


if [[ "${output^^}" == "Y" ]]; then
    perform_audit > "LinuxAudit.txt"
else
    perform_audit
fi

echo
echo "###############################################"
echo
END=$(date +%s)
DIFF=$(( END - START ))
echo "Script completed in $DIFF seconds."
echo
echo "Executed on:"
date
echo
            # End audit.sh content
            echo "Audit process completed."
            ;;
        2)
            echo "Running Audit..."
            #!/usr/bin/env bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
GRAY='\033[0;90m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Get current timestamp for the report filename
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="vps-audit-report-${TIMESTAMP}.txt"

print_header() {
    local header="$1"
    echo -e "\n${BLUE}${BOLD}$header${NC}"
    echo -e "\n$header" >> "$REPORT_FILE"
    echo "================================" >> "$REPORT_FILE"
}

print_info() {
    local label="$1"
    local value="$2"
    echo -e "${BOLD}$label:${NC} $value"
    echo "$label: $value" >> "$REPORT_FILE"
}

# Start the audit
echo -e "${BLUE}${BOLD}AlphaShield Security Audit Tool${NC}"
echo -e "${GRAY}Starting audit at $(date)${NC}\n"

echo "AlphaShield Security Audit Tool" > "$REPORT_FILE"
echo "Starting audit at $(date)" >> "$REPORT_FILE"
echo "================================" >> "$REPORT_FILE"

# System Information Section
print_header "System Information"

# Get system information
OS_INFO=$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
KERNEL_VERSION=$(uname -r)
HOSTNAME=$HOSTNAME
UPTIME=$(uptime -p)
UPTIME_SINCE=$(uptime -s)
CPU_INFO=$(lscpu | grep "Model name" | cut -d':' -f2 | xargs)
CPU_CORES=$(nproc)
TOTAL_MEM=$(free -h | awk '/^Mem:/ {print $2}')
TOTAL_DISK=$(df -h / | awk 'NR==2 {print $2}')
PUBLIC_IP=$(curl -s https://api.ipify.org)
LOAD_AVERAGE=$(uptime | awk -F'load average:' '{print $2}' | xargs)

# Print system information
print_info "Hostname" "$HOSTNAME"
print_info "Operating System" "$OS_INFO"
print_info "Kernel Version" "$KERNEL_VERSION"
print_info "Uptime" "$UPTIME (since $UPTIME_SINCE)"
print_info "CPU Model" "$CPU_INFO"
print_info "CPU Cores" "$CPU_CORES"
print_info "Total Memory" "$TOTAL_MEM"
print_info "Total Disk Space" "$TOTAL_DISK"
print_info "Public IP" "$PUBLIC_IP"
print_info "Load Average" "$LOAD_AVERAGE"

echo "" >> "$REPORT_FILE"

# Security Audit Section
print_header "Security Audit Results"

# Function to check and report with three states
check_security() {
    local test_name="$1"
    local status="$2"
    local message="$3"
    
    case $status in
        "PASS")
            echo -e "${GREEN}[PASS]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[PASS] $test_name - $message" >> "$REPORT_FILE"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[WARN] $test_name - $message" >> "$REPORT_FILE"
            ;;
        "FAIL")
            echo -e "${RED}[FAIL]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[FAIL] $test_name - $message" >> "$REPORT_FILE"
            ;;
    esac
    echo "" >> "$REPORT_FILE"
}

# Check system uptime
UPTIME=$(uptime -p)
UPTIME_SINCE=$(uptime -s)
echo -e "\nSystem Uptime Information:" >> "$REPORT_FILE"
echo "Current uptime: $UPTIME" >> "$REPORT_FILE"
echo "System up since: $UPTIME_SINCE" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo -e "System Uptime: $UPTIME (since $UPTIME_SINCE)"

# Check if system requires restart
if [ -f /var/run/reboot-required ]; then
    check_security "System Restart" "WARN" "System requires a restart to apply updates"
else
    check_security "System Restart" "PASS" "No restart required"
fi

# Check SSH config overrides
SSH_CONFIG_OVERRIDES=$(grep "^Include" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')

# Check SSH root login (handle both main config and overrides if they exist)
if [ -n "$SSH_CONFIG_OVERRIDES" ] && [ -d "$(dirname "$SSH_CONFIG_OVERRIDES")" ]; then
    SSH_ROOT=$(grep "^PermitRootLogin" $SSH_CONFIG_OVERRIDES /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
else
    SSH_ROOT=$(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
fi
if [ -z "$SSH_ROOT" ]; then
    SSH_ROOT="prohibit-password"
fi
if [ "$SSH_ROOT" = "no" ]; then
    check_security "SSH Root Login" "PASS" "Root login is properly disabled in SSH configuration"
else
    check_security "SSH Root Login" "FAIL" "Root login is currently allowed - this is a security risk. Disable it in /etc/ssh/sshd_config"
fi

# Check SSH password authentication (handle both main config and overrides if they exist)
if [ -n "$SSH_CONFIG_OVERRIDES" ] && [ -d "$(dirname "$SSH_CONFIG_OVERRIDES")" ]; then
    SSH_PASSWORD=$(grep "^PasswordAuthentication" $SSH_CONFIG_OVERRIDES /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
else
    SSH_PASSWORD=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
fi
if [ -z "$SSH_PASSWORD" ]; then
    SSH_PASSWORD="yes"
fi
if [ "$SSH_PASSWORD" = "no" ]; then
    check_security "SSH Password Auth" "PASS" "Password authentication is disabled, key-based auth only"
else
    check_security "SSH Password Auth" "FAIL" "Password authentication is enabled - consider using key-based authentication only"
fi


# Check for default/unsecure SSH ports 
UNPRIVILEGED_PORT_START=$(sysctl -n net.ipv4.ip_unprivileged_port_start)
SSH_PORT=""
if [ -n "$SSH_CONFIG_OVERRIDES" ] && [ -d "$(dirname "$SSH_CONFIG_OVERRIDES")" ]; then
    SSH_PORT=$(grep "^Port" $SSH_CONFIG_OVERRIDES /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
else
    SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
fi
if [ -z "$SSH_PORT" ]; then
    SSH_PORT="22"
fi

if [ "$SSH_PORT" = "22" ]; then
    check_security "SSH Port" "WARN" "Using default port 22 - consider changing to a non-standard port for security by obscurity"
elif [ "$SSH_PORT" -ge "$UNPRIVILEGED_PORT_START" ]; then
    check_security "SSH Port" "FAIL" "Using unprivileged port $SSH_PORT -  use a port below $UNPRIVILEGED_PORT_START for better security"
else
    check_security "SSH Port" "PASS" "Using non-default port $SSH_PORT which helps prevent automated attacks"
fi

# Check Firewall Status
check_firewall_status() {
    if command -v ufw >/dev/null 2>&1; then
        if ufw status | grep -qw "active"; then
            check_security "Firewall Status (UFW)" "PASS" "UFW firewall is active and protecting your system"
        else
            check_security "Firewall Status (UFW)" "FAIL" "UFW firewall is not active - your system is exposed to network attacks"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state 2>/dev/null | grep -q "running"; then
            check_security "Firewall Status (firewalld)" "PASS" "Firewalld is active and protecting your system"
        else
            check_security "Firewall Status (firewalld)" "FAIL" "Firewalld is not active - your system is exposed to network attacks"
        fi
    elif command -v iptables >/dev/null 2>&1; then
        if iptables -L -n | grep -q "Chain INPUT"; then
            check_security "Firewall Status (iptables)" "PASS" "iptables rules are active and protecting your system"
        else
            check_security "Firewall Status (iptables)" "FAIL" "No active iptables rules found - your system may be exposed"
        fi
    elif command -v nft >/dev/null 2>&1; then
        if nft list ruleset | grep -q "table"; then
            check_security "Firewall Status (nftables)" "PASS" "nftables rules are active and protecting your system"
        else
            check_security "Firewall Status (nftables)" "FAIL" "No active nftables rules found - your system may be exposed"
        fi
    else
        check_security "Firewall Status" "FAIL" "No recognized firewall tool is installed on this system"
    fi
}

# Firewall check
check_firewall_status

# Check for unattended upgrades
if dpkg -l | grep -q "unattended-upgrades"; then
    check_security "Unattended Upgrades" "PASS" "Automatic security updates are configured"
else
    check_security "Unattended Upgrades" "FAIL" "Automatic security updates are not configured - system may miss critical updates"
fi

# Check Intrusion Prevention Systems (Fail2ban or CrowdSec)
IPS_INSTALLED=0
IPS_ACTIVE=0

if dpkg -l | grep -q "fail2ban"; then
    IPS_INSTALLED=1
    systemctl is-active fail2ban >/dev/null 2>&1 && IPS_ACTIVE=1
fi

if dpkg -l | grep -q "crowdsec"; then
    IPS_INSTALLED=1
    systemctl is-active crowdsec >/dev/null 2>&1 && IPS_ACTIVE=1
fi

case "$IPS_INSTALLED$IPS_ACTIVE" in
    "11") check_security "Intrusion Prevention" "PASS" "Fail2ban or CrowdSec is installed and running" ;;
    "10") check_security "Intrusion Prevention" "WARN" "Fail2ban or CrowdSec is installed but not running" ;;
    *)    check_security "Intrusion Prevention" "FAIL" "No intrusion prevention system (Fail2ban or CrowdSec) is installed" ;;
esac

# Check failed login attempts
LOG_FILE="/var/log/auth.log"

if [ -f "$LOG_FILE" ]; then
    FAILED_LOGINS=$(grep -c "Failed password" "$LOG_FILE" 2>/dev/null || echo 0)
else
    FAILED_LOGINS=0
    echo "Warning: Log file $LOG_FILE not found or unreadable. Assuming 0 failed login attempts."
fi

# Ensure FAILED_LOGINS is numeric and strip whitespace
FAILED_LOGINS=$(echo "$FAILED_LOGINS" | tr -d '[:space:]')
# Remove leading zeros (if any)
FAILED_LOGINS=$((10#$FAILED_LOGINS)) # Use arithmetic evaluation to ensure it's numeric and format correctly.

if [ "$FAILED_LOGINS" -lt 10 ]; then
    check_security "Failed Logins" "PASS" "Only $FAILED_LOGINS failed login attempts detected - this is within normal range"
elif [ "$FAILED_LOGINS" -lt 50 ]; then
    check_security "Failed Logins" "WARN" "$FAILED_LOGINS failed login attempts detected - might indicate breach attempts"
else
    check_security "Failed Logins" "FAIL" "$FAILED_LOGINS failed login attempts detected - possible brute force attack in progress"
fi

# Check system updates
UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -P '^\d+ upgraded' | cut -d" " -f1)
if [ -z "$UPDATES" ]; then
    UPDATES=0
fi
if [ "$UPDATES" -eq 0 ]; then
    check_security "System Updates" "PASS" "All system packages are up to date"
else
    check_security "System Updates" "FAIL" "$UPDATES security updates available - system is vulnerable to known exploits"
fi
# Check running services
SERVICES=$(systemctl list-units --type=service --state=running | grep -c "loaded active running")
if [ "$SERVICES" -lt 20 ]; then
    check_security "Running Services" "PASS" "Running minimal services ($SERVICES) - good for security"
elif [ "$SERVICES" -lt 40 ]; then
    check_security "Running Services" "WARN" "$SERVICES services running - consider reducing attack surface"
else
    check_security "Running Services" "FAIL" "Too many services running ($SERVICES) - increases attack surface"
fi

# Check ports using netstat or ss
if command -v netstat >/dev/null 2>&1; then
    LISTENING_PORTS=$(netstat -tuln | grep LISTEN | awk '{print $4}')
elif command -v ss >/dev/null 2>&1; then
    LISTENING_PORTS=$(ss -tuln | grep LISTEN | awk '{print $5}')
else
    check_security "Port Scanning" "FAIL" "Neither 'netstat' nor 'ss' is available on this system."
    LISTENING_PORTS=""
fi

# Process LISTENING_PORTS to extract unique public ports
if [ -n "$LISTENING_PORTS" ]; then
    PUBLIC_PORTS=$(echo "$LISTENING_PORTS" | awk -F':' '{print $NF}' | sort -n | uniq | tr '\n' ',' | sed 's/,$//')
    PORT_COUNT=$(echo "$PUBLIC_PORTS" | tr ',' '\n' | wc -w)
    INTERNET_PORTS=$(echo "$PUBLIC_PORTS" | tr ',' '\n' | wc -w)

    if [ "$PORT_COUNT" -lt 10 ] && [ "$INTERNET_PORTS" -lt 3 ]; then
        check_security "Port Security" "PASS" "Good configuration (Total: $PORT_COUNT, Public: $INTERNET_PORTS accessible ports): $PUBLIC_PORTS"
    elif [ "$PORT_COUNT" -lt 20 ] && [ "$INTERNET_PORTS" -lt 5 ]; then
        check_security "Port Security" "WARN" "Review recommended (Total: $PORT_COUNT, Public: $INTERNET_PORTS accessible ports): $PUBLIC_PORTS"
    else
        check_security "Port Security" "FAIL" "High exposure (Total: $PORT_COUNT, Public: $INTERNET_PORTS accessible ports): $PUBLIC_PORTS"
    fi
else
    check_security "Port Scanning" "WARN" "Port scanning failed due to missing tools. Ensure 'ss' or 'netstat' is installed."
fi

# Function to format the message with proper indentation for the report file
format_for_report() {
    local message="$1"
    echo "$message" >> "$REPORT_FILE"
}

# Check disk space usage
DISK_TOTAL=$(df -h / | awk 'NR==2 {print $2}')
DISK_USED=$(df -h / | awk 'NR==2 {print $3}')
DISK_AVAIL=$(df -h / | awk 'NR==2 {print $4}')
DISK_USAGE=$(df -h / | awk 'NR==2 {print int($5)}')
if [ "$DISK_USAGE" -lt 50 ]; then
    check_security "Disk Usage" "PASS" "Healthy disk space available (${DISK_USAGE}% used - Used: ${DISK_USED} of ${DISK_TOTAL}, Available: ${DISK_AVAIL})"
elif [ "$DISK_USAGE" -lt 80 ]; then
    check_security "Disk Usage" "WARN" "Disk space usage is moderate (${DISK_USAGE}% used - Used: ${DISK_USED} of ${DISK_TOTAL}, Available: ${DISK_AVAIL})"
else
    check_security "Disk Usage" "FAIL" "Critical disk space usage (${DISK_USAGE}% used - Used: ${DISK_USED} of ${DISK_TOTAL}, Available: ${DISK_AVAIL})"
fi

# Check memory usage
MEM_TOTAL=$(free -h | awk '/^Mem:/ {print $2}')
MEM_USED=$(free -h | awk '/^Mem:/ {print $3}')
MEM_AVAIL=$(free -h | awk '/^Mem:/ {print $7}')
MEM_USAGE=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2 * 100}')
if [ "$MEM_USAGE" -lt 50 ]; then
    check_security "Memory Usage" "PASS" "Healthy memory usage (${MEM_USAGE}% used - Used: ${MEM_USED} of ${MEM_TOTAL}, Available: ${MEM_AVAIL})"
elif [ "$MEM_USAGE" -lt 80 ]; then
    check_security "Memory Usage" "WARN" "Moderate memory usage (${MEM_USAGE}% used - Used: ${MEM_USED} of ${MEM_TOTAL}, Available: ${MEM_AVAIL})"
else
    check_security "Memory Usage" "FAIL" "Critical memory usage (${MEM_USAGE}% used - Used: ${MEM_USED} of ${MEM_TOTAL}, Available: ${MEM_AVAIL})"
fi

# Check CPU usage
CPU_CORES=$(nproc)
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print int($2)}')
CPU_IDLE=$(top -bn1 | grep "Cpu(s)" | awk '{print int($8)}')
CPU_LOAD=$(uptime | awk -F'load average:' '{ print $2 }' | awk -F',' '{ print $1 }' | tr -d ' ')
if [ "$CPU_USAGE" -lt 50 ]; then
    check_security "CPU Usage" "PASS" "Healthy CPU usage (${CPU_USAGE}% used - Active: ${CPU_USAGE}%, Idle: ${CPU_IDLE}%, Load: ${CPU_LOAD}, Cores: ${CPU_CORES})"
elif [ "$CPU_USAGE" -lt 80 ]; then
    check_security "CPU Usage" "WARN" "Moderate CPU usage (${CPU_USAGE}% used - Active: ${CPU_USAGE}%, Idle: ${CPU_IDLE}%, Load: ${CPU_LOAD}, Cores: ${CPU_CORES})"
else
    check_security "CPU Usage" "FAIL" "Critical CPU usage (${CPU_USAGE}% used - Active: ${CPU_USAGE}%, Idle: ${CPU_IDLE}%, Load: ${CPU_LOAD}, Cores: ${CPU_CORES})"
fi

# Check sudo configuration
if grep -q "^Defaults.*logfile" /etc/sudoers; then
    check_security "Sudo Logging" "PASS" "Sudo commands are being logged for audit purposes"
else
    check_security "Sudo Logging" "FAIL" "Sudo commands are not being logged - reduces audit capability"
fi

# Check password policy
if [ -f "/etc/security/pwquality.conf" ]; then
    if grep -q "minlen.*12" /etc/security/pwquality.conf; then
        check_security "Password Policy" "PASS" "Strong password policy is enforced"
    else
        check_security "Password Policy" "FAIL" "Weak password policy - passwords may be too simple"
    fi
else
    check_security "Password Policy" "FAIL" "No password policy configured - system accepts weak passwords"
fi

# Check for suspicious SUID files
COMMON_SUID_PATHS='^/usr/bin/|^/bin/|^/sbin/|^/usr/sbin/|^/usr/lib|^/usr/libexec'
KNOWN_SUID_BINS='ping$|sudo$|mount$|umount$|su$|passwd$|chsh$|newgrp$|gpasswd$|chfn$'

SUID_FILES=$(find / -type f -perm -4000 2>/dev/null | \
    grep -v -E "$COMMON_SUID_PATHS" | \
    grep -v -E "$KNOWN_SUID_BINS" | \
    wc -l)

if [ "$SUID_FILES" -eq 0 ]; then
    check_security "SUID Files" "PASS" "No suspicious SUID files found - good security practice"
else
    check_security "SUID Files" "WARN" "Found $SUID_FILES SUID files outside standard locations - verify if legitimate"
fi

# Add system information summary to report
echo "================================" >> "$REPORT_FILE"
echo "System Information Summary:" >> "$REPORT_FILE"
echo "Hostname: $(hostname)" >> "$REPORT_FILE"
echo "Kernel: $(uname -r)" >> "$REPORT_FILE"
echo "OS: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)" >> "$REPORT_FILE"
echo "CPU Cores: $(nproc)" >> "$REPORT_FILE"
echo "Total Memory: $(free -h | awk '/^Mem:/ {print $2}')" >> "$REPORT_FILE"
echo "Total Disk Space: $(df -h / | awk 'NR==2 {print $2}')" >> "$REPORT_FILE"
echo "================================" >> "$REPORT_FILE"

echo -e "\nAlphaShield audit complete. Full report saved to $REPORT_FILE"
echo -e "Review $REPORT_FILE for detailed recommendations."

# Add summary to report
echo "================================" >> "$REPORT_FILE"
echo "End of AlphaShield Audit Report" >> "$REPORT_FILE"
echo "Please review all failed checks and implement the recommended fixes." >> "$REPORT_FILE"

            echo "Audit process completed."
            ;;
        3)
            echo "Setting up Secure Environment for Server..."
           #!/bin/bash

# bash script to set minimal security on new installations of Ubuntu
# Rocky Linux and CentOS Linux. Written using Ubuntu 20.04 and Rocky 
# Linux 8 and CentOS 8.
# Written by Ted LeRoy with help from Google and the Linux community
# Follow or contribute on GitHub here:
# https://github.com/TedLeRoy/first-ten-seconds-centos-ubuntu
# Inspired by Jerry Gamblin's post:
# https://jerrygamblin.com/2016/07/13/my-first-10-seconds-on-a-server/
# Also by Bryan Kennedy's post which no longer seems to be available
# This script has been verified by shellcheck. Thanks koalaman!
# https://github.com/koalaman/shellcheck

# Defining Colors for text output if to stdout
if [[ -t 1 ]]; then
  red=$( tput setaf 1 );
  yellow=$( tput setaf 3 );
  green=$( tput setaf 2 );
  normal=$( tput sgr 0 );
fi

# Determine OS name and store it in "osName" variable
osName=$( cat /etc/*os-release | grep ^NAME | cut -d '"' -f 2 );
# Determine architecture and store in "arch" variable
arch=$( /bin/arch );
# Determine major release and store in "release" variable
osRelease=$( cat /etc/*os-release | grep PRETTY_NAME | cut -d " " -f 5 | cut -d "." -f 1 );

# Checking if running as root. If yes, asking to change to a non-root user.
# This verifies that a non-root user is configured and is being used to run
# the script.

if [ ${UID} == 0  ]
then
  echo "${red}
  You're running this script as root user.
  Please configure a non-root user and run this
  script as that non-root user.
  Please do not start the script using sudo, but
  enter sudo privileges when prompted.
  ${normal}"
  #Pause so user can see output
  sleep 1
  exit
fi

#################################################
#                 Ubuntu Section                #
#################################################

# If OS is Ubuntu, apply the security settings for Ubuntu

if [ "$osName" == "Ubuntu" ]
then
  echo "${green}  You're running $osName Linux. $osName security
  first measures will be applied.

  You will be prompted for your sudo password.
  Please enter it when asked.
  ${normal}
  "
  ##############################################
  #            Ubuntu Firewall Section         #
  ##############################################
  
  # Enabling ufw firewall and making sure it allows SSH
  echo "${yellow}  Enabling ufw firewall. Ensuring SSH is allowed.
  ${normal}"
  sudo ufw allow ssh
  sudo ufw --force enable
  echo "${green}
  Done configuring ufw firewall.
  ${normal}"
  #Pausing so user can see output
  sleep 1

  ##############################################
  #              Ubuntu SSH Section            #
  ##############################################

  # Checking whether an authorized_keys file exists in logged in user's account.
  # If so, the assumption is that key based authentication is set up.
  if [ -f /home/"$USER"/.ssh/authorized_keys ]
  then
    echo "${yellow}  
    Locking down SSH so it will only permit key-based authentication.
    ${normal}"
    echo -n "${red}  
    Are you sure you want to allow only key-based authentication for SSH? 
    PASSWORD AUTHENTICATION WILL BE DISABLED FOR SSH ACCESS!
    (y or n):${normal} " 
    read -r answer
    # Putting relevant lines in /etc/ssh/sshd_config.d/11-sshd-first-ten.conf file
    if [ "$answer" == "y" ] || [ "$answer" == "Y" ] ;then
      echo "${yellow}
      Adding the following lines to a file in sshd_config.d
      ${normal}"
      echo "DebianBanner no
DisableForwarding yes
PermitRootLogin no
IgnoreRhosts yes
PasswordAuthentication no" | sudo tee /etc/ssh/sshd_config.d/11-sshd-first-ten.conf 
      echo "${yellow}
      Reloading ssh
      ${normal}"
      # Restarting ssh daemon
      sudo systemctl reload ssh
      echo "${green}
      ssh has been restarted.
      # Pause so user can see output
      sleep 1
      ${normal}"

    else
      # User chose a key other than "y" for configuring ssh so it will not be set up now
      echo "${red}
      You have chosen not to disable password based authentication at this time.
      Please do so yourself or re-run this script when you're prepared to do so.
      ${normal}"
      # Pausing so user can see output
      sleep 1
    fi

  else
    # The check for an authorized_keys file failed so it is assumed key based auth is not set up
    # Skipping this configuration and warning user to do it for herself
    echo "${red}  
    It looks like SSH is not configured to allow key based authentication.
    Please enable it and re-run this script.${normal}"
  fi

  ##############################################
  #          Ubuntu fail2ban Section           #
  ##############################################

  # Installing fail2ban and networking tools (includes netstat)
  echo "${yellow}
  Installing fail2ban and networking tools.
  ${normal}"
  sudo apt install fail2ban net-tools -y
  echo "${green}
  fail2ban and networking tools have been installed.
  ${normal}"
  # Setting up the fail2ban jail for SSH
  echo "${yellow}
  Configuring fail2ban to protect SSH.

  Entering the following into /etc/fail2ban/jail.local
  ${normal}"
  echo "# Default banning action (e.g. iptables, iptables-new,
# iptables-multiport, shorewall, etc) It is used to define
# action_* variables. Can be overridden globally or per
# section within jail.local file

[ssh]

enabled  = true
banaction = iptables-multiport
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
findtime = 43200
bantime = 86400" | sudo tee /etc/fail2ban/jail.local
  # Restarting fail2ban
  echo "${green}
  Restarting fail2ban
  ${normal}"
  sudo systemctl restart fail2ban
  echo "${green}
  fail2ban restarted
  ${normal}"
  # Tell the user what the fail2ban protections are set to
  echo "${green}
  fail2ban is now protecting SSH with the following settings:
  maxretry: 5
  findtime: 12 hours (43200 seconds)
  bantime: 24 hours (86400 seconds)
  ${normal}"
  # Pausing so user can see output
  sleep 1

  ##############################################
  #           Ubuntu Overview Section          #
  ##############################################

#Explain what was done
echo "${green}
Description of what was done:
1. Ensured a non-root user is set up.
2. Ensured non-root user also has sudo permission (script won't continue without it).
3. Ensured SSH is allowed.
4. Ensured ufw firewall is enabled.
5. Locked down SSH if you chose y for that step.
   a. Set SSH not to display banner
   b. Disabled all forwarding
   c. Disabled root login over SSH
   d. Ignoring rhosts
   e. Disabled password authentication
6. Installed fail2ban and configured it to protect SSH.
[note] For a default Ubuntu server installation, automatic security updates are enabled so no action was taken regarding updates.
${normal}"

#################################################
#          CentOS / Red Hat Section             #
#################################################

elif [ "$osName" == "CentOS Linux" ] || [ "$osName" == "Red Hat Enterprise Linux" ] || [ "$osName" == "Rocky Linux" ] || [ "$osName" == "CentOS Stream" ] || [ "$osName" == "AlmaLinux" ]
then

  # Determine wheter Extra Packages for Enterprise Linux (epel) repo is supported.
  # epel support is needed for fail2ban installation.
  epelStat=$( dnf list installed | grep epel-release | cut -d "." -f1 )

  echo "${green}  You're running $osName. $osName security first 
  measures will be applied.

  You will be prompted for your sudo password.
  Please enter it when asked.
  ${normal}"
  #Pause so user can see output
  sleep 1
  
  ##############################################
  #            CentOS Firewall Section         #
  ##############################################

  # Enabling firewalld firewall and making sure it allows SSH
  echo "${yellow}  Enabling firewalld firewall. Ensuring SSH is allowed.
  ${normal}"

  echo "${yellow}  Configuring firewalld to disallow Zone Drifting
  ${normal}"
  sudo sed -i.bak 's/#\?\(AllowZoneDrifting*\).*$/\1=no/' /etc/firewalld/firewalld.conf

  OUTPUT=$(sudo firewall-cmd --permanent --list-all | grep services)
  if echo "$OUTPUT" | grep -q "ssh"; then
    echo "${green}
    firewalld is already configured to allow SSH
    ${normal}"
    echo "${yellow}
    Ensuring firewalld is running
    ${normal}"
    sudo systemctl start firewalld
    echo "${green}
    Done configuring firewalld
    ${normal}"
    #Pause so user can see output
    sleep 1
  else
    echo "${yellow}
    Adding SSH to allowed protocols in firewalld
    ${normal}"
    sudo firewall-cmd --permanent --add-service=ssh
    echo "${yellow}
    Restarting firewalld
    ${normal}"
    sudo systemctl restart firewalld
    echo "${green}
    Done configuring firewalld
    ${normal}"
    #Pause so user can see output
    sleep 1
  fi

  ##############################################
  #              CentOS SSH Section            #
  ##############################################

  # Checking whether an authorized_keys file exists in logged in user's account.
  # If so, the assumption is that key based authentication is set up.
  if [ -f /home/"$USER"/.ssh/authorized_keys ]
  then
    echo "${yellow}
    Locking down SSH so it will only permit key-based authentication.
    ${normal}"
    echo -n "${red}
    Are you sure you want to allow only key-based authentication for SSH?
    PASSWORD AUTHENTICATIN WILL BE DISABLED FOR SSH ACCESS!
    (y or n):${normal} "
    read -r answer
    # Putting relevant lines in /etc/ssh/sshd_config.d/11-sshd-first-ten.conf file
    if [ "$answer" == "y" ] || [ "$answer" == "Y" ] ;then
      echo "${yellow}
      Making modifications to /etc/ssh/sshd_config.
      ${normal}"
      # Making backup copy 1 of sshd_config
      sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.0
      echo "
# Disabling all forwarding.
# [note] This setting overrides all other forwarding settings!
# This entry was added by first-ten.sh
DisableForwarding yes" | sudo tee -a /etc/ssh/sshd_config
      sudo sed -i.bak -e 's/#IgnoreRhosts/IgnoreRhosts/' -e 's/IgnoreRhosts\s\no/IgnoreRhosts\s\yes/' /etc/ssh/sshd_config
      sudo sed -i.bak1 '/^PermitRootLogin/s/yes/no/' /etc/ssh/sshd_config
      sudo sed -i.bak2 '/^PasswordAuthentication/s/yes/no/' /etc/ssh/sshd_config
      echo "${yellow}
      Reloading ssh
      ${normal}"
      # Restarting ssh daemon
      sudo systemctl reload sshd
      echo "${green}
      ssh has been restarted.
      ${normal}"
      #Pause so user can see output
      sleep 1
    else
      # User chose a key other than "y" for configuring ssh so it will not be set up now
      echo "${red}
      You have chosen not to disable password based authentication at this time and
      not to apply the other SSH hardening steps.
      Please do so yourself or re-run this script when you\'re prepared to do so.
      ${normal}"
      #Pause so user can see output
      sleep 1
  fi

  else
    # The check for an authorized_keys file failed so it is assumed key based auth is not set up
    # Skipping this configuration and warning user to do it for herself
    echo "${red}
    It looks like SSH is not configured to allow key based authentication.
    Please enable it and re-run this script.${normal}"
    #Pause so user can see output
    sleep 1
  fi

  ##############################################
  #          CentOS fail2ban Section           #
  ##############################################

  # If epel not supported add it before installing fail2ban
  if [ "$epelStat" != "epel-release" ]; then
    if [ "$osName" == "Red Hat Enterprise Linux" ]; then
      echo "Installing epel-release repository to support fail2ban installation for RHEL"
      sudo subscription-manager repos --enable codeready-builder-for-rhel-"$osRelease"-"$arch"-rpms
      sudo dnf install epel-release epel-next-release
    fi
    echo "Installing epel-release repository to support fail2ban installation $osName"
    sudo dnf install epel-release -y
    sleep 1
  fi

  # Installing fail2ban and networking tools (includes netstat)
  echo "${yellow}
    Installing fail2ban.
    ${normal}"
    sudo dnf install fail2ban -y
      echo "${green}
      fail2ban has been installed.
      ${normal}"
      # Setting up the fail2ban jail for SSH
      echo "${yellow}
      Configuring fail2ban to protect SSH.
      Entering the following into /etc/fail2ban/jail.local
      ${normal}"
      echo "# Default banning action (e.g. iptables, iptables-new,
# iptables-multiport, shorewall, etc) It is used to define
# action_* variables. Can be overridden globally or per
# section within jail.local file

[ssh]

enabled  = true
banaction = iptables-multiport
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
findtime = 43200
bantime = 86400" | sudo tee /etc/fail2ban/jail.local
      # Restarting fail2ban
      echo "${green}
      Restarting fail2ban
      ${normal}"
      sudo systemctl restart fail2ban
      echo "${green}
      fail2ban restarted
      ${normal}"
      # Tell the user what the fail2ban protections are set to
      echo "${green}
      fail2ban is now protecting SSH with the following settings:
      maxretry: 5
      findtime: 12 hours (43200 seconds)
      bantime: 24 hours (86400 seconds)
      ${normal}"
      #Pause so user can see output
      sleep 1

  ##############################################
  #            CentOS Updates Section          #
  ##############################################

  # Configuring automatic updates for CentOS / Red Hat
  echo "${yellow}
  Running system update and upgrade.
  ${normal}"
  sudo dnf upgrade
  echo "${green}
  Upgrade complete.
  ${normal}"
  echo "${yellow}
  Installing Auto-upgrade (dnf-automatic)
  ${normal}"
  sudo dnf install dnf-automatic -y
  echo "${green}
  dnf-automatic installed.
  ${normal}"
  echo "${yellow}
  Enabling automatic updates (dnf-automatic.timer)
  ${normal}"
  sudo systemctl enable --now dnf-automatic.timer
  echo "${green}
  Automatic updates enabled.
  ${normal}"
  echo "${green}
  You can check timer by running:
  sudo systemctl status dnf-automatic.timer
  Look for \"loaded\" under the Loaded: line
  and \"active\" under the Active: line.
  ${normal}"
  #Pause so user can see output
  sleep 1


  ##############################################
  #           CentOS Overview Section          #
  ##############################################

#Explain what was done
echo "${green}
Description of what was done:
1. Ensured a non-root user is set up.
2. Ensured non-root user also has sudo permission (script won't continue without it).
3. Ensured SSH is allowed.
4. Ensured firewlld firewall is enabled.
5. Locked down SSH if you chose y for that step.
   a. Disabled all forwarding
   b. Disabled root login over SSH
   c. Ignoring rhosts
   d. Disabled password authentication
6. Installed fail2ban and configured it to protect SSH.
[note] For a default Ubuntu server installation, automatic security updates are enabled so no action was taken regarding updates.
${normal}"

####################################################
#  If Neither CentOS / Red Hat or Ubuntu is found  #
####################################################

else
  echo "${red}
  I'm not sure what operating system you're running.
  This script has only been tested for CentOS / Red Hat 
  Rocky Linux, and Ubuntu.
  Please run it only on those operating systems.
  ${normal}"
fi

exit 0

            echo "Configuration completed."
            ;;
        4)
            echo "Setup Honeypot!"
      #!/bin/bash
# Main menu
while true; do
    echo "========================================="
    echo " AlphaShield: Secure Your Linux Server"
    echo "========================================="
    echo " 1. Start Honeypot"
    echo " 2. Stop Honeypot"
    echo " 3. Exit"
    echo "========================================="
    read -p "Choose an option [1-3]: " choice

    case $choice in
        1)
           #!/bin/bash

echo ""
echo "// Honeypot //"
echo ""
echo -e "\e[31mYou must run this script with root privileges.\e[0m"
echo ""
echo "Select option:"
echo ""
echo "1 - Fast Auto Configuration"
echo "2 - Manual Configuration [Advanced Users, more options]"
echo ""
read -p "   -> " configuration

function honeyconfig() {
    local PORT=$1
    local MESSAGE=$2
    local SOUND=$3
    local LOG=$4
    local LOGFILE=$5

    echo ""
    echo "HONEYPOT ACTIVATED ON PORT $PORT ($(date))"
    echo ""

    if [[ $LOG == "y" || $LOG == "Y" ]]; then
        mkdir -p "$(dirname \"$LOGFILE\")"
        echo "#################### Honeypot log ####################" >> "$LOGFILE"
        echo "HONEYPOT ACTIVATED ON PORT $PORT ($(date))" >> "$LOGFILE"
        echo "" >> "$LOGFILE"
    fi

    while true; do
        TMP_SOCKET="/tmp/honeypot_$PORT.sock"
        rm -f "$TMP_SOCKET"

        # Start listener using bash here-string for -c (avoids quote issues)
        nc -l -p "$PORT" -c bash <<< "
            echo \"$MESSAGE\"
            echo \"Type a command:\"
            while true; do
                echo -n \"root@honeypot:~# \"
                read CMD
                case \"$CMD\" in
                    ls)
                        echo \"bin  boot  dev  etc  home  lib  media  opt  tmp  usr  var\"
                        ;;
                    whoami)
                        echo \"root\"
                        ;;
                    pwd)
                        echo \"/root\"
                        ;;
                    uname*)
                        echo \"Linux honeypot 5.15.0-91-generic x86_64\"
                        ;;
                    cat*)
                        echo \"Permission denied\"
                        ;;
                    exit|logout|quit)
                        echo \"Session ended. Goodbye.\"
                        break
                        ;;
                    *)
                        echo \"Command not found\"
                        ;;
                esac
            done
        " > "$TMP_SOCKET"

        sleep 2

        IP=$(netstat -tnp 2>/dev/null | grep ":$PORT" | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | head -n1)
        IP=${IP:-unknown}

        echo ""
        echo "INTRUSION ATTEMPT DETECTED! from $IP ($(date))"
        echo "-----------------------------"

        if [[ $SOUND == "y" || $SOUND == "Y" ]]; then
            echo -e "\a\a\a"
        fi

        if [[ $LOG == "y" || $LOG == "Y" ]]; then
            echo "" >> "$LOGFILE"
            echo "INTRUSION ATTEMPT DETECTED! from $IP ($(date))" >> "$LOGFILE"
            echo "-----------------------------" >> "$LOGFILE"
            echo "[$(date)] Intrusion Data:" >> "$LOGFILE"
            cat "$TMP_SOCKET" >> "$LOGFILE"
        fi

        rm -f "$TMP_SOCKET"
        sleep 1
    done
}

if [[ "$configuration" == "1" ]]; then
    RANDOM_NUM=$((RANDOM % 3))
    case $RANDOM_NUM in
        0)
            MSG="<HEAD><TITLE>Access denied</TITLE></HEAD><H2>Access denied</H2><H3>HTTP Referrer login failed</H3><H3>IP Address login failed</H3><P>$(date)</P>"
            ;;
        1)
            MSG="<HEAD><TITLE>Access denied</TITLE></HEAD><H2>Access denied</H2><H3>IP Address login failed</H3><P>$(date)</P>"
            ;;
        2)
            MSG="<HEAD><TITLE>Access denied</TITLE></HEAD><H2>Access denied</H2><P>$(date)</P>"
            ;;
    esac
    honeyconfig 80 "$MSG" "n" "n" ""
elif [[ "$configuration" == "2" ]]; then
    echo ""
    read -p "Insert port to open: " PORT
    echo ""
    read -p "Insert false message to show: " MESSAGE
    echo ""
    read -p "Save a log with intrusions? (y/n): " LOG
    if [[ $LOG == "y" || $LOG == "Y" ]]; then
        echo ""
        echo "Log file name? (with path if needed)"
        echo "Default: ./log_honeypot.txt"
        echo ""
        read -p "   -> " LOGNAME
        LOGNAME="${LOGNAME//\"/}"
        LOGNAME="${LOGNAME//\'/}"
        if [[ -z "$LOGNAME" ]]; then
            LOGNAME="./log_honeypot.txt"
        fi
    else
        LOGNAME=""
    fi
    echo ""
    read -p "Activate beep() sound when intrusion? (y/n): " SOUND
    honeyconfig "$PORT" "$MESSAGE" "$SOUND" "$LOG" "$LOGNAME"
else
    echo ""
    echo "Invalid option."
    echo ""
fi
;;
        2)
            cleanup
            ;;
        3)
            echo "[*] Exiting AlphaShield. Stay secure!"
            exit 0
            ;;
        *)
            echo "[!] Invalid option. Please choose again."
            ;;
    esac
done
            break
            ;;
        5)
            echo "Exiting AlphaShield. Stay secure!"
            break
            ;;
        *)
            echo "Invalid option. Please choose again."
            ;;
    esac
done
